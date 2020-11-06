use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};

use crypto_box::{ChaChaBox, PublicKey, SecretKey};
use scheduled_thread_pool::ScheduledThreadPool;

use crate::crypto::CryptoStream;
use crate::event::Event;
use crate::event_handler::EventHandler;
use crate::result::VentedError::UnknownNode;
use crate::result::{VentedError, VentedResult};
use crate::server::data::{Node, ServerConnectionContext};
use crate::server::server_events::{
    AuthPayload, ChallengePayload, NodeInformationPayload, ACCEPT_EVENT, AUTH_EVENT,
    CHALLENGE_EVENT, CONNECT_EVENT, READY_EVENT, REJECT_EVENT,
};
use crossbeam_utils::sync::WaitGroup;
use parking_lot::Mutex;
use std::io::Write;
use std::sync::Arc;
use std::thread;
use x25519_dalek::StaticSecret;

pub mod data;
pub mod server_events;

/// The vented server that provides parallel handling of connections
/// Usage:
/// ```rust
/// use vented::server::VentedServer;
/// use vented::server::data::Node;
/// use vented::crypto::SecretKey;
/// use rand::thread_rng;
/// use vented::event::Event;
///
/// let nodes = vec![
/// Node {
///        id: "B".to_string(),
///        address: None,
///        public_key: global_secret_b.public_key() // load it from somewhere
///    },
///];
/// // in a real world example the secret key needs to be loaded from somewhere because connections
/// // with unknown keys are not accepted.
/// let global_secret = SecretKey::new(&mut thread_rng());
/// let mut server = VentedServer::new("A".to_string(), global_secret, nodes.clone(), 4);
///
///
/// server.listen("localhost:20000".to_string());
/// server.on("pong", |_event| {
///    println!("Pong!");
///    
///    None    // the return value is the response event Option<Event>
/// });
/// server.emit("B".to_string(), Event::new("ping".to_string())).unwrap();
/// ```
pub struct VentedServer {
    connections: Arc<Mutex<HashMap<String, CryptoStream>>>,
    known_nodes: Arc<Mutex<Vec<Node>>>,
    listener_pool: Arc<Mutex<ScheduledThreadPool>>,
    sender_pool: Arc<Mutex<ScheduledThreadPool>>,
    event_handler: Arc<Mutex<EventHandler>>,
    global_secret_key: SecretKey,
    node_id: String,
}

impl VentedServer {
    /// Creates a new vented server with a given node_id and secret key that are
    /// used to authenticate against other servers.
    /// The given nodes are used for authentication.
    /// The server runs with 2x the given amount of threads.
    pub fn new(
        node_id: String,
        secret_key: SecretKey,
        nodes: Vec<Node>,
        num_threads: usize,
    ) -> Self {
        Self {
            node_id,
            event_handler: Arc::new(Mutex::new(EventHandler::new())),
            listener_pool: Arc::new(Mutex::new(ScheduledThreadPool::new(num_threads))),
            sender_pool: Arc::new(Mutex::new(ScheduledThreadPool::new(num_threads))),
            connections: Arc::new(Mutex::new(HashMap::new())),
            global_secret_key: secret_key,
            known_nodes: Arc::new(Mutex::new(nodes)),
        }
    }

    /// Emits an event to the specified Node
    /// The actual writing is done in a separate thread from the thread pool.
    /// With the returned waitgroup one can wait for the event to be written.
    pub fn emit(&self, node_id: String, event: Event) -> VentedResult<WaitGroup> {
        let handler = self.connections.lock().get(&node_id).cloned();
        let wg = WaitGroup::new();
        let wg2 = WaitGroup::clone(&wg);

        if let Some(handler) = handler {
            self.sender_pool.lock().execute(move || {
                handler.send(event).expect("Failed to send event");
                std::mem::drop(wg);
            });
            Ok(wg2)
        } else {
            let found_node = self
                .known_nodes
                .lock()
                .iter()
                .find(|n| n.id == node_id)
                .cloned();
            if let Some(node) = found_node {
                if let Some(address) = &node.address {
                    let handler = self.connect(address.clone())?;
                    self.sender_pool.lock().execute(move || {
                        handler.send(event).expect("Failed to send event");
                        std::mem::drop(wg);
                    });
                    Ok(wg2)
                } else {
                    Err(VentedError::NotAServer(node_id))
                }
            } else {
                Err(VentedError::UnknownNode(node_id))
            }
        }
    }

    /// Adds a handler for the given event.
    /// The event returned by the handler is returned to the server.
    /// If there is more than one handler, the response will be piped to the next handler.
    /// The oder is by order of insertion. The first registered handler will be executed first.
    pub fn on<F: 'static>(&mut self, event_name: &str, handler: F)
    where
        F: Fn(Event) -> Option<Event> + Send + Sync,
    {
        self.event_handler.lock().on(event_name, handler);
    }

    /// Starts listening on the specified address (with port!)
    /// This will cause a new thread to start up so that the method returns immediately
    /// With the returned wait group one can wait for the server to be ready.
    /// The method can be called multiple times to start listeners on multiple ports.
    pub fn listen(&mut self, address: String) -> WaitGroup {
        let context = self.get_server_context();
        let wg = WaitGroup::new();
        let wg2 = WaitGroup::clone(&wg);

        thread::spawn(move || match TcpListener::bind(&address) {
            Ok(listener) => {
                log::info!("Listener running on {}", address);
                std::mem::drop(wg);
                for connection in listener.incoming() {
                    match connection {
                        Ok(stream) => {
                            if let Err(e) = Self::handle_connection(context.clone(), stream) {
                                log::error!("Failed to handle connection: {}", e);
                            }
                        }
                        Err(e) => log::trace!("Failed to establish connection: {}", e),
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to bind listener: {}", e);
                std::mem::drop(wg);
            }
        });

        wg2
    }

    /// Returns a copy of the servers metadata
    fn get_server_context(&self) -> ServerConnectionContext {
        ServerConnectionContext {
            is_server: true,
            node_id: self.node_id.clone(),
            global_secret: self.global_secret_key.clone(),
            known_nodes: Arc::clone(&self.known_nodes),
            connections: Arc::clone(&self.connections),
            event_handler: Arc::clone(&self.event_handler),
            listener_pool: Arc::clone(&self.listener_pool),
        }
    }

    /// Handles a single connection by first performing a key exchange and
    /// then establishing an encrypted connection
    fn handle_connection(params: ServerConnectionContext, stream: TcpStream) -> VentedResult<()> {
        let pool = Arc::clone(&params.listener_pool);
        let event_handler = Arc::clone(&params.event_handler);

        pool.lock().execute(move || {
            let stream = match VentedServer::get_crypto_stream(params, stream) {
                Ok(stream) => stream,
                Err(e) => {
                    log::error!("Failed to establish encrypted connection: {}", e);
                    return;
                }
            };
            event_handler
                .lock()
                .handle_event(Event::new(READY_EVENT.to_string()));
            while let Ok(event) = stream.read() {
                if let Some(response) = event_handler.lock().handle_event(event) {
                    stream.send(response).expect("Failed to send response");
                }
            }
        });

        Ok(())
    }

    /// Establishes a crypto stream for the given stream
    fn get_crypto_stream(
        params: ServerConnectionContext,
        stream: TcpStream,
    ) -> VentedResult<CryptoStream> {
        let (node_id, stream) = VentedServer::perform_key_exchange(
            params.is_server,
            stream,
            params.node_id.clone(),
            params.global_secret,
            params.known_nodes,
        )?;

        params
            .connections
            .lock()
            .insert(node_id, CryptoStream::clone(&stream));

        Ok(stream)
    }

    /// Connects to the given address as a tcp client
    fn connect(&self, address: String) -> VentedResult<CryptoStream> {
        let stream = TcpStream::connect(address)?;
        let mut context = self.get_server_context();
        context.is_server = false;

        let stream = Self::get_crypto_stream(context, stream)?;
        self.listener_pool.lock().execute({
            let stream = CryptoStream::clone(&stream);
            let event_handler = Arc::clone(&self.event_handler);
            move || {
                while let Ok(event) = stream.read() {
                    if let Some(response) = event_handler.lock().handle_event(event) {
                        stream.send(response).expect("Failed to send response");
                    }
                }
            }
        });
        self.event_handler
            .lock()
            .handle_event(Event::new(READY_EVENT.to_string()));

        Ok(stream)
    }

    /// Performs a key exchange
    fn perform_key_exchange(
        is_server: bool,
        stream: TcpStream,
        own_node_id: String,
        global_secret: SecretKey,
        known_nodes: Arc<Mutex<Vec<Node>>>,
    ) -> VentedResult<(String, CryptoStream)> {
        let secret_key = SecretKey::generate(&mut rand::thread_rng());
        if is_server {
            Self::perform_server_key_exchange(
                stream,
                &secret_key,
                own_node_id,
                global_secret,
                known_nodes,
            )
        } else {
            Self::perform_client_key_exchange(
                stream,
                &secret_key,
                own_node_id,
                global_secret,
                known_nodes,
            )
        }
    }

    /// Performs the client side DH key exchange
    fn perform_client_key_exchange(
        mut stream: TcpStream,
        secret_key: &SecretKey,
        own_node_id: String,
        global_secret: SecretKey,
        known_nodes: Arc<Mutex<Vec<Node>>>,
    ) -> VentedResult<(String, CryptoStream)> {
        stream.write(
            &Event::with_payload(
                CONNECT_EVENT,
                &NodeInformationPayload {
                    public_key: secret_key.public_key().to_bytes(),
                    node_id: own_node_id,
                },
            )
            .as_bytes(),
        )?;
        stream.flush()?;
        let event = Event::from_bytes(&mut stream)?;
        if event.name != CONNECT_EVENT {
            return Err(VentedError::UnexpectedEvent(event.name));
        }
        let NodeInformationPayload {
            public_key,
            node_id,
        } = event.get_payload::<NodeInformationPayload>().unwrap();

        let public_key = PublicKey::from(public_key);
        let secret_box = ChaChaBox::new(&public_key, &secret_key);

        let node_data = if let Some(data) = known_nodes.lock().iter().find(|n| n.id == node_id) {
            data.clone()
        } else {
            stream.write(&Event::new(REJECT_EVENT).as_bytes())?;
            stream.flush()?;
            return Err(UnknownNode(node_id));
        };

        let mut stream = CryptoStream::new(stream, secret_box)?;

        log::trace!("Authenticating recipient...");
        Self::authenticate_other(&mut stream, node_data.public_key)?;
        log::trace!("Authenticating self...");
        Self::authenticate_self(&mut stream, StaticSecret::from(global_secret.to_bytes()))?;
        log::trace!("Connection fully authenticated.");

        Ok((node_id, stream))
    }

    /// Performs a DH key exchange by using the crypto_box module and events
    /// On success it returns a secret box with the established secret and the node id of the client
    fn perform_server_key_exchange(
        mut stream: TcpStream,
        secret_key: &SecretKey,
        own_node_id: String,
        global_secret: SecretKey,
        known_nodes: Arc<Mutex<Vec<Node>>>,
    ) -> VentedResult<(String, CryptoStream)> {
        let event = Event::from_bytes(&mut stream)?;
        if event.name != CONNECT_EVENT {
            return Err(VentedError::UnexpectedEvent(event.name));
        }
        let NodeInformationPayload {
            public_key,
            node_id,
        } = event.get_payload::<NodeInformationPayload>().unwrap();
        let public_key = PublicKey::from(public_key);

        let node_data = if let Some(data) = known_nodes.lock().iter().find(|n| n.id == node_id) {
            data.clone()
        } else {
            stream.write(&Event::new(REJECT_EVENT).as_bytes())?;
            stream.flush()?;
            return Err(UnknownNode(node_id));
        };

        stream.write(
            &Event::with_payload(
                CONNECT_EVENT,
                &NodeInformationPayload {
                    public_key: secret_key.public_key().to_bytes(),
                    node_id: own_node_id,
                },
            )
            .as_bytes(),
        )?;
        stream.flush()?;
        let secret_box = ChaChaBox::new(&public_key, &secret_key);
        let mut stream = CryptoStream::new(stream, secret_box)?;

        log::trace!("Authenticating self...");
        Self::authenticate_self(&mut stream, StaticSecret::from(global_secret.to_bytes()))?;
        log::trace!("Authenticating recipient...");
        Self::authenticate_other(&mut stream, node_data.public_key)?;
        log::trace!("Connection fully authenticated.");

        Ok((node_id, stream))
    }

    /// Performs the challenged side of the authentication challenge
    fn authenticate_self(stream: &CryptoStream, static_secret: StaticSecret) -> VentedResult<()> {
        let challenge_event = stream.read()?;

        if challenge_event.name != CHALLENGE_EVENT {
            stream.send(Event::new(REJECT_EVENT))?;
            return Err(VentedError::UnexpectedEvent(challenge_event.name));
        }
        let ChallengePayload { public_key } = challenge_event.get_payload()?;
        let auth_key = static_secret.diffie_hellman(&PublicKey::from(public_key));

        stream.send(Event::with_payload(
            AUTH_EVENT,
            &AuthPayload {
                calculated_secret: auth_key.to_bytes(),
            },
        ))?;

        let response = stream.read()?;

        match response.name.as_str() {
            ACCEPT_EVENT => Ok(()),
            REJECT_EVENT => Err(VentedError::Rejected),
            _ => {
                stream.send(Event::new(REJECT_EVENT))?;
                Err(VentedError::UnexpectedEvent(response.name))
            }
        }
    }

    /// Authenticates the other party by using their stored public key and a generated secret
    fn authenticate_other(
        stream: &CryptoStream,
        other_static_public: PublicKey,
    ) -> VentedResult<()> {
        let auth_secret = SecretKey::generate(&mut rand::thread_rng());
        stream.send(Event::with_payload(
            CHALLENGE_EVENT,
            &ChallengePayload {
                public_key: auth_secret.public_key().to_bytes(),
            },
        ))?;

        let auth_event = stream.read()?;

        if auth_event.name != AUTH_EVENT {
            stream.send(Event::new(REJECT_EVENT))?;
            return Err(VentedError::UnexpectedEvent(auth_event.name));
        }
        let AuthPayload { calculated_secret } = auth_event.get_payload()?;
        let expected_secret =
            StaticSecret::from(auth_secret.to_bytes()).diffie_hellman(&other_static_public);

        if expected_secret.to_bytes() != calculated_secret {
            stream.send(Event::new(REJECT_EVENT))?;
            Err(VentedError::AuthFailed)
        } else {
            stream.send(Event::new(ACCEPT_EVENT))?;
            Ok(())
        }
    }
}
