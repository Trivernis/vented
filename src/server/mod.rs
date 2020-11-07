use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};

use crypto_box::{PublicKey, SecretKey};
use scheduled_thread_pool::ScheduledThreadPool;

use crate::crypto::CryptoStream;
use crate::event::Event;
use crate::event_handler::EventHandler;
use crate::result::VentedError::UnknownNode;
use crate::result::{VentedError, VentedResult};
use crate::server::data::{Future, Node, ServerConnectionContext};
use crate::server::server_events::{
    AuthPayload, ChallengePayload, NodeInformationPayload, VersionMismatchPayload, ACCEPT_EVENT,
    AUTH_EVENT, CHALLENGE_EVENT, CONNECT_EVENT, MISMATCH_EVENT, READY_EVENT, REJECT_EVENT,
};
use crossbeam_utils::sync::WaitGroup;
use parking_lot::Mutex;
use sha2::Digest;
use std::io::Write;
use std::sync::Arc;
use std::thread;
use x25519_dalek::StaticSecret;

pub mod data;
pub mod server_events;

pub(crate) const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

type ForwardFutureVector = Arc<Mutex<HashMap<(String, String), Future<CryptoStream>>>>;
type CryptoStreamMap = Arc<Mutex<HashMap<String, CryptoStream>>>;

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
    connections: CryptoStreamMap,
    forwarded_connections: ForwardFutureVector,
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
            listener_pool: Arc::new(Mutex::new(ScheduledThreadPool::with_name(
                "vented_listeners",
                num_threads,
            ))),
            sender_pool: Arc::new(Mutex::new(ScheduledThreadPool::with_name(
                "vented_senders",
                num_threads,
            ))),
            connections: Arc::new(Mutex::new(HashMap::new())),
            forwarded_connections: Arc::new(Mutex::new(HashMap::new())),
            global_secret_key: secret_key,
            known_nodes: Arc::new(Mutex::new(nodes)),
        }
    }

    /// Returns the nodeId of the server
    pub fn node_id(&self) -> String {
        self.node_id.clone()
    }

    /// Returns the nodes known to the server
    pub fn nodes(&self) -> Vec<Node> {
        self.known_nodes.lock().clone()
    }

    /// Emits an event to the specified Node
    /// The actual writing is done in a separate thread from the thread pool.
    /// With the returned wait group one can wait for the event to be written.
    pub fn emit(&self, node_id: String, event: Event) -> VentedResult<WaitGroup> {
        let wg = WaitGroup::new();
        let stream = self.get_connection(node_id)?;

        self.sender_pool.lock().execute({
            let wg = WaitGroup::clone(&wg);
            let connections = Arc::clone(&self.connections);
            move || {
                if let Err(e) = stream.send(event) {
                    log::error!("Failed to send event: {}", e);
                    connections.lock().remove(stream.receiver_node());
                }
                std::mem::drop(wg);
            }
        });

        Ok(wg)
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
            forwarded_connections: Arc::clone(&self.forwarded_connections),
        }
    }

    /// Handles a single connection by first performing a key exchange and
    /// then establishing an encrypted connection
    fn handle_connection(params: ServerConnectionContext, stream: TcpStream) -> VentedResult<()> {
        let pool = Arc::clone(&params.listener_pool);
        let event_handler = Arc::clone(&params.event_handler);
        log::trace!(
            "Received connection from {}",
            stream.peer_addr().expect("Failed to get peer address")
        );

        pool.lock().execute(move || {
            let connections = Arc::clone(&params.connections);

            let stream = match VentedServer::get_crypto_stream(params, stream) {
                Ok(stream) => stream,
                Err(e) => {
                    log::error!("Failed to establish encrypted connection: {}", e);
                    return;
                }
            };
            log::trace!("Secure connection established.");
            event_handler.lock().handle_event(Event::new(READY_EVENT));
            if let Err(e) = Self::handle_read(event_handler, &stream) {
                log::error!("Connection aborted: {}", e);
            }

            connections.lock().remove(stream.receiver_node());
        });

        Ok(())
    }

    /// Handler for reading after the connection is established
    fn handle_read(
        event_handler: Arc<Mutex<EventHandler>>,
        stream: &CryptoStream,
    ) -> VentedResult<()> {
        while let Ok(event) = stream.read() {
            if let Some(response) = event_handler.lock().handle_event(event) {
                stream.send(response)?
            }
        }

        Ok(())
    }

    /// Takes three attempts to retrieve a connection for the given node.
    /// First it tries to use the already established connection stored in the shared connections vector.
    /// If that fails it tries to establish a new connection to the node by using the known address
    fn get_connection(&self, target: String) -> VentedResult<CryptoStream> {
        log::trace!("Trying to connect to {}", target);
        if let Some(stream) = self.connections.lock().get(&target) {
            log::trace!("Reusing existing connection.");
            return Ok(CryptoStream::clone(stream));
        }

        let target_node = {
            self.known_nodes
                .lock()
                .iter()
                .find(|node| node.id == target)
                .cloned()
                .ok_or(VentedError::UnknownNode(target.clone()))?
        };
        if let Some(address) = target_node.address {
            log::trace!("Connecting to known address");
            match self.connect(address) {
                Ok(stream) => {
                    return Ok(stream);
                }
                Err(e) => log::error!("Failed to connect to node '{}': {}", target, e),
            }
        }

        log::debug!("All connection attempts to {} failed!", target);

        Err(VentedError::NotAServer(target))
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

        let connections = Arc::clone(&context.connections);
        let stream = Self::get_crypto_stream(context.clone(), stream)?;

        self.listener_pool.lock().execute({
            let stream = CryptoStream::clone(&stream);
            let event_handler = Arc::clone(&self.event_handler);
            event_handler.lock().handle_event(Event::new(READY_EVENT));

            move || {
                if let Err(e) = Self::handle_read(event_handler, &stream) {
                    log::error!("Connection aborted: {}", e);
                }
                connections.lock().remove(stream.receiver_node());
            }
        });

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
                    vented_version: CRATE_VERSION.to_string(),
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
            vented_version,
        } = event.get_payload::<NodeInformationPayload>().unwrap();

        if !Self::compare_version(&vented_version, CRATE_VERSION) {
            stream.write(
                &Event::with_payload(
                    MISMATCH_EVENT,
                    &VersionMismatchPayload::new(CRATE_VERSION, &vented_version),
                )
                .as_bytes(),
            )?;
            stream.flush()?;
            return Err(VentedError::VersionMismatch(vented_version));
        }

        let public_key = PublicKey::from(public_key);

        let node_data = if let Some(data) = known_nodes.lock().iter().find(|n| n.id == node_id) {
            data.clone()
        } else {
            stream.write(&Event::new(REJECT_EVENT).as_bytes())?;
            stream.flush()?;
            return Err(UnknownNode(node_id));
        };

        let mut stream = CryptoStream::new(node_id.clone(), stream, &public_key, &secret_key)?;

        log::trace!("Authenticating recipient...");
        let key_a = Self::authenticate_other(&mut stream, node_data.public_key)?;
        log::trace!("Authenticating self...");
        let key_b =
            Self::authenticate_self(&mut stream, StaticSecret::from(global_secret.to_bytes()))?;
        log::trace!("Connection fully authenticated.");

        let pre_secret = StaticSecret::from(secret_key.to_bytes()).diffie_hellman(&public_key);
        let final_secret =
            Self::generate_final_secret(pre_secret.to_bytes().to_vec(), key_a, key_b);
        let final_public = final_secret.public_key();
        stream.update_key(&final_secret, &final_public);

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
            vented_version,
        } = event.get_payload::<NodeInformationPayload>().unwrap();

        if !Self::compare_version(&vented_version, CRATE_VERSION) {
            stream.write(
                &Event::with_payload(
                    MISMATCH_EVENT,
                    &VersionMismatchPayload::new(CRATE_VERSION, &vented_version),
                )
                .as_bytes(),
            )?;
            stream.flush()?;
            return Err(VentedError::VersionMismatch(vented_version));
        }

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
                    vented_version: CRATE_VERSION.to_string(),
                },
            )
            .as_bytes(),
        )?;
        stream.flush()?;

        let mut stream = CryptoStream::new(node_id.clone(), stream, &public_key, &secret_key)?;

        log::trace!("Authenticating self...");
        let key_a =
            Self::authenticate_self(&mut stream, StaticSecret::from(global_secret.to_bytes()))?;
        log::trace!("Authenticating recipient...");
        let key_b = Self::authenticate_other(&mut stream, node_data.public_key)?;
        log::trace!("Connection fully authenticated.");

        let pre_secret = StaticSecret::from(secret_key.to_bytes()).diffie_hellman(&public_key);
        let final_secret =
            Self::generate_final_secret(pre_secret.to_bytes().to_vec(), key_a, key_b);
        let final_public = final_secret.public_key();
        stream.update_key(&final_secret, &final_public);

        Ok((node_id, stream))
    }

    /// Performs the challenged side of the authentication challenge
    fn authenticate_self(
        stream: &CryptoStream,
        static_secret: StaticSecret,
    ) -> VentedResult<Vec<u8>> {
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
            ACCEPT_EVENT => Ok(auth_key.to_bytes().to_vec()),
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
    ) -> VentedResult<Vec<u8>> {
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
            Ok(calculated_secret.to_vec())
        }
    }

    /// Compares two version for their major and minor value
    fn compare_version(a: &str, b: &str) -> bool {
        let parts_a = a.split('.').collect::<Vec<&str>>();
        let parts_b = b.split('.').collect::<Vec<&str>>();

        parts_a.get(0) == parts_b.get(0) && parts_a.get(1) == parts_b.get(1)
    }

    /// Generates a secret from handshake components
    fn generate_final_secret(
        mut pre_secret: Vec<u8>,
        mut key_a: Vec<u8>,
        mut key_b: Vec<u8>,
    ) -> SecretKey {
        let mut secret_data = Vec::new();
        secret_data.append(&mut pre_secret);
        secret_data.append(&mut key_a);
        secret_data.append(&mut key_b);
        let final_secret = sha2::Sha256::digest(&secret_data).to_vec();
        let mut final_secret_arr = [0u8; 32];
        final_secret_arr.copy_from_slice(&final_secret[..]);

        SecretKey::from(final_secret_arr)
    }
}
