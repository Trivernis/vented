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
    AuthPayload, NodeInformationPayload, AUTH_EVENT, CONNECT_EVENT, CONN_ACCEPT_EVENT,
    CONN_CHALLENGE_EVENT, CONN_REJECT_EVENT, READY_EVENT,
};
use parking_lot::Mutex;
use std::io::Write;
use std::sync::Arc;
use std::thread;
use x25519_dalek::StaticSecret;

pub mod data;
pub mod server_events;

/// The vented server that provides parallel handling of connections
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
    pub fn emit(&self, node_id: String, event: Event) -> VentedResult<()> {
        let handler = self.connections.lock().get(&node_id).cloned();

        if let Some(handler) = handler {
            self.sender_pool.lock().execute(move || {
                handler.send(event).expect("Failed to send event");
            });
            Ok(())
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
                    });
                    Ok(())
                } else {
                    Err(VentedError::NotAServer(node_id))
                }
            } else {
                Err(VentedError::UnknownNode(node_id))
            }
        }
    }

    /// Adds a handler for the given event
    pub fn on<F: 'static>(&mut self, event_name: &str, handler: F)
    where
        F: Fn(Event) -> Option<Event> + Send + Sync,
    {
        self.event_handler.lock().on(event_name, handler);
    }

    /// Starts listening on the specified address (with port!)
    pub fn listen(&mut self, address: String) {
        let context = self.get_server_context();

        thread::spawn(move || match TcpListener::bind(address) {
            Ok(listener) => {
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
            Err(e) => log::error!("Failed to bind listener: {}", e),
        });
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
            let stream = VentedServer::get_crypto_stream(params, stream).expect("Listener failed");
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

    fn get_crypto_stream(
        params: ServerConnectionContext,
        mut stream: TcpStream,
    ) -> VentedResult<CryptoStream> {
        let (node_id, secret_box) = VentedServer::perform_key_exchange(
            params.is_server,
            &mut stream,
            params.node_id.clone(),
            params.global_secret,
            params.known_nodes,
        )?;

        let stream = CryptoStream::new(stream, secret_box)?;
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
        stream: &mut TcpStream,
        own_node_id: String,
        global_secret: SecretKey,
        known_nodes: Arc<Mutex<Vec<Node>>>,
    ) -> VentedResult<(String, ChaChaBox)> {
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
        mut stream: &mut TcpStream,
        secret_key: &SecretKey,
        own_node_id: String,
        global_secret: SecretKey,
        known_nodes: Arc<Mutex<Vec<Node>>>,
    ) -> VentedResult<(String, ChaChaBox)> {
        stream.write(
            &Event::with_payload(
                CONNECT_EVENT.to_string(),
                &NodeInformationPayload {
                    public_key: secret_key.public_key().to_bytes(),
                    node_id: own_node_id,
                },
            )
            .as_bytes(),
        )?;
        stream.flush()?;
        let event = Event::from_bytes(&mut stream)?;
        if event.name != CONN_CHALLENGE_EVENT {
            return Err(VentedError::UnknownNode(event.name));
        }
        let NodeInformationPayload {
            public_key,
            node_id,
        } = event.get_payload::<NodeInformationPayload>().unwrap();
        let public_key = PublicKey::from(public_key);
        let shared_auth_secret =
            StaticSecret::from(global_secret.to_bytes()).diffie_hellman(&public_key);

        stream.write(
            &Event::with_payload(
                AUTH_EVENT.to_string(),
                &AuthPayload {
                    calculated_secret: shared_auth_secret.to_bytes(),
                },
            )
            .as_bytes(),
        )?;

        let event = Event::from_bytes(&mut stream)?;
        if event.name != CONN_ACCEPT_EVENT {
            return Err(VentedError::UnknownNode(event.name));
        }
        let known_nodes = known_nodes.lock();
        let node_static_info = event.get_payload::<NodeInformationPayload>()?;
        let node_data = if let Some(data) = known_nodes
            .iter()
            .find(|n| n.id == node_static_info.node_id)
        {
            data.clone()
        } else {
            return Err(UnknownNode(node_id));
        };
        if node_data.public_key.to_bytes() != node_static_info.public_key {
            return Err(UnknownNode(node_id));
        }

        let secret_box = ChaChaBox::new(&public_key, &secret_key);

        Ok((node_id, secret_box))
    }

    /// Performs a DH key exchange by using the crypto_box module and events
    /// On success it returns a secret box with the established secret and the node id of the client
    fn perform_server_key_exchange(
        mut stream: &mut TcpStream,
        secret_key: &SecretKey,
        own_node_id: String,
        global_secret: SecretKey,
        known_nodes: Arc<Mutex<Vec<Node>>>,
    ) -> VentedResult<(String, ChaChaBox)> {
        let event = Event::from_bytes(&mut stream)?;
        if event.name != CONNECT_EVENT {
            return Err(VentedError::UnexpectedEvent(event.name));
        }
        let NodeInformationPayload {
            public_key,
            node_id,
        } = event.get_payload::<NodeInformationPayload>().unwrap();
        let public_key = PublicKey::from(public_key);

        let known_nodes = known_nodes.lock();
        let node_data = if let Some(data) = known_nodes.iter().find(|n| n.id == node_id) {
            data.clone()
        } else {
            stream.write(&Event::new(CONN_REJECT_EVENT.to_string()).as_bytes())?;
            stream.flush()?;
            return Err(UnknownNode(node_id));
        };

        let secret_box = ChaChaBox::new(&public_key, &secret_key);
        stream.write(
            &Event::with_payload(
                CONN_CHALLENGE_EVENT.to_string(),
                &NodeInformationPayload {
                    public_key: secret_key.public_key().to_bytes(),
                    node_id: own_node_id.clone(),
                },
            )
            .as_bytes(),
        )?;
        stream.flush()?;
        let auth_event = Event::from_bytes(&mut stream)?;

        if auth_event.name != AUTH_EVENT {
            return Err(VentedError::UnexpectedEvent(auth_event.name));
        }
        let AuthPayload { calculated_secret } = auth_event.get_payload::<AuthPayload>()?;
        let expected_secret =
            StaticSecret::from(secret_key.to_bytes()).diffie_hellman(&node_data.public_key);

        if expected_secret.to_bytes() != calculated_secret {
            stream.write(&Event::new(CONN_REJECT_EVENT.to_string()).as_bytes())?;
            stream.flush()?;
            return Err(UnknownNode(node_id));
        } else {
            stream.write(
                &Event::with_payload(
                    CONN_ACCEPT_EVENT.to_string(),
                    &NodeInformationPayload {
                        node_id: own_node_id,
                        public_key: global_secret.public_key().to_bytes(),
                    },
                )
                .as_bytes(),
            )?;
            stream.flush()?;
        }

        Ok((node_id, secret_box))
    }
}
