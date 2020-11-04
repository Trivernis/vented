use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};

use crypto_box::{ChaChaBox, PublicKey, SecretKey};
use scheduled_thread_pool::ScheduledThreadPool;

use crate::crypto::CryptoStream;
use crate::event::Event;
use crate::event_handler::EventHandler;
use crate::result::{VentedError, VentedResult};
use crate::server::data::{Node, ServerConnectionContext};
use crate::server::server_events::{
    NodeInformationPayload, CONNECT_EVENT, CONN_ACCEPT_EVENT, CONN_REJECT_EVENT,
};
use parking_lot::Mutex;
use std::io::Write;
use std::sync::Arc;
use std::thread;

pub mod data;
pub(crate) mod server_events;

/// The vented server that provides parallel handling of connections
pub struct VentedServer {
    connections: Arc<Mutex<HashMap<String, CryptoStream>>>,
    known_nodes: Arc<Mutex<Vec<Node>>>,
    listener_pool: Arc<Mutex<ScheduledThreadPool>>,
    sender_pool: Arc<Mutex<ScheduledThreadPool>>,
    event_handler: Arc<Mutex<EventHandler>>,
    secret_key: SecretKey,
    node_id: String,
}

impl VentedServer {
    pub fn new(node_id: String, nodes: Vec<Node>, num_threads: usize) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            node_id,
            event_handler: Arc::new(Mutex::new(EventHandler::new())),
            listener_pool: Arc::new(Mutex::new(ScheduledThreadPool::new(num_threads))),
            sender_pool: Arc::new(Mutex::new(ScheduledThreadPool::new(num_threads))),
            connections: Arc::new(Mutex::new(HashMap::new())),
            secret_key: SecretKey::generate(&mut rng),
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
            if let Some(node) = self.known_nodes.lock().iter().find(|n| n.id == node_id) {
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
            own_node_id: self.node_id.clone(),
            secret_key: self.secret_key.clone(),
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
            &params.secret_key,
            params.own_node_id,
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

        Ok(stream)
    }

    /// Performs a key exchange
    fn perform_key_exchange(
        is_server: bool,
        stream: &mut TcpStream,
        secret_key: &SecretKey,
        own_node_id: String,
        known_nodes: Arc<Mutex<Vec<Node>>>,
    ) -> VentedResult<(String, ChaChaBox)> {
        if is_server {
            Self::perform_server_key_exchange(stream, secret_key, own_node_id, known_nodes)
        } else {
            Self::perform_client_key_exchange(stream, secret_key, own_node_id)
        }
    }

    /// Performs the client side DH key exchange
    fn perform_client_key_exchange(
        mut stream: &mut TcpStream,
        secret_key: &SecretKey,
        own_node_id: String,
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
        if event.name != CONN_ACCEPT_EVENT {
            return Err(VentedError::UnknownNode(event.name));
        }
        let NodeInformationPayload {
            public_key,
            node_id,
        } = event.get_payload::<NodeInformationPayload>().unwrap();
        let public_key = PublicKey::from(public_key);
        let secret_box = ChaChaBox::new(&public_key, &secret_key);

        Ok((node_id, secret_box))
    }

    /// Performs a DH key exchange by using the crypto_box module and events
    /// On success it returns a secret box with the established secret and the node id of the client
    fn perform_server_key_exchange(
        mut stream: &mut TcpStream,
        secret_key: &SecretKey,
        own_node_id: String,
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

        if known_nodes
            .lock()
            .iter()
            .find(|n| n.id == node_id)
            .is_none()
        {
            stream.write(&Event::new(CONN_REJECT_EVENT.to_string()).as_bytes())?;
            stream.flush()?;
            return Err(VentedError::UnknownNode(node_id));
        }

        let secret_box = ChaChaBox::new(&public_key, &secret_key);
        stream.write(
            &Event::with_payload(
                CONN_ACCEPT_EVENT.to_string(),
                &NodeInformationPayload {
                    public_key: secret_key.public_key().to_bytes(),
                    node_id: own_node_id,
                },
            )
            .as_bytes(),
        )?;
        stream.flush()?;

        Ok((node_id, secret_box))
    }
}
