use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};

use crypto_box::{ChaChaBox, PublicKey, SecretKey};
use scheduled_thread_pool::ScheduledThreadPool;

use crate::crypto::CryptoStream;
use crate::event::Event;
use crate::event_handler::EventHandler;
use crate::result::{VentedError, VentedResult};
use crate::server::server_events::{
    NodeInformationPayload, CONNECT_EVENT, CONN_ACCEPT_EVENT, CONN_REJECT_EVENT,
};
use parking_lot::Mutex;
use std::io::Write;
use std::sync::Arc;

pub(crate) mod server_events;

/// The vented server that provides parallel handling of connections
pub struct VentedServer {
    connections: Arc<Mutex<HashMap<String, CryptoStream>>>,
    known_nodes: Arc<Mutex<Vec<String>>>,
    listener_pool: ScheduledThreadPool,
    sender_pool: ScheduledThreadPool,
    event_handler: Arc<Mutex<EventHandler>>,
    secret_key: SecretKey,
    node_id: String,
}

impl VentedServer {
    pub fn new(node_id: String, nodes: Vec<String>, num_threads: usize) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            node_id,
            event_handler: Arc::new(Mutex::new(EventHandler::new())),
            listener_pool: ScheduledThreadPool::new(num_threads),
            sender_pool: ScheduledThreadPool::new(num_threads),
            connections: Arc::new(Mutex::new(HashMap::new())),
            secret_key: SecretKey::generate(&mut rng),
            known_nodes: Arc::new(Mutex::new(nodes)),
        }
    }

    /// Starts listening on the specified address (with port!)
    pub fn listen(&mut self, address: &str) -> VentedResult<()> {
        let listener = TcpListener::bind(address)?;
        for connection in listener.incoming() {
            match connection {
                Ok(stream) => self.handle_connection(stream)?,
                Err(e) => log::trace!("Failed to establish connection: {}", e),
            }
        }

        Ok(())
    }

    /// Handles a single connection by first performing a key exchange and
    /// then establishing an encrypted connection
    fn handle_connection(&mut self, mut stream: TcpStream) -> VentedResult<()> {
        let secret_key = self.secret_key.clone();
        let self_public_key = secret_key.public_key();
        let connections = Arc::clone(&self.connections);
        let own_node_id = self.node_id.clone();
        let known_nodes = Arc::clone(&self.known_nodes);
        let event_handler = Arc::clone(&self.event_handler);

        self.listener_pool.execute(move || {
            match VentedServer::perform_key_exchange(
                &mut stream,
                &secret_key,
                &self_public_key,
                own_node_id,
                known_nodes,
            ) {
                Ok((node_id, secret_box)) => {
                    let stream = CryptoStream::new(stream, secret_box)
                        .expect("Failed to create crypto stream");
                    connections
                        .lock()
                        .insert(node_id, CryptoStream::clone(&stream));
                    while let Ok(event) = stream.read() {
                        if let Some(response) = event_handler.lock().handle_event(event) {
                            stream.send(response).expect("Failed to send response");
                        }
                    }
                }
                Err(e) => log::error!("Failed to establish connection: {}", e),
            }
        });
        Ok(())
    }

    /// Emits an event to the specified Node
    pub fn emit(&self, node_id: &str, event: Event) -> bool {
        let handler = self.connections.lock().get(node_id).cloned();

        if let Some(handler) = handler {
            self.sender_pool.execute(move || {
                handler.send(event).expect("Failed to send event");
            });
            true
        } else {
            false
        }
    }

    /// Performs a DH key exchange by using the crypto_box module and events
    /// On success it returns a secret box with the established secret and the node id of the client
    fn perform_key_exchange(
        mut stream: &mut TcpStream,
        secret_key: &SecretKey,
        self_public_key: &PublicKey,
        own_node_id: String,
        known_nodes: Arc<Mutex<Vec<String>>>,
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

        if !known_nodes.lock().contains(&node_id) {
            stream.write(&Event::new(CONN_REJECT_EVENT.to_string()).as_bytes())?;
            return Err(VentedError::UnknownNode(node_id));
        }

        let secret_box = ChaChaBox::new(&public_key, &secret_key);
        stream.write(
            &Event::with_payload(
                CONN_ACCEPT_EVENT.to_string(),
                &NodeInformationPayload {
                    public_key: self_public_key.to_bytes(),
                    node_id: own_node_id,
                },
            )
            .as_bytes(),
        )?;

        Ok((node_id, secret_box))
    }
}
