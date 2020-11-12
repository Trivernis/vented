use async_std::net::{TcpListener, TcpStream};
use std::collections::HashMap;
use std::iter::FromIterator;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crypto_box::{PublicKey, SecretKey};
use parking_lot::Mutex;
use sha2::Digest;
use x25519_dalek::StaticSecret;

use crate::event::Event;
use crate::event_handler::EventHandler;
use crate::server::data::{Node, NodeData, NodeState, ServerTimeouts};
use crate::server::server_events::{
    AuthPayload, ChallengePayload, NodeInformationPayload, RedirectPayload, VersionMismatchPayload,
    ACCEPT_EVENT, AUTH_EVENT, CHALLENGE_EVENT, CONNECT_EVENT, MISMATCH_EVENT, READY_EVENT,
    REDIRECT_EVENT, REJECT_EVENT,
};
use crate::stream::cryptostream::CryptoStream;
use crate::utils::result::{VentedError, VentedResult};
use crate::utils::sync::AsyncValue;
use async_listen::ListenExt;
use async_std::prelude::*;
use async_std::task;
use std::pin::Pin;

pub mod data;
pub mod server_events;

pub(crate) const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: &str = "1.0";

type ForwardFutureVector = Arc<Mutex<HashMap<(String, String), AsyncValue<CryptoStream, ()>>>>;

/// The vented server that provides parallel handling of connections
/// Usage:
/// ```rust
/// use vented::server::VentedServer;
/// use vented::server::data::{Node, ServerTimeouts};
/// use vented::stream::SecretKey;
/// use rand::thread_rng;
/// use vented::event::Event;
///
/// let global_secret_b = SecretKey::generate(&mut thread_rng());
/// let nodes = vec![
/// Node {
///        id: "B".to_string(),
///        addresses: vec![],
///        trusted: true,
///        public_key: global_secret_b.public_key() // load it from somewhere
///    },
///];
/// // in a real world example the secret key needs to be loaded from somewhere because connections
/// // with unknown keys are not accepted.
/// let global_secret = SecretKey::generate(&mut thread_rng());
/// let mut server = VentedServer::new("A".to_string(), global_secret, nodes.clone(), ServerTimeouts::default());
///
///
/// server.listen("localhost:20000".to_string());
/// server.on("pong", |_event| {
///    Box::pin(async {println!("Pong!");
///    
///        None
///    })
/// });
/// assert!(async_std::task::block_on(server.emit("B", Event::new("ping".to_string()))).is_err()) // this won't work without a known node B
/// ```
#[derive(Clone)]
pub struct VentedServer {
    forwarded_connections: ForwardFutureVector,
    known_nodes: Arc<Mutex<HashMap<String, NodeData>>>,
    event_handler: EventHandler,
    global_secret_key: SecretKey,
    node_id: String,
    redirect_handles: Arc<Mutex<HashMap<[u8; 16], AsyncValue<(), VentedError>>>>,
    timeouts: ServerTimeouts,
    connections: Arc<Mutex<HashMap<String, CryptoStream>>>,
}

impl VentedServer {
    /// Creates a new vented server with a given node_id and secret key that are
    /// used to authenticate against other servers.
    /// The given nodes are used for authentication.
    pub fn new(
        node_id: String,
        secret_key: SecretKey,
        nodes: Vec<Node>,
        timeouts: ServerTimeouts,
    ) -> Self {
        let mut server = Self {
            node_id,
            connections: Arc::new(Mutex::new(HashMap::new())),
            event_handler: EventHandler::new(),
            forwarded_connections: Arc::new(Mutex::new(HashMap::new())),
            global_secret_key: secret_key,
            known_nodes: Arc::new(Mutex::new(HashMap::from_iter(
                nodes
                    .iter()
                    .cloned()
                    .map(|node| (node.id.clone(), node.into())),
            ))),
            redirect_handles: Arc::new(Mutex::new(HashMap::new())),
            timeouts,
        };
        server.register_events();

        server
    }

    /// Returns the nodeId of the server
    pub fn node_id(&self) -> String {
        self.node_id.clone()
    }

    /// Returns the nodes known to the server
    pub fn nodes(&self) -> Vec<Node> {
        self.known_nodes
            .lock()
            .values()
            .cloned()
            .map(Node::from)
            .collect()
    }

    /// Returns the actual reference to the inner node list
    pub fn nodes_ref(&self) -> Arc<Mutex<HashMap<String, NodeData>>> {
        Arc::clone(&self.known_nodes)
    }

    /// Emits an event to the specified Node
    #[inline]
    pub async fn emit<S: ToString>(&self, node_id: S, event: Event) -> VentedResult<()> {
        self.send_event(&node_id.to_string(), event, true).await
    }

    /// Adds a handler for the given event.
    /// The event returned by the handler is returned to the sender.
    /// Multiple handlers can be registered for an event.
    pub fn on<F: 'static>(&mut self, event_name: &str, handler: F)
    where
        F: Fn(Event) -> Pin<Box<dyn Future<Output = Option<Event>>>> + Send + Sync,
    {
        self.event_handler.on(event_name, handler);
    }

    /// Starts listening on the specified address (with port!)
    /// This will cause a new thread to start up so that the method returns immediately
    /// With the returned wait group one can wait for the server to be ready.
    /// The method can be called multiple times to start listeners on multiple ports.
    pub fn listen(&self, address: String) {
        let this = self.clone();
        task::spawn(async move {
            let listener = match TcpListener::bind(&address).await {
                Ok(l) => l,
                Err(e) => {
                    log::error!("Failed to bind listener to address {}: {}", address, e);
                    return;
                }
            };
            log::info!("Listener running on {}", address);
            while let Some((token, stream)) = listener
                .incoming()
                .log_warnings(|e| log::warn!("Failed to establish connection: {}", e))
                .handle_errors(Duration::from_millis(500))
                .backpressure(1000)
                .next()
                .await
            {
                let mut this = this.clone();
                task::spawn(async move {
                    if let Err(e) = this.handle_connection(stream).await {
                        log::error!("Failed to handle connection: {}", e);
                    }
                    std::mem::drop(token)
                });
            }
        });
    }

    /// Sends an event asynchronously to a node
    /// The redirect flag is used to determine if it should be tried to redirect an event after
    /// a direct sending attempt failed
    async fn send_event(&self, target: &String, event: Event, redirect: bool) -> VentedResult<()> {
        log::trace!(
            "Emitting: '{}' from {} to {}",
            event.name,
            self.node_id,
            target
        );
        let mut result = Ok(());
        let node_state = if let Ok(mut stream) = self.get_connection(target).await {
            log::trace!("Reusing existing connection.");
            match stream.send(event).await {
                Ok(_) => NodeState::Alive(Instant::now()),
                Err(e) => {
                    result = Err(e);
                    NodeState::Dead(Instant::now())
                }
            }
        } else if redirect {
            log::trace!("Trying to use a proxy node...");
            match self.send_event_redirected(&target, event).await {
                Ok(_) => {
                    result = Ok(());
                    NodeState::Alive(Instant::now())
                }
                Err(e) => {
                    log::trace!("Failed to redirect: {}", e);
                    result = Err(e);
                    NodeState::Dead(Instant::now())
                }
            }
        } else {
            log::trace!("Failed to emit event to node {}", target);
            result = Err(VentedError::UnreachableNode(target.clone()));

            NodeState::Dead(Instant::now())
        };

        if let Some(node) = self.known_nodes.lock().get_mut(target) {
            node.set_node_state(node_state);
        }

        result
    }

    /// Tries to send an event redirected by emitting a redirect event to all public nodes
    async fn send_event_redirected(&self, target: &String, event: Event) -> VentedResult<()> {
        let connected_nodes = self
            .known_nodes
            .lock()
            .values()
            .filter(|node| node.is_alive())
            .cloned()
            .collect::<Vec<NodeData>>();

        for node in connected_nodes {
            let payload = RedirectPayload::new(
                self.node_id.clone(),
                node.node().id.clone(),
                target.clone(),
                event.clone().as_bytes(),
            );
            let mut value = AsyncValue::new();
            self.redirect_handles
                .lock()
                .insert(payload.id, AsyncValue::clone(&value));

            if let Ok(mut stream) = self.get_connection(&node.node().id).await {
                if let Err(e) = stream
                    .send(Event::with_payload(REDIRECT_EVENT, &payload))
                    .await
                {
                    log::trace!("Failed to redirect via {}: {}", stream.receiver_node(), e);
                    continue;
                }
            } else {
                continue;
            }

            if let Some(Ok(_)) = value
                .get_value_with_timeout_async(self.timeouts.redirect_timeout.clone())
                .await
            {
                return Ok(());
            } else {
                log::error!("Failed to redirect via {}: Timeout", node.node().id);
            }
        }

        Err(VentedError::UnreachableNode(target.clone()))
    }

    /// Handles a single connection by first performing a key exchange and
    /// then establishing an encrypted connection
    async fn handle_connection(&mut self, stream: TcpStream) -> VentedResult<()> {
        log::trace!(
            "Received connection from {}",
            stream.peer_addr().expect("Failed to get peer address")
        );

        let stream = self.perform_server_key_exchange(stream).await?;

        log::trace!("Secure connection established.");
        self.connections
            .lock()
            .insert(stream.receiver_node().clone(), stream.clone());
        self.event_handler
            .handle_event(Event::new(READY_EVENT))
            .await;
        Self::read_stream(
            stream.clone(),
            self.connections.clone(),
            self.event_handler.clone(),
        )
        .await;

        Ok(())
    }

    /// Reads events from the stream and removes it from the known connections when it's closed
    async fn read_stream(
        mut stream: CryptoStream,
        connections: Arc<Mutex<HashMap<String, CryptoStream>>>,
        mut handler: EventHandler,
    ) {
        loop {
            match stream.read().await {
                Ok(mut event) => {
                    event.origin = Some(stream.receiver_node().clone());
                    let results = handler.handle_event(event).await;
                    for result in results {
                        if let Err(e) = stream.send(result).await {
                            log::error!(
                                "Failed to send event to {}: {}",
                                stream.receiver_node(),
                                e
                            );
                            break;
                        }
                    }
                }
                Err(e) => {
                    log::error!(
                        "Failed to read events from {}: {}",
                        stream.receiver_node(),
                        e
                    );
                    break;
                }
            }
        }
        connections.lock().remove(stream.receiver_node());
    }

    /// Takes three attempts to retrieve a connection for the given node.
    /// First it tries to use the already established connection stored in the shared connections vector.
    /// If that fails it tries to establish a new connection to the node by using the known address
    async fn get_connection(&self, target: &String) -> VentedResult<CryptoStream> {
        if let Some(stream) = self.connections.lock().get(target) {
            log::trace!("Reusing existing connection.");
            return Ok(stream.clone());
        }

        let target_node = self
            .known_nodes
            .lock()
            .get(target)
            .cloned()
            .ok_or(VentedError::UnknownNode(target.clone()))?;

        log::trace!("Connecting to known addresses");

        for address in &target_node.node().addresses {
            match self.connect(address.clone()).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    log::error!("Failed to connect to node {}'s address: {}", target, e);
                    self.known_nodes
                        .lock()
                        .get_mut(target)
                        .unwrap()
                        .node_mut()
                        .addresses
                        .retain(|a| a != address);
                }
            }
        }

        log::trace!("All direct connection attempts to {} failed", target);
        Err(VentedError::UnreachableNode(target.clone()))
    }

    /// Connects to the given address as a tcp client
    async fn connect(&self, address: String) -> VentedResult<CryptoStream> {
        let stream = TcpStream::connect(address).await?;
        let stream = self.perform_client_key_exchange(stream).await?;
        self.connections
            .lock()
            .insert(stream.receiver_node().clone(), stream.clone());
        task::spawn(Self::read_stream(
            stream.clone(),
            self.connections.clone(),
            self.event_handler.clone(),
        ));

        Ok(stream)
    }

    /// Performs the client side DH key exchange
    async fn perform_client_key_exchange(
        &self,
        mut stream: TcpStream,
    ) -> VentedResult<CryptoStream> {
        let secret_key = SecretKey::generate(&mut rand::thread_rng());
        stream
            .write(
                &Event::with_payload(
                    CONNECT_EVENT,
                    &NodeInformationPayload {
                        public_key: secret_key.public_key().to_bytes(),
                        node_id: self.node_id.clone(),
                        vented_version: PROTOCOL_VERSION.to_string(),
                    },
                )
                .as_bytes(),
            )
            .await?;
        stream.flush().await?;
        let event = Event::from_async_tcp(&mut stream).await?;

        if event.name != CONNECT_EVENT {
            return Err(VentedError::UnexpectedEvent(event.name));
        }
        let NodeInformationPayload {
            public_key,
            node_id,
            vented_version,
        } = event.get_payload::<NodeInformationPayload>().unwrap();

        if !Self::compare_version(&vented_version, PROTOCOL_VERSION) {
            stream
                .write(
                    &Event::with_payload(
                        MISMATCH_EVENT,
                        &VersionMismatchPayload::new(PROTOCOL_VERSION, &vented_version),
                    )
                    .as_bytes(),
                )
                .await?;
            stream.flush().await?;
            return Err(VentedError::VersionMismatch(vented_version));
        }

        let public_key = PublicKey::from(public_key);

        let node_data = if let Some(data) = self.known_nodes.lock().get(&node_id) {
            data.clone()
        } else {
            stream.write(&Event::new(REJECT_EVENT).as_bytes()).await?;
            stream.flush().await?;
            return Err(VentedError::UnknownNode(node_id));
        };

        let mut stream = CryptoStream::new(node_id.clone(), stream, &public_key, &secret_key)?;

        log::trace!("Authenticating recipient...");
        let key_a = Self::authenticate_other(&mut stream, node_data.node().public_key).await?;
        log::trace!("Authenticating self...");
        let key_b = Self::authenticate_self(
            &mut stream,
            StaticSecret::from(self.global_secret_key.to_bytes()),
        )
        .await?;
        log::trace!("Connection fully authenticated.");

        let pre_secret = StaticSecret::from(secret_key.to_bytes()).diffie_hellman(&public_key);
        let final_secret =
            Self::generate_final_secret(pre_secret.to_bytes().to_vec(), key_a, key_b);
        let final_public = final_secret.public_key();
        stream.update_key(&final_secret, &final_public);

        Ok(stream)
    }

    /// Performs a DH key exchange by using the crypto_box module and events
    /// On success it returns a secret box with the established secret and the node id of the client
    async fn perform_server_key_exchange(
        &self,
        mut stream: TcpStream,
    ) -> VentedResult<CryptoStream> {
        let secret_key = SecretKey::generate(&mut rand::thread_rng());
        let event = Event::from_async_tcp(&mut stream).await?;

        if event.name != CONNECT_EVENT {
            return Err(VentedError::UnexpectedEvent(event.name));
        }
        let NodeInformationPayload {
            public_key,
            node_id,
            vented_version,
        } = event.get_payload::<NodeInformationPayload>().unwrap();

        if !Self::compare_version(&vented_version, PROTOCOL_VERSION) {
            stream
                .write(
                    &Event::with_payload(
                        MISMATCH_EVENT,
                        &VersionMismatchPayload::new(PROTOCOL_VERSION, &vented_version),
                    )
                    .as_bytes(),
                )
                .await?;
            stream.flush().await?;
            return Err(VentedError::VersionMismatch(vented_version));
        }

        let public_key = PublicKey::from(public_key);
        let data_options = self.known_nodes.lock().get(&node_id).cloned();
        let node_data = if let Some(data) = data_options {
            data
        } else {
            stream.write(&Event::new(REJECT_EVENT).as_bytes()).await?;
            stream.flush().await?;
            return Err(VentedError::UnknownNode(node_id));
        };

        stream
            .write(
                &Event::with_payload(
                    CONNECT_EVENT,
                    &NodeInformationPayload {
                        public_key: secret_key.public_key().to_bytes(),
                        node_id: self.node_id.clone(),
                        vented_version: PROTOCOL_VERSION.to_string(),
                    },
                )
                .as_bytes(),
            )
            .await?;
        stream.flush().await?;

        let mut stream = CryptoStream::new(node_id.clone(), stream, &public_key, &secret_key)?;

        log::trace!("Authenticating self...");
        let key_a = Self::authenticate_self(
            &mut stream,
            StaticSecret::from(self.global_secret_key.to_bytes()),
        )
        .await?;
        log::trace!("Authenticating recipient...");
        let key_b = Self::authenticate_other(&mut stream, node_data.node().public_key).await?;
        log::trace!("Connection fully authenticated.");

        let pre_secret = StaticSecret::from(secret_key.to_bytes()).diffie_hellman(&public_key);
        let final_secret =
            Self::generate_final_secret(pre_secret.to_bytes().to_vec(), key_a, key_b);
        let final_public = final_secret.public_key();
        stream.update_key(&final_secret, &final_public);

        Ok(stream)
    }

    /// Performs the challenged side of the authentication challenge
    async fn authenticate_self(
        stream: &mut CryptoStream,
        static_secret: StaticSecret,
    ) -> VentedResult<Vec<u8>> {
        let challenge_event = stream.read().await?;

        if challenge_event.name != CHALLENGE_EVENT {
            stream.send(Event::new(REJECT_EVENT)).await?;
            return Err(VentedError::UnexpectedEvent(challenge_event.name));
        }
        let ChallengePayload { public_key } = challenge_event.get_payload()?;
        let auth_key = static_secret.diffie_hellman(&PublicKey::from(public_key));

        stream
            .send(Event::with_payload(
                AUTH_EVENT,
                &AuthPayload {
                    calculated_secret: auth_key.to_bytes(),
                },
            ))
            .await?;

        let response = stream.read().await?;

        match response.name.as_str() {
            ACCEPT_EVENT => Ok(auth_key.to_bytes().to_vec()),
            REJECT_EVENT => Err(VentedError::Rejected),
            _ => {
                stream.send(Event::new(REJECT_EVENT)).await?;
                Err(VentedError::UnexpectedEvent(response.name))
            }
        }
    }

    /// Authenticates the other party by using their stored public key and a generated secret
    async fn authenticate_other(
        stream: &mut CryptoStream,
        other_static_public: PublicKey,
    ) -> VentedResult<Vec<u8>> {
        let auth_secret = SecretKey::generate(&mut rand::thread_rng());
        stream
            .send(Event::with_payload(
                CHALLENGE_EVENT,
                &ChallengePayload {
                    public_key: auth_secret.public_key().to_bytes(),
                },
            ))
            .await?;

        let auth_event = stream.read().await?;

        if auth_event.name != AUTH_EVENT {
            stream.send(Event::new(REJECT_EVENT)).await?;
            return Err(VentedError::UnexpectedEvent(auth_event.name));
        }
        let AuthPayload { calculated_secret } = auth_event.get_payload()?;
        let expected_secret =
            StaticSecret::from(auth_secret.to_bytes()).diffie_hellman(&other_static_public);

        if expected_secret.to_bytes() != calculated_secret {
            stream.send(Event::new(REJECT_EVENT)).await?;
            Err(VentedError::AuthFailed)
        } else {
            stream.send(Event::new(ACCEPT_EVENT)).await?;
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
