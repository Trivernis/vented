use std::collections::HashMap;
use std::io::Write;
use std::iter::FromIterator;
use std::mem;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_utils::sync::WaitGroup;
use crypto_box::{PublicKey, SecretKey};
use parking_lot::Mutex;
use scheduled_thread_pool::ScheduledThreadPool;
use sha2::Digest;
use x25519_dalek::StaticSecret;

use crate::event::Event;
use crate::event_handler::EventHandler;
use crate::server::data::{Node, NodeData, NodeState, ServerConnectionContext};
use crate::server::server_events::{
    AuthPayload, ChallengePayload, NodeInformationPayload, RedirectPayload, VersionMismatchPayload,
    ACCEPT_EVENT, AUTH_EVENT, CHALLENGE_EVENT, CONNECT_EVENT, MISMATCH_EVENT, READY_EVENT,
    REDIRECT_EVENT, REJECT_EVENT,
};
use crate::stream::cryptostream::CryptoStream;
use crate::stream::manager::{ConcurrentStreamManager, CONNECTION_TIMEOUT_SECONDS};
use crate::utils::result::{VentedError, VentedResult};
use crate::utils::sync::AsyncValue;
use std::cmp::max;

pub mod data;
pub mod server_events;

pub(crate) const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: &str = "1.0";

type ForwardFutureVector = Arc<Mutex<HashMap<(String, String), AsyncValue<CryptoStream, ()>>>>;

/// The vented server that provides parallel handling of connections
/// Usage:
/// ```rust
/// use vented::server::VentedServer;
/// use vented::server::data::Node;
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
/// let mut server = VentedServer::new("A".to_string(), global_secret, nodes.clone(), 4, 100);
///
///
/// server.listen("localhost:20000".to_string());
/// server.on("pong", |_event| {
///    println!("Pong!");
///    
///    None    // the return value is the response event Option<Event>
/// });
/// assert!(server.emit("B", Event::new("ping".to_string())).get_value().is_err()) // this won't work without a known node B
/// ```
pub struct VentedServer {
    forwarded_connections: ForwardFutureVector,
    known_nodes: Arc<Mutex<HashMap<String, NodeData>>>,
    event_handler: Arc<Mutex<EventHandler>>,
    global_secret_key: SecretKey,
    node_id: String,
    redirect_handles: Arc<Mutex<HashMap<[u8; 16], AsyncValue<(), VentedError>>>>,
    manager: ConcurrentStreamManager,
    sender_pool: Arc<Mutex<ScheduledThreadPool>>,
    receiver_pool: Arc<Mutex<ScheduledThreadPool>>,
}

impl VentedServer {
    /// Creates a new vented server with a given node_id and secret key that are
    /// used to authenticate against other servers.
    /// The given nodes are used for authentication.
    pub fn new(
        node_id: String,
        secret_key: SecretKey,
        nodes: Vec<Node>,
        num_threads: usize,
        max_threads: usize,
    ) -> Self {
        let mut server = Self {
            node_id,
            manager: ConcurrentStreamManager::new(max_threads),
            event_handler: Arc::new(Mutex::new(EventHandler::new())),
            forwarded_connections: Arc::new(Mutex::new(HashMap::new())),
            global_secret_key: secret_key,
            known_nodes: Arc::new(Mutex::new(HashMap::from_iter(
                nodes
                    .iter()
                    .cloned()
                    .map(|node| (node.id.clone(), node.into())),
            ))),
            redirect_handles: Arc::new(Mutex::new(HashMap::new())),
            sender_pool: Arc::new(Mutex::new(ScheduledThreadPool::new(max(
                num_threads / 2,
                1,
            )))),
            receiver_pool: Arc::new(Mutex::new(ScheduledThreadPool::new(max(
                num_threads / 2,
                1,
            )))),
        };
        server.register_events();
        server.start_event_listener();

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
    /// The actual writing is done in a separate thread from the thread pool.
    /// For that reason an Async value is returned to use it to wait for the result
    pub fn emit<S: ToString>(&self, node_id: S, event: Event) -> AsyncValue<(), VentedError> {
        Self::send_event(self.get_server_context(), &node_id.to_string(), event, true)
    }

    /// Adds a handler for the given event.
    /// The event returned by the handler is returned to the sender.
    /// Multiple handlers can be registered for an event.
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
            event_handler: Arc::clone(&self.event_handler),
            sender_pool: Arc::clone(&self.sender_pool),
            forwarded_connections: Arc::clone(&self.forwarded_connections),
            redirect_handles: Arc::clone(&self.redirect_handles),
            manager: self.manager.clone(),
            recv_pool: Arc::clone(&self.receiver_pool),
        }
    }

    /// Starts the event listener thread
    fn start_event_listener(&self) {
        let receiver = self.manager.receiver();
        let event_handler = Arc::clone(&self.event_handler);
        let context = self.get_server_context();
        let wg = WaitGroup::new();

        thread::spawn({
            let wg = WaitGroup::clone(&wg);
            move || {
                mem::drop(wg);
                while let Ok((origin, event)) = receiver.recv() {
                    if let Some(node) = context.known_nodes.lock().get_mut(&origin) {
                        node.set_node_state(NodeState::Alive(Instant::now()));
                    }
                    let responses = event_handler.lock().handle_event(event);

                    for response in responses {
                        Self::send_event(context.clone(), &origin, response, true);
                    }
                }
                log::warn!("Event listener stopped!");
            }
        });
        wg.wait();
    }

    /// Sends an event asynchronously to a node
    /// The redirect flag is used to determine if it should be tried to redirect an event after
    /// a direct sending attempt failed
    fn send_event(
        context: ServerConnectionContext,
        target: &String,
        event: Event,
        redirect: bool,
    ) -> AsyncValue<(), VentedError> {
        log::trace!(
            "Emitting: '{}' from {} to {}",
            event.name,
            context.node_id,
            target
        );
        if context.manager.has_connection(target) {
            log::trace!("Reusing existing connection.");
            context.manager.send(target, event)
        } else {
            let future = AsyncValue::new();

            context.sender_pool.lock().execute({
                let mut future = AsyncValue::clone(&future);
                let node_id = target.clone();
                let context = context.clone();

                move || {
                    log::trace!("Trying to establish connection...");
                    let node_state = if let Ok(connection) =
                        Self::get_connection(context.clone(), &node_id)
                    {
                        if let Err(e) = context.manager.add_connection(connection) {
                            future.reject(e);
                            return;
                        }
                        log::trace!("Established new connection.");
                        let result = context.manager.send(&node_id, event).get_value();
                        match result {
                            Ok(_) => {
                                future.resolve(());
                                NodeState::Alive(Instant::now())
                            }
                            Err(e) => {
                                future.reject(e);
                                NodeState::Dead(Instant::now())
                            }
                        }
                    } else if redirect {
                        log::trace!("Trying to use a proxy node...");
                        let result = Self::send_event_redirected(context.clone(), &node_id, event);
                        match result {
                            Ok(_) => {
                                future.resolve(());
                                NodeState::Alive(Instant::now())
                            }
                            Err(e) => {
                                future.reject(e);
                                NodeState::Dead(Instant::now())
                            }
                        }
                    } else {
                        log::trace!("Failed to emit event to node {}", node_id);
                        future.reject(VentedError::UnreachableNode(node_id.clone()));
                        NodeState::Dead(Instant::now())
                    };
                    if let Some(node) = context.known_nodes.lock().get_mut(&node_id) {
                        node.set_node_state(node_state);
                    }
                }
            });

            future
        }
    }

    /// Tries to send an event redirected by emitting a redirect event to all public nodes
    fn send_event_redirected(
        context: ServerConnectionContext,
        target: &String,
        event: Event,
    ) -> VentedResult<()> {
        let public_nodes = context
            .known_nodes
            .lock()
            .values()
            .filter(|node| !node.node().addresses.is_empty() && node.is_alive())
            .cloned()
            .collect::<Vec<NodeData>>();

        for node in public_nodes {
            let payload = RedirectPayload::new(
                context.node_id.clone(),
                node.node().id.clone(),
                target.clone(),
                event.clone().as_bytes(),
            );
            let mut future = AsyncValue::new();
            context
                .redirect_handles
                .lock()
                .insert(payload.id, AsyncValue::clone(&future));

            if let Err(e) = Self::send_event(
                context.clone(),
                &node.node().id,
                Event::with_payload(REDIRECT_EVENT, &payload),
                false,
            )
            .get_value()
            {
                log::error!("Failed to redirect via {}: {}", node.node().id, e);
            }

            if let Some(Ok(_)) =
                future.get_value_with_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECONDS))
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
    fn handle_connection(context: ServerConnectionContext, stream: TcpStream) -> VentedResult<()> {
        let event_handler = Arc::clone(&context.event_handler);
        stream.set_write_timeout(Some(Duration::from_secs(CONNECTION_TIMEOUT_SECONDS)))?;
        log::trace!(
            "Received connection from {}",
            stream.peer_addr().expect("Failed to get peer address")
        );

        context.recv_pool.lock().execute({
            let context = context.clone();
            move || {
                let manager = context.manager.clone();

                let stream = match VentedServer::get_crypto_stream(context, stream) {
                    Ok(stream) => stream,
                    Err(e) => {
                        log::error!("Failed to establish encrypted connection: {}", e);
                        return;
                    }
                };
                log::trace!("Secure connection established.");
                if let Err(e) = manager.add_connection(stream) {
                    log::trace!("Failed to add connection to manager: {}", e);
                    return;
                }
                event_handler.lock().handle_event(Event::new(READY_EVENT));
            }
        });

        Ok(())
    }

    /// Takes three attempts to retrieve a connection for the given node.
    /// First it tries to use the already established connection stored in the shared connections vector.
    /// If that fails it tries to establish a new connection to the node by using the known address
    fn get_connection(
        context: ServerConnectionContext,
        target: &String,
    ) -> VentedResult<CryptoStream> {
        let target_node = context
            .known_nodes
            .lock()
            .get(target)
            .cloned()
            .ok_or(VentedError::UnknownNode(target.clone()))?;

        log::trace!("Connecting to known addresses");

        for address in &target_node.node().addresses {
            match Self::connect(context.clone(), address.clone()) {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    log::error!("Failed to connect to node {}'s address: {}", target, e);
                    context
                        .known_nodes
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

    /// Establishes a crypto stream for the given stream
    fn get_crypto_stream(
        context: ServerConnectionContext,
        stream: TcpStream,
    ) -> VentedResult<CryptoStream> {
        let (_, stream) = VentedServer::perform_key_exchange(
            context.is_server,
            stream,
            context.node_id.clone(),
            context.global_secret,
            context.known_nodes,
        )?;

        Ok(stream)
    }

    /// Connects to the given address as a tcp client
    fn connect(
        mut context: ServerConnectionContext,
        address: String,
    ) -> VentedResult<CryptoStream> {
        let stream = TcpStream::connect(address)?;
        stream.set_write_timeout(Some(Duration::from_secs(CONNECTION_TIMEOUT_SECONDS)))?;
        context.is_server = false;
        let stream = Self::get_crypto_stream(context, stream)?;

        Ok(stream)
    }

    /// Performs a key exchange
    fn perform_key_exchange(
        is_server: bool,
        stream: TcpStream,
        own_node_id: String,
        global_secret: SecretKey,
        known_nodes: Arc<Mutex<HashMap<String, NodeData>>>,
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
        known_nodes: Arc<Mutex<HashMap<String, NodeData>>>,
    ) -> VentedResult<(String, CryptoStream)> {
        stream.write(
            &Event::with_payload(
                CONNECT_EVENT,
                &NodeInformationPayload {
                    public_key: secret_key.public_key().to_bytes(),
                    node_id: own_node_id,
                    vented_version: PROTOCOL_VERSION.to_string(),
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

        if !Self::compare_version(&vented_version, PROTOCOL_VERSION) {
            stream.write(
                &Event::with_payload(
                    MISMATCH_EVENT,
                    &VersionMismatchPayload::new(PROTOCOL_VERSION, &vented_version),
                )
                .as_bytes(),
            )?;
            stream.flush()?;
            return Err(VentedError::VersionMismatch(vented_version));
        }

        let public_key = PublicKey::from(public_key);

        let node_data = if let Some(data) = known_nodes.lock().get(&node_id) {
            data.clone()
        } else {
            stream.write(&Event::new(REJECT_EVENT).as_bytes())?;
            stream.flush()?;
            return Err(VentedError::UnknownNode(node_id));
        };

        let mut stream = CryptoStream::new(node_id.clone(), stream, &public_key, &secret_key)?;

        log::trace!("Authenticating recipient...");
        let key_a = Self::authenticate_other(&mut stream, node_data.node().public_key)?;
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
        known_nodes: Arc<Mutex<HashMap<String, NodeData>>>,
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

        if !Self::compare_version(&vented_version, PROTOCOL_VERSION) {
            stream.write(
                &Event::with_payload(
                    MISMATCH_EVENT,
                    &VersionMismatchPayload::new(PROTOCOL_VERSION, &vented_version),
                )
                .as_bytes(),
            )?;
            stream.flush()?;
            return Err(VentedError::VersionMismatch(vented_version));
        }

        let public_key = PublicKey::from(public_key);
        let node_data = if let Some(data) = known_nodes.lock().get(&node_id) {
            data.clone()
        } else {
            stream.write(&Event::new(REJECT_EVENT).as_bytes())?;
            stream.flush()?;
            return Err(VentedError::UnknownNode(node_id));
        };

        stream.write(
            &Event::with_payload(
                CONNECT_EVENT,
                &NodeInformationPayload {
                    public_key: secret_key.public_key().to_bytes(),
                    node_id: own_node_id,
                    vented_version: PROTOCOL_VERSION.to_string(),
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
        let key_b = Self::authenticate_other(&mut stream, node_data.node().public_key)?;
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
