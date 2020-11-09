use std::collections::HashMap;
use std::net::{Shutdown, TcpListener, TcpStream};

use crypto_box::{PublicKey, SecretKey};
use executors::{crossbeam_workstealing_pool, Executor};

use crate::crypto::CryptoStream;
use crate::event::Event;
use crate::event_handler::EventHandler;
use crate::server::data::{Node, ServerConnectionContext};
use crate::server::server_events::{
    AuthPayload, ChallengePayload, NodeInformationPayload, RedirectPayload, VersionMismatchPayload,
    ACCEPT_EVENT, AUTH_EVENT, CHALLENGE_EVENT, CONNECT_EVENT, MISMATCH_EVENT, READY_EVENT,
    REDIRECT_EVENT, REJECT_EVENT,
};
use crate::utils::result::{VentedError, VentedResult};
use crate::utils::sync::AsyncValue;
use crossbeam_utils::sync::WaitGroup;
use executors::parker::DynParker;
use parking_lot::Mutex;
use sha2::Digest;
use std::io::Write;
use std::iter::FromIterator;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use x25519_dalek::StaticSecret;

pub mod data;
pub mod server_events;

pub(crate) const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

type ForwardFutureVector = Arc<Mutex<HashMap<(String, String), AsyncValue<CryptoStream, ()>>>>;
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
/// let global_secret_b = SecretKey::generate(&mut thread_rng());
/// let nodes = vec![
/// Node {
///        id: "B".to_string(),
///        address: None,
///        trusted: true,
///        public_key: global_secret_b.public_key() // load it from somewhere
///    },
///];
/// // in a real world example the secret key needs to be loaded from somewhere because connections
/// // with unknown keys are not accepted.
/// let global_secret = SecretKey::generate(&mut thread_rng());
/// let mut server = VentedServer::new("A".to_string(), global_secret, nodes.clone(), 4);
///
///
/// server.listen("localhost:20000".to_string());
/// server.on("pong", |_event| {
///    println!("Pong!");
///    
///    None    // the return value is the response event Option<Event>
/// });
/// assert!(server.emit("B".to_string(), Event::new("ping".to_string())).get_value().is_err()) // this won't work without a known node B
/// ```
pub struct VentedServer {
    connections: CryptoStreamMap,
    forwarded_connections: ForwardFutureVector,
    known_nodes: Arc<Mutex<HashMap<String, Node>>>,
    pool: crossbeam_workstealing_pool::ThreadPool<DynParker>,
    event_handler: Arc<Mutex<EventHandler>>,
    global_secret_key: SecretKey,
    node_id: String,
    redirect_handles: Arc<Mutex<HashMap<[u8; 16], AsyncValue<(), VentedError>>>>,
    listener_count: Arc<AtomicUsize>,
    num_threads: usize,
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
    ) -> Self {
        let mut server = Self {
            node_id,
            num_threads,
            event_handler: Arc::new(Mutex::new(EventHandler::new())),
            pool: executors::crossbeam_workstealing_pool::pool_with_auto_parker(num_threads),
            connections: Arc::new(Mutex::new(HashMap::new())),
            forwarded_connections: Arc::new(Mutex::new(HashMap::new())),
            global_secret_key: secret_key,
            known_nodes: Arc::new(Mutex::new(HashMap::from_iter(
                nodes.iter().cloned().map(|node| (node.id.clone(), node)),
            ))),
            redirect_handles: Arc::new(Mutex::new(HashMap::new())),
            listener_count: Arc::new(AtomicUsize::new(0)),
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
        self.known_nodes.lock().values().cloned().collect()
    }

    /// Returns the actual reference to the inner node list
    pub fn nodes_ref(&self) -> Arc<Mutex<HashMap<String, Node>>> {
        Arc::clone(&self.known_nodes)
    }

    /// Emits an event to the specified Node
    /// The actual writing is done in a separate thread from the thread pool.
    /// With the returned wait group one can wait for the event to be written.
    pub fn emit(&self, node_id: String, event: Event) -> AsyncValue<(), VentedError> {
        let future = AsyncValue::new();

        self.pool.execute({
            let mut future = AsyncValue::clone(&future);
            let context = self.get_server_context();
            move || {

                if let Ok(stream) = Self::get_connection(context.clone(), &node_id) {
                    if let Err(e) = stream.send(event) {
                        log::error!("Failed to send event: {}", e);
                        context.connections.lock().remove(stream.receiver_node());

                        future.reject(e);
                    } else {
                        future.resolve(());
                    }
                } else {
                    log::trace!(
                        "Trying to redirect the event to a different node to be sent to target node..."
                    );
                    let result = Self::send_event_redirected(context.clone(), node_id, event);
                    future.result(result);
                }
            }
        });

        future
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
        let num_threads = self.num_threads;
        let listener_count = Arc::clone(&self.listener_count);

        thread::spawn(move || match TcpListener::bind(&address) {
            Ok(listener) => {
                log::info!("Listener running on {}", address);
                std::mem::drop(wg);

                for connection in listener.incoming() {
                    match connection {
                        Ok(stream) => {
                            let listener_count = listener_count.load(Ordering::Relaxed);

                            if listener_count >= num_threads {
                                log::warn!("Connection limit reached. Shutting down incoming connection...");
                                if let Err(e) = stream.shutdown(Shutdown::Both) {
                                    log::error!("Failed to shutdown connection: {}", e)
                                }
                            } else {
                                if let Err(e) = Self::handle_connection(context.clone(), stream) {
                                    log::error!("Failed to handle connection: {}", e);
                                }
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
            pool: self.pool.clone(),
            forwarded_connections: Arc::clone(&self.forwarded_connections),
            redirect_handles: Arc::clone(&self.redirect_handles),
            listener_count: Arc::clone(&self.listener_count),
        }
    }

    /// Tries to send an event redirected by emitting a redirect event to all public nodes
    fn send_event_redirected(
        context: ServerConnectionContext,
        target: String,
        event: Event,
    ) -> VentedResult<()> {
        let public_nodes = context
            .known_nodes
            .lock()
            .values()
            .filter(|node| node.address.is_some())
            .cloned()
            .collect::<Vec<Node>>();

        for node in public_nodes {
            let payload = RedirectPayload::new(
                context.node_id.clone(),
                node.id.clone(),
                target.clone(),
                event.clone().as_bytes(),
            );
            let mut future = AsyncValue::new();
            context
                .redirect_handles
                .lock()
                .insert(payload.id, AsyncValue::clone(&future));

            if let Ok(stream) = Self::get_connection(context.clone(), &node.id) {
                if let Err(e) = stream.send(Event::with_payload(REDIRECT_EVENT, &payload)) {
                    log::error!("Failed to send event: {}", e);
                    context.connections.lock().remove(stream.receiver_node());
                }
            }

            if let Some(Ok(_)) = future.get_value_with_timeout(Duration::from_secs(1)) {
                return Ok(());
            }
        }

        Err(VentedError::UnreachableNode(target))
    }

    /// Handles a single connection by first performing a key exchange and
    /// then establishing an encrypted connection
    fn handle_connection(params: ServerConnectionContext, stream: TcpStream) -> VentedResult<()> {
        let event_handler = Arc::clone(&params.event_handler);
        log::trace!(
            "Received connection from {}",
            stream.peer_addr().expect("Failed to get peer address")
        );

        thread::spawn(move || {
            let connections = Arc::clone(&params.connections);
            let listener_count = Arc::clone(&params.listener_count);
            listener_count.fetch_add(1, Ordering::Relaxed);

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
            listener_count.fetch_sub(1, Ordering::Relaxed);
        });

        Ok(())
    }

    /// Handler for reading after the connection is established
    fn handle_read(
        event_handler: Arc<Mutex<EventHandler>>,
        stream: &CryptoStream,
    ) -> VentedResult<()> {
        while let Ok(mut event) = stream.read() {
            event.origin = Some(stream.receiver_node().clone());
            for response in event_handler.lock().handle_event(event) {
                stream.send(response)?
            }
        }

        Ok(())
    }

    /// Takes three attempts to retrieve a connection for the given node.
    /// First it tries to use the already established connection stored in the shared connections vector.
    /// If that fails it tries to establish a new connection to the node by using the known address
    fn get_connection(
        context: ServerConnectionContext,
        target: &String,
    ) -> VentedResult<CryptoStream> {
        log::trace!("Trying to connect to {}", target);

        if let Some(stream) = context.connections.lock().get(target) {
            log::trace!("Reusing existing connection.");

            return Ok(CryptoStream::clone(stream));
        }

        let target_node = context
            .known_nodes
            .lock()
            .get(target)
            .cloned()
            .ok_or(VentedError::UnknownNode(target.clone()))?;

        if let Some(address) = target_node.address {
            log::trace!("Connecting to known address");

            Self::connect(context, address)
        } else {
            log::trace!("All direct connection attempts to {} failed", target);

            Err(VentedError::UnreachableNode(target.clone()))
        }
    }

    /// Establishes a crypto stream for the given stream
    fn get_crypto_stream(
        params: ServerConnectionContext,
        stream: TcpStream,
    ) -> VentedResult<CryptoStream> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

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
    fn connect(
        mut context: ServerConnectionContext,
        address: String,
    ) -> VentedResult<CryptoStream> {
        let stream = TcpStream::connect(address)?;
        context.is_server = false;

        let connections = Arc::clone(&context.connections);
        let event_handler = Arc::clone(&context.event_handler);
        let listener_count = Arc::clone(&context.listener_count);
        let stream = Self::get_crypto_stream(context, stream)?;

        thread::spawn({
            let stream = CryptoStream::clone(&stream);

            move || {
                listener_count.fetch_add(1, Ordering::Relaxed);
                event_handler.lock().handle_event(Event::new(READY_EVENT));
                if let Err(e) = Self::handle_read(event_handler, &stream) {
                    log::error!("Connection aborted: {}", e);
                }
                connections.lock().remove(stream.receiver_node());
                listener_count.fetch_sub(1, Ordering::Relaxed);
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
        known_nodes: Arc<Mutex<HashMap<String, Node>>>,
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
        known_nodes: Arc<Mutex<HashMap<String, Node>>>,
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

        let node_data = if let Some(data) = known_nodes.lock().get(&node_id) {
            data.clone()
        } else {
            stream.write(&Event::new(REJECT_EVENT).as_bytes())?;
            stream.flush()?;
            return Err(VentedError::UnknownNode(node_id));
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
        known_nodes: Arc<Mutex<HashMap<String, Node>>>,
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
