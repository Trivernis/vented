use crate::crypto::CryptoStream;
use crate::event_handler::EventHandler;
use crate::utils::result::VentedError;
use crate::utils::sync::AsyncValue;
use crypto_box::SecretKey;
use executors::crossbeam_workstealing_pool;
use executors::parker::DynParker;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use x25519_dalek::PublicKey;

#[derive(Clone, Debug)]
pub struct Node {
    pub id: String,
    pub public_key: PublicKey,
    pub address: Option<String>,
    pub trusted: bool,
}

#[derive(Clone)]
pub(crate) struct ServerConnectionContext {
    pub is_server: bool,
    pub node_id: String,
    pub global_secret: SecretKey,
    pub known_nodes: Arc<Mutex<HashMap<String, Node>>>,
    pub event_handler: Arc<Mutex<EventHandler>>,
    pub connections: Arc<Mutex<HashMap<String, CryptoStream>>>,
    pub forwarded_connections: Arc<Mutex<HashMap<(String, String), AsyncValue<CryptoStream, ()>>>>,
    pub pool: crossbeam_workstealing_pool::ThreadPool<DynParker>,
    pub redirect_handles: Arc<Mutex<HashMap<[u8; 16], AsyncValue<(), VentedError>>>>,
    pub listener_count: Arc<AtomicUsize>,
}
