use std::collections::HashMap;
use std::sync::Arc;

use crypto_box::SecretKey;
use parking_lot::Mutex;
use scheduled_thread_pool::ScheduledThreadPool;
use x25519_dalek::PublicKey;

use crate::event_handler::EventHandler;
use crate::stream::cryptostream::CryptoStream;
use crate::stream::manager::ConcurrentStreamManager;
use crate::utils::result::VentedError;
use crate::utils::sync::AsyncValue;

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
    pub forwarded_connections: Arc<Mutex<HashMap<(String, String), AsyncValue<CryptoStream, ()>>>>,
    pub pool: Arc<Mutex<ScheduledThreadPool>>,
    pub redirect_handles: Arc<Mutex<HashMap<[u8; 16], AsyncValue<(), VentedError>>>>,
    pub manager: ConcurrentStreamManager,
}
