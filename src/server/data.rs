use crate::crypto::CryptoStream;
use crate::event_handler::EventHandler;
use crypto_box::SecretKey;
use parking_lot::Mutex;
use scheduled_thread_pool::ScheduledThreadPool;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Node {
    pub id: String,
    pub address: Option<String>,
}

#[derive(Clone)]
pub(crate) struct ServerConnectionContext {
    pub is_server: bool,
    pub secret_key: SecretKey,
    pub own_node_id: String,
    pub known_nodes: Arc<Mutex<Vec<Node>>>,
    pub event_handler: Arc<Mutex<EventHandler>>,
    pub connections: Arc<Mutex<HashMap<String, CryptoStream>>>,
    pub listener_pool: Arc<Mutex<ScheduledThreadPool>>,
}
