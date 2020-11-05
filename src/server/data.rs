use crate::crypto::CryptoStream;
use crate::event_handler::EventHandler;
use crypto_box::SecretKey;
use parking_lot::Mutex;
use scheduled_thread_pool::ScheduledThreadPool;
use std::collections::HashMap;
use std::sync::Arc;
use x25519_dalek::PublicKey;

#[derive(Clone, Debug)]
pub struct Node {
    pub id: String,
    pub public_key: PublicKey,
    pub address: Option<String>,
}

#[derive(Clone)]
pub(crate) struct ServerConnectionContext {
    pub is_server: bool,
    pub node_id: String,
    pub global_secret: SecretKey,
    pub known_nodes: Arc<Mutex<Vec<Node>>>,
    pub event_handler: Arc<Mutex<EventHandler>>,
    pub connections: Arc<Mutex<HashMap<String, CryptoStream>>>,
    pub listener_pool: Arc<Mutex<ScheduledThreadPool>>,
}
