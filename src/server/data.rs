use crate::crypto::CryptoStream;
use crate::event_handler::EventHandler;
use crate::WaitGroup;
use crypto_box::SecretKey;
use parking_lot::Mutex;
use scheduled_thread_pool::ScheduledThreadPool;
use std::collections::HashMap;
use std::mem;
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
    pub forwarded_connections: Arc<Mutex<HashMap<(String, String), Future<CryptoStream>>>>,
    pub listener_pool: Arc<Mutex<ScheduledThreadPool>>,
}

#[derive(Clone)]
pub(crate) struct Future<T> {
    value: Arc<Mutex<Option<T>>>,
    wg: Option<WaitGroup>,
}

impl<T> Future<T> {
    /// Creates the future with no value
    pub fn new() -> Self {
        Self {
            value: Arc::new(Mutex::new(None)),
            wg: Some(WaitGroup::new()),
        }
    }

    /// Creates the future with an already resolved value
    pub fn with_value(value: T) -> Self {
        Self {
            value: Arc::new(Mutex::new(Some(value))),
            wg: None,
        }
    }

    /// Sets the value of the future consuming the wait group
    pub fn set_value(&mut self, value: T) {
        self.value.lock().replace(value);
        mem::take(&mut self.wg);
    }

    /// Returns the value of the future after it has been set.
    /// This call blocks
    pub fn get_value(&mut self) -> T {
        if let Some(wg) = mem::take(&mut self.wg) {
            wg.wait();
        }
        self.value.lock().take().unwrap()
    }
}
