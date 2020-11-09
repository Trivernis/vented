use crate::crypto::CryptoStream;
use crate::event_handler::EventHandler;
use crate::result::VentedError;
use crate::WaitGroup;
use crypto_box::SecretKey;
use executors::crossbeam_workstealing_pool;
use executors::parker::DynParker;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::mem;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
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
}

pub struct AsyncValue<T, E> {
    value: Arc<Mutex<Option<T>>>,
    error: Arc<Mutex<Option<E>>>,
    wg: Option<WaitGroup>,
}

impl<V, E> AsyncValue<V, E>
where
    E: std::fmt::Display,
{
    /// Creates the future with no value
    pub fn new() -> Self {
        Self {
            value: Arc::new(Mutex::new(None)),
            error: Arc::new(Mutex::new(None)),
            wg: Some(WaitGroup::new()),
        }
    }

    /// Creates a new AsyncValue with an already resolved value
    pub fn with_value(value: V) -> Self {
        Self {
            value: Arc::new(Mutex::new(Some(value))),
            error: Arc::new(Mutex::new(None)),
            wg: None,
        }
    }

    pub fn with_error(error: E) -> Self {
        Self {
            value: Arc::new(Mutex::new(None)),
            error: Arc::new(Mutex::new(Some(error))),
            wg: None,
        }
    }

    /// Sets the value of the future consuming the wait group
    pub fn resolve(&mut self, value: V) {
        self.value.lock().replace(value);
        mem::take(&mut self.wg);
    }

    /// Sets an error for the value
    pub fn reject(&mut self, error: E) {
        self.error.lock().replace(error);
        mem::take(&mut self.wg);
    }

    pub fn result(&mut self, result: Result<V, E>) {
        match result {
            Ok(v) => self.resolve(v),
            Err(e) => self.reject(e),
        }
    }

    pub fn block_unwrap(&mut self) -> V {
        match self.get_value() {
            Ok(v) => v,
            Err(e) => panic!("Unwrap on Err value: {}", e),
        }
    }

    /// Returns the value of the future after it has been set.
    /// This call blocks
    pub fn get_value(&mut self) -> Result<V, E> {
        if let Some(wg) = mem::take(&mut self.wg) {
            wg.wait();
        }
        if let Some(err) = self.error.lock().take() {
            Err(err)
        } else {
            Ok(self.value.lock().take().unwrap())
        }
    }

    /// Returns the value of the future only blocking for the given timeout
    pub fn get_value_with_timeout(&mut self, timeout: Duration) -> Option<Result<V, E>> {
        let start = Instant::now();

        while self.value.lock().is_none() {
            thread::sleep(Duration::from_millis(1));
            if start.elapsed() > timeout {
                break;
            }
        }
        if let Some(err) = self.error.lock().take() {
            Some(Err(err))
        } else if let Some(value) = self.value.lock().take() {
            Some(Ok(value))
        } else {
            None
        }
    }
}

impl<T, E> Clone for AsyncValue<T, E> {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            error: Arc::clone(&self.error),
            wg: self.wg.clone(),
        }
    }
}
