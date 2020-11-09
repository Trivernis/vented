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
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Node {
    pub id: String,
    pub public_key: PublicKey,
    pub addresses: Vec<String>,
    pub trusted: bool,
}

#[derive(Clone, Debug)]
pub struct NodeData {
    inner: Node,
    state: NodeState,
}

#[derive(Clone, Debug)]
pub enum NodeState {
    Alive(Instant),
    Dead(Instant),
    Unknown,
}

#[derive(Clone)]
pub(crate) struct ServerConnectionContext {
    pub is_server: bool,
    pub node_id: String,
    pub global_secret: SecretKey,
    pub known_nodes: Arc<Mutex<HashMap<String, NodeData>>>,
    pub event_handler: Arc<Mutex<EventHandler>>,
    pub forwarded_connections: Arc<Mutex<HashMap<(String, String), AsyncValue<CryptoStream, ()>>>>,
    pub sender_pool: Arc<Mutex<ScheduledThreadPool>>,
    pub recv_pool: Arc<Mutex<ScheduledThreadPool>>,
    pub redirect_handles: Arc<Mutex<HashMap<[u8; 16], AsyncValue<(), VentedError>>>>,
    pub manager: ConcurrentStreamManager,
}

impl From<Node> for NodeData {
    fn from(node: Node) -> Self {
        Self {
            inner: node,
            state: NodeState::Unknown,
        }
    }
}

impl From<NodeData> for Node {
    fn from(other: NodeData) -> Self {
        other.inner
    }
}

// how long is a node assumed to be in a state before rechecking is necessary
const NODE_STATE_TTL_SECONDS: u64 = 600;

impl NodeData {
    /// Returns the inner node data
    pub fn node(&self) -> &Node {
        &self.inner
    }

    /// Returns a mutable reference of the inner node data
    pub fn node_mut(&mut self) -> &mut Node {
        &mut self.inner
    }

    /// Returns the state of the node
    pub fn node_state(&mut self) -> &NodeState {
        let ttl = Duration::from_secs(NODE_STATE_TTL_SECONDS);
        match &self.state {
            NodeState::Alive(since) | NodeState::Dead(since) if since.elapsed() > ttl => {
                self.state = NodeState::Unknown;
                log::trace!(
                    "Node state of {} updated to {:?}",
                    self.inner.id,
                    self.state
                )
            }
            _ => {}
        }
        &self.state
    }

    /// Sets the state of the node
    pub fn set_node_state(&mut self, state: NodeState) {
        self.state = state;
        log::trace!(
            "Node state of {} updated to {:?}",
            self.inner.id,
            self.state
        )
    }

    /// Returns if the node is dead
    pub fn is_dead(&self) -> bool {
        match &self.state {
            NodeState::Dead(_) => true,
            _ => false,
        }
    }

    pub fn is_alive(&self) -> bool {
        match &self.state {
            NodeState::Alive(_) => true,
            _ => false,
        }
    }
}
