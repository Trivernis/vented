use std::sync::Arc;

use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;

use crate::event::Event;
use crate::server::data::Node;
use crate::server::VentedServer;
use crate::utils::result::VentedError;

pub(crate) const CONNECT_EVENT: &str = "conn:connect";
pub(crate) const AUTH_EVENT: &str = "conn:authenticate";
pub(crate) const CHALLENGE_EVENT: &str = "conn:challenge";
pub(crate) const ACCEPT_EVENT: &str = "conn:accept";
pub(crate) const REJECT_EVENT: &str = "conn:reject";
pub(crate) const MISMATCH_EVENT: &str = "conn:reject_version_mismatch";
pub(crate) const REDIRECT_EVENT: &str = "conn:redirect";
pub(crate) const REDIRECT_CONFIRM_EVENT: &str = "conn:redirect_confirm";
pub(crate) const REDIRECT_FAIL_EVENT: &str = "conn:redirect_failed";
pub(crate) const REDIRECT_REDIRECTED_EVENT: &str = "conn:redirect_redirected";
pub const NODE_LIST_REQUEST_EVENT: &str = "conn:node_list_request";
pub const NODE_LIST_EVENT: &str = "conn:node_list";

pub(crate) const READY_EVENT: &str = "server:ready";

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct NodeInformationPayload {
    pub node_id: String,
    pub public_key: [u8; 32],
    pub vented_version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ChallengePayload {
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AuthPayload {
    pub calculated_secret: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct VersionMismatchPayload {
    pub expected: String,
    pub got: String,
}

impl VersionMismatchPayload {
    pub fn new(expected: &str, got: &str) -> Self {
        Self {
            expected: expected.to_string(),
            got: got.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct RedirectPayload {
    pub(crate) source: String,
    pub(crate) proxy: String,
    pub(crate) target: String,
    pub(crate) content: Vec<u8>,
    pub(crate) id: [u8; 16],
}

impl RedirectPayload {
    pub fn new(source: String, proxy: String, target: String, content: Vec<u8>) -> Self {
        let mut id = [0u8; 16];
        thread_rng().fill_bytes(&mut id);

        Self {
            source,
            target,
            content,
            proxy,
            id,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RedirectResponsePayload {
    pub(crate) id: [u8; 16],
}

#[derive(Serialize, Deserialize)]
pub struct NodeListPayload {
    pub nodes: Vec<NodeListElement>,
}

#[derive(Serialize, Deserialize)]
pub struct NodeListElement {
    pub id: String,
    pub public_key: [u8; 32],
    pub address: Option<String>,
}

impl VentedServer {
    /// Registers default server events
    pub(crate) fn register_events(&mut self) {
        self.on(REDIRECT_CONFIRM_EVENT, {
            let redirect_handles = Arc::clone(&self.redirect_handles);
            move |event| {
                let payload = event.get_payload::<RedirectResponsePayload>().ok()?;
                let mut future = redirect_handles.lock().remove(&payload.id)?;
                future.resolve(());

                None
            }
        });
        self.on(REDIRECT_FAIL_EVENT, {
            let redirect_handles = Arc::clone(&self.redirect_handles);
            move |event| {
                let payload = event.get_payload::<RedirectResponsePayload>().ok()?;
                let mut future = redirect_handles.lock().remove(&payload.id)?;
                future.reject(VentedError::Rejected);

                None
            }
        });
        self.on(REDIRECT_EVENT, {
            let manager = self.manager.clone();
            let pool = Arc::clone(&self.pool);

            move |event| {
                let payload = event.get_payload::<RedirectPayload>().ok()?;
                let origin = event.origin?;
                let manager = manager.clone();

                pool.lock().execute(move || {
                    let response = if manager
                        .send(
                            &payload.target,
                            Event::with_payload(REDIRECT_REDIRECTED_EVENT, &payload),
                        )
                        .get_value()
                        .is_ok()
                    {
                        Event::with_payload(
                            REDIRECT_CONFIRM_EVENT,
                            &RedirectResponsePayload { id: payload.id },
                        )
                    } else {
                        Event::with_payload(
                            REDIRECT_FAIL_EVENT,
                            &RedirectResponsePayload { id: payload.id },
                        )
                    };
                    manager.send(&origin, response);
                });

                None
            }
        });
        self.on(REDIRECT_REDIRECTED_EVENT, {
            let event_handler = Arc::clone(&self.event_handler);
            let manager = self.manager.clone();
            let pool = self.pool.clone();
            let known_nodes = Arc::clone(&self.known_nodes);

            move |event| {
                let payload = event.get_payload::<RedirectPayload>().ok()?;
                let event = Event::from_bytes(&mut &payload.content[..]).ok()?;

                if known_nodes.lock().contains_key(&payload.source) {
                    pool.lock().execute({
                        let event_handler = Arc::clone(&event_handler);
                        let manager = manager.clone();
                        move || {
                            let responses = event_handler.lock().handle_event(event);
                            responses
                                .iter()
                                .cloned()
                                .map(|mut value| {
                                    let payload = payload.clone();
                                    Event::with_payload(
                                        REDIRECT_EVENT,
                                        &RedirectPayload::new(
                                            payload.target,
                                            payload.proxy,
                                            payload.source,
                                            value.as_bytes(),
                                        ),
                                    )
                                })
                                .for_each(|event| {
                                    manager.send(&payload.proxy, event);
                                });
                        }
                    });
                }

                None
            }
        });
        self.on(NODE_LIST_EVENT, {
            let node_list = Arc::clone(&self.known_nodes);
            let own_id = self.node_id.clone();

            move |event| {
                let list = event.get_payload::<NodeListPayload>().ok()?;
                let mut own_nodes = node_list.lock();
                let origin = event.origin?;

                if !own_nodes.get(&origin)?.trusted {
                    log::warn!("Untrusted node '{}' tried to send network update!", origin);
                    return None;
                }

                let mut new_nodes = 0;
                for node in list.nodes {
                    if !own_nodes.contains_key(&node.id) && node.id != own_id {
                        own_nodes.insert(
                            node.id.clone(),
                            Node {
                                id: node.id,
                                trusted: false,
                                public_key: PublicKey::from(node.public_key),
                                address: node.address,
                            },
                        );
                        new_nodes += 1;
                    }
                }
                log::debug!("Updated node list: Added {} new nodes", new_nodes);

                None
            }
        });
        self.on(NODE_LIST_REQUEST_EVENT, {
            let node_list = Arc::clone(&self.known_nodes);

            move |event| {
                let sender_id = event.origin?;
                let nodes = node_list
                    .lock()
                    .values()
                    .filter(|node| node.id != sender_id)
                    .map(|node| NodeListElement {
                        id: node.id.clone(),
                        address: node.address.clone(),
                        public_key: node.public_key.to_bytes(),
                    })
                    .collect();

                Some(Event::with_payload(
                    NODE_LIST_EVENT,
                    &NodeListPayload { nodes },
                ))
            }
        });
    }
}
