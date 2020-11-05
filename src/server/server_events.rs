use serde::{Deserialize, Serialize};

pub(crate) const CONNECT_EVENT: &str = "client:connect";
pub(crate) const AUTH_EVENT: &str = "client:authenticate";
pub(crate) const CONN_CHALLENGE_EVENT: &str = "server:conn_challenge";
pub(crate) const CONN_ACCEPT_EVENT: &str = "server:conn_accept";
pub(crate) const CONN_REJECT_EVENT: &str = "server:conn_reject";

pub const READY_EVENT: &str = "connection:ready";

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct NodeInformationPayload {
    pub node_id: String,
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AuthPayload {
    pub calculated_secret: [u8; 32],
}
