use serde::{Deserialize, Serialize};

pub(crate) const CONNECT_EVENT: &str = "client:connect";
pub(crate) const CONN_ACCEPT_EVENT: &str = "server:conn_accept";
pub(crate) const CONN_REJECT_EVENT: &str = "server:conn_reject";

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct NodeInformationPayload {
    pub node_id: String,
    pub public_key: [u8; 32],
}
