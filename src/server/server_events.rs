use serde::{Deserialize, Serialize};

pub(crate) const CONNECT_EVENT: &str = "conn:connect";
pub(crate) const AUTH_EVENT: &str = "conn:authenticate";
pub(crate) const CHALLENGE_EVENT: &str = "conn:challenge";
pub(crate) const ACCEPT_EVENT: &str = "conn:accept";
pub(crate) const REJECT_EVENT: &str = "conn:reject";

pub const READY_EVENT: &str = "connection:ready";

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct NodeInformationPayload {
    pub node_id: String,
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ChallengePayload {
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AuthPayload {
    pub calculated_secret: [u8; 32],
}
