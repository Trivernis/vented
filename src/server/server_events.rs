use serde::{Deserialize, Serialize};

pub(crate) const CONNECT_EVENT: &str = "conn:connect";
pub(crate) const AUTH_EVENT: &str = "conn:authenticate";
pub(crate) const CHALLENGE_EVENT: &str = "conn:challenge";
pub(crate) const ACCEPT_EVENT: &str = "conn:accept";
pub(crate) const REJECT_EVENT: &str = "conn:reject";
pub(crate) const MISMATCH_EVENT: &str = "conn:reject_version_mismatch";
pub const READY_EVENT: &str = "server:ready";

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
