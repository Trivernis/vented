use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};

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
