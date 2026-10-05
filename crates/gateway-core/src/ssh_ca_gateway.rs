//! B-1 slice 3: gateway wiring — the `CaMinter` implements `CaContext` over
//! the gateway's real vault router and enrollment store, and `open_session`
//! branches on `ca://` BEFORE the per-host-key `resolve` (spec §2).
//!
//! The cert text is returned as the session "secret", so the existing
//! `SshBackend::connect` contract is unchanged except for the auth method.

use std::sync::Arc;

use chaperone_identity::EnrollmentStore;
use chaperone_vault::SecretString;

use super::ssh_ca_provider::{AgentIdentity, CA_ENTRY, CaContext, CaError};
use chaperone_vault::VaultRouter;

/// The gateway-side `CaContext`: vault reads go through the same router the
/// per-host path uses (fresh per mint, D5), identity lookups through the
/// enrollment store (RAE L0).
pub struct GatewayCaContext {
    pub vault: Arc<VaultRouter>,
    pub local_entry_secret: Arc<std::sync::RwLock<Option<chaperone_vault::SharedVault>>>,
    pub enrollment: Arc<EnrollmentStore>,
}

impl GatewayCaContext {
    /// Reads the raw CA key text from the local vault entry.
    fn read_ca_text(&self) -> Result<Option<String>, CaError> {
        let guard = self
            .local_entry_secret
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(vault) = guard.as_ref() else {
            return Ok(None);
        };
        let list = vault.lock().list().map_err(|_| CaError::CaUnreadable)?;
        if !list.iter().any(|p| p == CA_ENTRY) {
            return Ok(None);
        }
        let value = vault
            .lock()
            .get(CA_ENTRY)
            .map_err(|_| CaError::CaUnreadable)?
            .ok_or(CaError::CaUnreadable)?;
        Ok(Some(value.expose().to_owned()))
    }

    fn write_ca_text(&self, text: &str) -> Result<(), CaError> {
        let guard = self
            .local_entry_secret
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(vault) = guard.as_ref() else {
            return Err(CaError::CaUnreadable);
        };
        vault
            .lock()
            .set(CA_ENTRY, SecretString::new(text.to_owned()))
            .map_err(|_| CaError::CaUnreadable)
    }
}

impl CaContext for GatewayCaContext {
    fn read_ca_entry(&self) -> Result<Option<String>, CaError> {
        self.read_ca_text()
    }

    fn write_ca_entry(&self, text: &str) -> Result<(), CaError> {
        self.write_ca_text(text)
    }

    fn agent_identity(&self, agent_id: &str) -> Result<Option<AgentIdentity>, CaError> {
        // The enrolled verifying key re-encodes to the exact b64url form the
        // enrollment store holds; sponsor id comes with it (RAE L0).
        match self.enrollment.lookup(agent_id) {
            Some(key) => Ok(Some(AgentIdentity {
                agent_id: agent_id.to_owned(),
                public_key_b64url: chaperone_protocol::encode_signature(&key.to_bytes()),
                sponsor_id: self.enrollment.sponsor_id_of(agent_id).unwrap_or_default(),
            })),
            None => Ok(None),
        }
    }
}
