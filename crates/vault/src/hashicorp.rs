//! HashiCorp Vault KV-v2 provider (`vault://mount/data/path`).
//!
//! First non-local backend behind [`crate::Provider`], proving the scheme
//! dispatch the abstraction promised: migrating from `local://` to Vault is
//! configuration, not agent-visible change (ARCH-SPEC §2.4).
//!
//! v0 scope: KV-v2 secret READS over HTTP(S) with token auth. Dynamic
//! engines (database creds, PKI) plug into the same `mint()` hook and are
//! tracked post-v1 - the trait already carries it.
//!
//! TLS: reqwest with rustls; an https base_url re-originates TLS per call,
//! matching how injectors treat targets.

use crate::{Provider, ResolveError, SecretString};
use std::future::Future;
use std::pin::Pin;

/// KV-v2 reader bound to one Vault instance + mount.
pub struct VaultKv2 {
    endpoint: String,
    mount: String,
    token: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for VaultKv2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKv2")
            .field("endpoint", &self.endpoint)
            .field("mount", &self.mount)
            .finish_non_exhaustive() // never render the token
    }
}

impl VaultKv2 {
    /// Targets `base_url` (e.g. `https://vault.internal:8200`) with the
    /// given KV-v2 mount name and bearer token.
    pub fn new(base_url: &str, mount: &str, token: SecretString) -> Result<Self, String> {
        let base = base_url.trim_end_matches('/');
        if !base.starts_with("http://") && !base.starts_with("https://") {
            return Err("vault base_url must be http(s)://".to_owned());
        }
        let mount = mount.trim_matches('/').to_owned();
        if mount.is_empty() || mount.contains("..") {
            return Err("vault mount must be a non-empty path segment".to_owned());
        }
        Ok(Self {
            endpoint: format!("{base}/v1/{mount}/data"),
            mount,
            token,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| e.to_string())?,
        })
    }

    /// Mount name (observability).
    #[must_use]
    pub fn mount(&self) -> &str {
        &self.mount
    }
}

impl Provider for VaultKv2 {
    fn resolve<'a>(
        &'a self,
        entry: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<SecretString, ResolveError>> + Send + 'a>> {
        Box::pin(async move {
            if entry.is_empty() || entry.contains("..") {
                return Err(ResolveError::EntryNotFound(entry.to_owned()));
            }
            let url = format!("{}/{}", self.endpoint, entry.trim_start_matches('/'));
            let resp = self
                .client
                .get(&url)
                .header("X-Vault-Token", self.token.expose())
                .send()
                .await
                .map_err(|e| ResolveError::Backend(format!("vault unreachable: {e}")))?;

            match resp.status().as_u16() {
                200 => {}
                403 | 401 => {
                    return Err(ResolveError::Backend("vault rejected the token".to_owned()));
                }
                404 => return Err(ResolveError::EntryNotFound(entry.to_owned())),
                code => {
                    return Err(ResolveError::Backend(format!("vault returned {code}")));
                }
            }

            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ResolveError::Backend(format!("vault body: {e}")))?;
            // KV-v2 read shape: {"data":{"data":{"<key>":"<secret>"},...}}
            let data = body
                .get("data")
                .and_then(|d| d.get("data"))
                .and_then(|d| d.as_object())
                .ok_or_else(|| {
                    ResolveError::Backend("vault response missing data.data".to_owned())
                })?;

            // Single-key secrets resolve directly; multi-key secrets accept
            // "path#key" selectors in the cred_ref entry.
            let (path, key_selector) = match entry.split_once('#') {
                Some((p, k)) => (p, Some(k)),
                None => (entry, None),
            };
            let _ = path;

            let value: String = match key_selector {
                Some(key) => data
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        ResolveError::Backend(format!("key {key:?} not present in secret"))
                    })?
                    .to_owned(),
                None => {
                    if data.len() == 1 {
                        data.values()
                            .next()
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| {
                                ResolveError::Backend(
                                    "single-key secret value is not a string".to_owned(),
                                )
                            })?
                            .to_owned()
                    } else {
                        return Err(ResolveError::Backend(format!(
                            "secret has {} keys; select one with path#key",
                            data.len()
                        )));
                    }
                }
            };

            Ok(SecretString::new(value))
        })
    }
}
