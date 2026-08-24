//! Operator-provisioned allowlist: exact commands + pinned argument prefixes.

use serde::Deserialize;

/// Parsed allowlist file.
#[derive(Debug)]
pub struct Allowlist {
    entries: Vec<AllowlistEntry>,
}

/// One pinned entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistEntry {
    /// Exact command path.
    pub command: String,
    /// Required argument PREFIX (the command may receive more arguments
    /// after these, never different ones before).
    #[serde(default)]
    pub args: Vec<String>,
}

impl Allowlist {
    /// Loads and validates the operator TOML.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct File {
            #[serde(default)]
            allow: Vec<AllowlistEntry>,
        }
        let raw = std::fs::read_to_string(path).map_err(|e| format!("allowlist: {e}"))?;
        let file: File = toml::from_str(&raw).map_err(|e| format!("allowlist schema: {e}"))?;
        Ok(Self {
            entries: file.allow,
        })
    }

    /// True only when the command matches exactly AND the provided args
    /// begin with the pinned sequence.
    pub fn permits(&self, command: &str, args: &[String]) -> bool {
        self.entries.iter().any(|e| {
            e.command == command && args.len() >= e.args.len() && args[..e.args.len()] == *e.args
        })
    }
}
