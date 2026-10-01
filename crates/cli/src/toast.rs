//! P1-1 item 2: OS-native toast notification, consumer-side.
//!
//! Lives in `chaperone tail --toast`, not in the gateway: the daemon is the
//! process with no display or session bus (it is deployed headless by
//! design, D8/D32), while the operator running `tail` has one by
//! definition. The feed already carries every fact a notification needs —
//! including `sponsor_id`, the accountable human (P1-1) — and carries no
//! secret material (D35, asserted by `no_secret_leak`), so the toast body
//! inherits both properties by construction.
//!
//! Two halves, deliberately split:
//! - [`toast_for`] is a pure event -> (title, body, urgency) mapper. Pure
//!   means unit-testable headless: CI has no dbus and no display, and a
//!   notifier nobody can test is a notifier nobody trusts.
//! - [`send`] is best-effort delivery via `notify-rust` (dbus/zbus on
//!   Linux, UserNotifications on macOS, WinRT toast on Windows — one
//!   maintained cross-platform crate, as the gap review prescribes). A
//!   delivery failure degrades to a one-line warning on stderr, once: the
//!   terminal render remains the guaranteed surface, the toast is the
//!   bonus. `tail` must never die because no notification daemon answered.

use serde_json::Value;

/// Urgency for the notification daemon (mapped onto platform primitives by
/// `send`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    /// A denial or a confirmation gate: interrupt the human.
    Critical,
    /// A use/teardown fact worth surfacing: normal popup lifetime.
    Normal,
    /// A liveness heartbeat: minimal interruption.
    Low,
}

/// A ready-to-send notification. Fields are plain text; nothing in the feed
/// is secret-shaped (D35), but the mapper still copies only known
/// reference fields — never `outcome` blobs — so a future payload change
/// cannot silently start toasting raw content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    /// One-line title: the decision or event kind.
    pub title: String,
    /// Body: agent · mechanism · target, named by sponsor where present.
    pub body: String,
    /// How hard to interrupt.
    pub urgency: Urgency,
}

/// Maps one feed event to a toast, or `None` for events that should not
/// interrupt (unknown types render in the terminal only).
pub fn toast_for(v: &Value) -> Option<Toast> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("");
    // The accountable human first; fall back to the agent when an event
    // (or a legacy feed line) predates sponsor attribution.
    let sponsor = v
        .get("sponsor_id")
        .and_then(Value::as_str)
        .filter(|x| !x.is_empty());
    let who = match sponsor {
        Some(sp) => format!("{sp} via {}", s("agent_id")),
        None => s("agent_id").to_owned(),
    };
    let place = if s("target_label").is_empty() {
        s("target_uri").to_owned()
    } else {
        format!("{} ({})", s("target_label"), s("target_uri"))
    };
    match s("type") {
        "decision" => {
            let effect = s("effect");
            let outcome = v
                .get("outcome")
                .and_then(|o| o.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let needs_confirm = outcome == "needs_confirmation";
            let title = if effect == "deny" {
                "Chaperone: DENIED".to_owned()
            } else if needs_confirm {
                "Chaperone: awaiting your approval".to_owned()
            } else {
                "Chaperone: allowed".to_owned()
            };
            let mut body = format!("{who} · {} · {place}", s("mechanism"));
            if !outcome.is_empty() {
                body.push_str(&format!(" · {outcome}"));
            }
            Some(Toast {
                title,
                body,
                // Denials and confirmation gates interrupt; allows inform.
                // A needs_confirmation nobody answers is a fail-closed
                // timeout — the one case where the human IS the mechanism,
                // so it earns Critical.
                urgency: if effect == "deny" || needs_confirm {
                    Urgency::Critical
                } else {
                    Urgency::Normal
                },
            })
        }
        "session.summary" => Some(Toast {
            title: "Chaperone: session ended".to_owned(),
            body: format!(
                "{who} · {} · {place} · {} command(s)",
                s("mechanism"),
                num(v, "commands")
            ),
            urgency: Urgency::Normal,
        }),
        "session.heartbeat" => Some(Toast {
            title: "Chaperone: session still open".to_owned(),
            body: format!(
                "{who} · {} · {place} · {} command(s), {}s elapsed",
                s("mechanism"),
                num(v, "commands"),
                num(v, "elapsed_secs")
            ),
            urgency: Urgency::Low,
        }),
        "policy_drift" => Some(Toast {
            title: "Chaperone: POLICY DRIFT — brokering halted".to_owned(),
            body: v
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("policy file changed under a running gateway")
                .to_owned(),
            // The gateway is now halted; this is the loudest thing it can say.
            urgency: Urgency::Critical,
        }),
        // Unknown/legacy types: terminal render only, no interruption.
        _ => None,
    }
}

fn num(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

/// Best-effort delivery. Errors are returned (never panic) so the caller
/// can warn once and keep tailing.
pub fn send(t: &Toast) -> Result<(), String> {
    let urgency = match t.urgency {
        Urgency::Critical => notify_rust::Urgency::Critical,
        Urgency::Normal => notify_rust::Urgency::Normal,
        Urgency::Low => notify_rust::Urgency::Low,
    };
    notify_rust::Notification::new()
        .appname("Chaperone")
        .summary(&t.title)
        .body(&t.body)
        .urgency(urgency)
        .timeout(notify_rust::Timeout::from(
            if matches!(t.urgency, Urgency::Critical) {
                0 // persist until dismissed
            } else {
                8000
            },
        ))
        .show()
        .map(|_handle| ())
        .map_err(|e| format!("toast delivery failed: {e}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use serde_json::json;

    #[test]
    fn deny_is_critical_and_names_the_human() {
        let ev = json!({
            "type": "decision", "effect": "deny",
            "agent_id": "planner-7", "sponsor_id": "human@example.org",
            "mechanism": "http-bearer",
            "target_uri": "https://api.example.com/v1", "target_label": "",
            "outcome": {"status": "denied"},
        });
        let t = toast_for(&ev).unwrap();
        assert_eq!(t.title, "Chaperone: DENIED");
        assert_eq!(t.urgency, Urgency::Critical);
        // The accountable human leads the body; the agent follows.
        assert!(
            t.body.contains("human@example.org via planner-7"),
            "{}",
            t.body
        );
        assert!(t.body.contains("http-bearer"), "{}", t.body);
        assert!(t.body.contains("api.example.com"), "{}", t.body);
    }

    #[test]
    fn needs_confirmation_is_critical() {
        // A confirmation gate nobody answers is a fail-closed timeout: the
        // human IS the mechanism, so it must interrupt.
        let ev = json!({
            "type": "decision", "effect": "needs_confirmation",
            "agent_id": "a", "sponsor_id": "s", "mechanism": "ssh",
            "target_uri": "ssh://h", "target_label": "h",
            "outcome": {"status": "needs_confirmation"},
        });
        let t = toast_for(&ev).unwrap();
        assert_eq!(t.urgency, Urgency::Critical);
        assert!(t.title.contains("approval"), "{t:?}");
        assert!(t.body.contains("h (ssh://h)"), "{t:?}");
    }

    #[test]
    fn allow_is_normal() {
        let ev = json!({
            "type": "decision", "effect": "allow",
            "agent_id": "a", "sponsor_id": "s", "mechanism": "ssh",
            "target_uri": "ssh://h", "target_label": "",
            "outcome": {"status": "session_opened"},
        });
        let t = toast_for(&ev).unwrap();
        assert_eq!(t.urgency, Urgency::Normal);
    }

    #[test]
    fn summary_and_heartbeat_render_counters_only() {
        let sum = json!({
            "type": "session.summary", "agent_id": "a", "sponsor_id": "s",
            "mechanism": "ssh", "target_uri": "ssh://h", "target_label": "h",
            "commands": 42, "bytes_in": 1000, "bytes_out": 2000, "elapsed_secs": 600,
        });
        let t = toast_for(&sum).unwrap();
        assert_eq!(t.title, "Chaperone: session ended");
        assert!(t.body.contains("42 command(s)"), "{}", t.body);
        // Counters and references only — never byte payloads or content.
        assert!(!t.body.contains("1000"), "{}", t.body);

        let hb = json!({
            "type": "session.heartbeat", "agent_id": "a", "sponsor_id": "s",
            "mechanism": "ssh", "target_uri": "ssh://h", "target_label": "",
            "commands": 7, "elapsed_secs": 900,
        });
        let t = toast_for(&hb).unwrap();
        assert_eq!(t.urgency, Urgency::Low);
        assert!(t.body.contains("7 command(s), 900s elapsed"), "{}", t.body);
    }

    #[test]
    fn drift_is_critical() {
        let ev = json!({
            "type": "policy_drift",
            "detail": "content changed (loaded ab, observed cd)",
        });
        let t = toast_for(&ev).unwrap();
        assert_eq!(t.urgency, Urgency::Critical);
        assert!(t.title.contains("halted"), "{t:?}");
        assert!(t.body.contains("content changed"), "{t:?}");
    }

    #[test]
    fn legacy_event_without_sponsor_still_renders() {
        // sponsor_id absent (pre-P1-1 feed line): fall back to the agent.
        let ev = json!({
            "type": "decision", "effect": "allow",
            "agent_id": "old-agent", "mechanism": "http-bearer",
            "target_uri": "https://x/", "target_label": "",
        });
        let t = toast_for(&ev).unwrap();
        assert!(t.body.starts_with("old-agent"), "{}", t.body);
        assert!(!t.body.contains(" via "), "{}", t.body);
    }

    #[test]
    fn unknown_type_gets_no_toast() {
        // Terminal render only; no interruption for types this build predates.
        assert!(toast_for(&json!({"type": "future.event", "x": 1})).is_none());
    }
}
