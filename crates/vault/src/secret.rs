//! Secret material under the ephemerality contract (ARCH-SPEC §2.9).
//!
//! [`SecretString`] is the ONLY type through which credential plaintext may
//! travel inside the gateway:
//!
//! - **Hold minimally**: it wraps a `zeroize::Zeroizing` buffer, wiped when
//!   dropped. It is deliberately NOT `Clone` - a second copy is a second
//!   attack surface, and injectors do not need one.
//! - **Never observable by accident**: `Debug` and `Display` print a redacted
//!   placeholder (pinned by test). It does not implement `Serialize`, so no
//!   log/audit/response path can serialize it by mistake.
//! - **Explicit exposure**: reading plaintext goes through
//!   [`SecretString::expose`], a name that reads honestly in review.

use zeroize::{Zeroize, Zeroizing};

/// A credential value held for exactly as long as its single use requires.
pub struct SecretString {
    inner: Zeroizing<String>,
}

impl SecretString {
    /// Wraps raw secret text.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self {
            inner: Zeroizing::new(value),
        }
    }

    /// Explicit, audited read of the plaintext.
    ///
    /// The name is deliberate: every call site says "secret exposed here",
    /// which is what code review should have to approve.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// Length in bytes, WITHOUT exposing content (sanity checks, logs).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Consumes the handle and returns the raw buffer pre-zeroization -
    /// ONLY for sinks that need ownership (e.g. handing bytes to an HTTP
    /// client builder). The sink inherits the scrub obligation.
    #[must_use]
    pub fn into_inner(self) -> Zeroizing<String> {
        self.inner
    }

    /// Consumes the handle and zeroes the buffer immediately (explicit
    /// early scrub on failure paths).
    pub fn wipe(self) {
        let mut inner = self.into_inner();
        inner.as_mut().zeroize();
        // Zeroizing's own Drop runs afterwards; belt and suspenders.
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[secret redacted]")
    }
}

impl std::fmt::Display for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[secret redacted]")
    }
}

// Tests are allowed to panic: a failing assert IS the test result.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    const VALUE: &str = "super-secret-plaintext-do-not-leak";

    #[test]
    fn debug_and_display_never_leak() {
        let s = SecretString::new(VALUE.to_owned());
        let dbg = format!("{s:?}");
        let disp = format!("{s}");
        assert_eq!(dbg, "[secret redacted]");
        assert_eq!(disp, "[secret redacted]");
        assert!(!dbg.contains(VALUE));
        assert!(!disp.contains(VALUE));
    }

    #[test]
    fn wipe_scrubs_before_drop() {
        // We cannot inspect freed memory soundly; instead verify the
        // explicit-wipe path runs and the wrapper still behaves.
        let s = SecretString::new(VALUE.to_owned());
        assert_eq!(s.len(), VALUE.len());
        s.wipe();
    }
}
