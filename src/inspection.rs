//! Stable inspection outcomes and a bounded, parse-only second reading.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::ast_matcher::{DEFAULT_MATCHER, MatchError, PatternMatch};
use crate::heredoc::ScriptLanguage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Dangerous,
    Dynamic,
    BoundInputs,
    Limit,
    /// No dialog was shown, and retrying the same request cannot show one.
    ReviewNotStarted,
    ReviewDeclined,
    ReviewExpired,
    /// The dialog could not complete: busy, helper unavailable, or reviewed
    /// inputs changed while it was open.
    ReviewUnavailable,
    InternalCommand,
}

impl Outcome {
    /// Presentation categories must not remove a working exception path.
    /// The tar helper gate consumes exact-command grants (covered end to end);
    /// the early script-file gate does not and must never advertise one.
    pub fn supports_command_review(self, pack: Option<&str>, pattern: Option<&str>) -> bool {
        self == Self::Dangerous
            || (self == Self::Dynamic
                && pack == Some("core.filesystem")
                && matches!(
                    pattern,
                    Some("tar-exec-unverified" | "tar-options-unresolved")
                ))
    }

    pub fn rule_remediation(self, pack: Option<&str>, pattern: Option<&str>) -> &'static str {
        if self == Self::Dynamic && self.supports_command_review(pack, pattern) {
            "The helper remains dynamically unresolved. Inspect its resolved executable and inputs before requesting an explicit human exception for this exact command; that exception is not static verification."
        } else {
            self.remediation()
        }
    }

    pub const fn code(self) -> &'static str {
        match self {
            Self::Dangerous => "definite-dangerous-operation",
            Self::Dynamic => "unsupported-dynamic",
            Self::BoundInputs => "bound-input-review",
            Self::Limit => "analysis-limit",
            Self::ReviewNotStarted => "review-not-started",
            Self::ReviewDeclined => "review-declined",
            Self::ReviewExpired => "review-expired",
            Self::ReviewUnavailable => "review-unavailable-or-cancelled",
            Self::InternalCommand => "internal-hook-command",
        }
    }

    pub const fn headline(self) -> &'static str {
        match self {
            Self::Dangerous => "Destructive Command Detected",
            Self::Dynamic => "Inspection Incomplete",
            Self::BoundInputs => "Literal Inputs Need Review",
            Self::Limit => "Analysis Limit Reached",
            Self::ReviewNotStarted => "Review Not Started",
            Self::ReviewDeclined => "Review Declined",
            Self::ReviewExpired => "Review Expired",
            Self::ReviewUnavailable => "Review Not Approved",
            Self::InternalCommand => "Internal Hook Command",
        }
    }

    pub const fn remediation(self) -> &'static str {
        match self {
            Self::Dangerous => {
                "Inspect the reported operation and its targets before requesting human approval."
            }
            Self::Dynamic => {
                "Executable inputs remain unresolved. Use bounded literal inputs, sandbox verification, or exact-version desktop review; command-only codes cannot resolve this boundary."
            }
            Self::BoundInputs => {
                "Literal environment values can be bound for one-request desktop review. Use a hook with desktop review enabled; no reusable trial approval or command-only exception applies."
            }
            Self::Limit => {
                "Static analysis reached a resource limit. A bounded parse-only retry cannot authorize execution; reduce the input or request desktop review."
            }
            Self::ReviewNotStarted => {
                "No review dialog was shown, and retrying or rephrasing this request cannot show one. Follow the next step named in the reason or ask the user to run the command; no approval was recorded."
            }
            Self::ReviewDeclined => {
                "The user declined this request in the desktop dialog. Do not retry or rephrase it; ask the user how to proceed. No approval was recorded."
            }
            Self::ReviewExpired => {
                "The desktop dialog received no decision within 120 seconds. Ask the user before requesting the same review again; no approval was recorded."
            }
            Self::ReviewUnavailable => {
                "The desktop review could not complete: another dialog was open, the Touch ID helper is unavailable (`dcg doctor`), or reviewed inputs changed during the dialog. Resolve that cause before requesting review again; no approval was recorded."
            }
            Self::InternalCommand => {
                "Submit the original finite command to the hook. Only the hook may construct its confined replacement; direct runner requests cannot be approved or learned."
            }
        }
    }
}

/// Classification changes presentation only, never the authorization decision.
pub fn outcome(pack: Option<&str>, pattern: Option<&str>, reason: &str) -> Outcome {
    if pack == Some("dcg.internal") && pattern == Some("confined-runner") {
        return Outcome::InternalCommand;
    }
    for (tag, review) in [
        ("[dcg:review-not-started]", Outcome::ReviewNotStarted),
        ("[dcg:review-declined]", Outcome::ReviewDeclined),
        ("[dcg:review-expired]", Outcome::ReviewExpired),
        (
            "[dcg:review-unavailable-or-cancelled]",
            Outcome::ReviewUnavailable,
        ),
    ] {
        if reason.contains(tag) {
            return review;
        }
    }
    if reason.contains("[dcg:bound-input-review]") {
        return Outcome::BoundInputs;
    }
    if reason.contains("[dcg:analysis-limit]")
        || reason.contains("AST matching error")
        || reason.contains("deadline")
        || reason.contains("inspection byte limit")
        || reason.contains("inspection depth/file limit")
        || reason.contains("file limit reached")
        || reason.contains("enumeration limit reached")
        || reason.contains("input bound")
        || pattern.is_some_and(|p| p.contains("timeout") || p.contains("budget"))
    {
        return Outcome::Limit;
    }
    if reason.contains("[dcg:unsupported-dynamic]")
        || (pack == Some("heredoc.script_files") && pattern == Some("unverified"))
        || pattern.is_some_and(|p| {
            p.contains("unverified") || p.contains("dynamic") || p.contains("incomplete")
        })
    {
        return Outcome::Dynamic;
    }
    Outcome::Dangerous
}

type CachedScan = ([u8; 32], Vec<PatternMatch>);
static SLOW_CACHE: LazyLock<Mutex<VecDeque<CachedScan>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

/// At most one concurrent slow reading, 64 cached bodies, 1 MiB of source and
/// 256 retained matches per entry. Only findings are returned: a clean retry
/// leaves the original timeout in force. No program or interpreter is launched.
pub(crate) fn slow_findings(
    source: &str,
    language: ScriptLanguage,
    policy: &str,
    cwd: Option<&Path>,
    timeout: Duration,
) -> Result<Vec<PatternMatch>, MatchError> {
    let unavailable = || MatchError::Unavailable {
        language,
        detail: "bounded parse-only retry unavailable or found no definite operation".to_owned(),
    };
    if source.len() > 1024 * 1024 || timeout.is_zero() {
        return Err(unavailable());
    }
    let mut hash = Sha256::new();
    for value in [
        source,
        &format!("{language:?}"),
        policy,
        env!("CARGO_PKG_VERSION"),
    ] {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    if let Some(cwd) = cwd {
        hash.update(cwd.as_os_str().as_encoded_bytes());
    }
    // HOME/PATH influence source resolution and protected-path classification.
    for name in [
        "HOME",
        "USERPROFILE",
        "PATH",
        "NODE_PATH",
        "NODE_OPTIONS",
        "BASH_ENV",
        "ENV",
    ] {
        if let Some(value) = std::env::var_os(name) {
            hash.update(value.as_encoded_bytes());
        }
        hash.update([0]);
    }
    let key: [u8; 32] = hash.finalize().into();
    let mut cache = SLOW_CACHE.try_lock().map_err(|_| unavailable())?;
    let findings = if let Some((_, findings)) = cache.iter().find(|(stored, _)| *stored == key) {
        findings.clone()
    } else {
        let findings = DEFAULT_MATCHER.find_matches_with_timeout(
            source,
            language,
            timeout.min(Duration::from_millis(200)),
        )?;
        if findings.len() > 256 {
            return Err(unavailable());
        }
        if cache.len() >= 64 {
            cache.pop_front();
        }
        cache.push_back((key, findings.clone()));
        findings
    };
    if findings.iter().any(|hit| hit.severity.blocks_by_default()) {
        Ok(findings)
    } else {
        Err(unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_reading_can_find_danger_but_never_authorizes_clean_or_oversized_input() {
        let limit = Duration::from_millis(200);
        let danger = "import shutil\nshutil.rmtree('/home/fixture/project')\n";
        assert!(slow_findings(danger, ScriptLanguage::Python, "policy-1", None, limit).is_ok());
        assert!(slow_findings(danger, ScriptLanguage::Python, "policy-1", None, limit).is_ok());
        assert!(
            slow_findings(
                "print('ok')",
                ScriptLanguage::Python,
                "policy-1",
                None,
                limit
            )
            .is_err()
        );
        assert!(
            slow_findings(
                &"x".repeat(1024 * 1024 + 1),
                ScriptLanguage::Python,
                "policy-1",
                None,
                limit
            )
            .is_err()
        );
        assert!(
            slow_findings(
                danger,
                ScriptLanguage::Python,
                "policy-1",
                None,
                Duration::ZERO
            )
            .is_err()
        );
    }

    #[test]
    fn outcomes_have_distinct_codes_and_remediation() {
        for (reason, expected) in [
            ("destructive", Outcome::Dangerous),
            ("[dcg:unsupported-dynamic]", Outcome::Dynamic),
            ("[dcg:bound-input-review]", Outcome::BoundInputs),
            ("[dcg:analysis-limit]", Outcome::Limit),
            ("[dcg:review-not-started]", Outcome::ReviewNotStarted),
            ("[dcg:review-declined]", Outcome::ReviewDeclined),
            ("[dcg:review-expired]", Outcome::ReviewExpired),
            (
                "[dcg:review-unavailable-or-cancelled]",
                Outcome::ReviewUnavailable,
            ),
        ] {
            assert_eq!(outcome(None, None, reason), expected);
            assert!(reason == "destructive" || reason == format!("[dcg:{}]", expected.code()));
            assert!(!expected.code().is_empty());
            assert!(!expected.remediation().is_empty());
        }
        // Every review outcome says no approval was recorded, and none of them
        // tells an agent to simply retry (fork issue #2).
        for review in [
            Outcome::ReviewNotStarted,
            Outcome::ReviewDeclined,
            Outcome::ReviewExpired,
            Outcome::ReviewUnavailable,
        ] {
            let text = review.remediation().to_lowercase();
            assert!(text.contains("no approval was recorded"), "{text}");
            assert!(!text.contains("and retry "), "{text}");
        }
        // Every diagnostic the review code emits maps to its own outcome.
        for failure in [
            crate::desktop_review::ReviewFailure::Busy,
            crate::desktop_review::ReviewFailure::NotShowable,
            crate::desktop_review::ReviewFailure::HelperUnavailable,
            crate::desktop_review::ReviewFailure::Declined,
            crate::desktop_review::ReviewFailure::Expired,
            crate::desktop_review::ReviewFailure::Changed,
        ] {
            let code = outcome(None, None, failure.diagnostic()).code();
            assert!(failure.diagnostic().starts_with(&format!("[dcg:{code}] ")));
        }
        assert!(
            !Outcome::BoundInputs
                .supports_command_review(Some("heredoc.script_files"), Some("unverified"))
        );
        assert_eq!(
            outcome(Some("dcg.internal"), Some("confined-runner"), ""),
            Outcome::InternalCommand
        );
        assert!(!Outcome::InternalCommand.supports_command_review(None, None));
    }
}
