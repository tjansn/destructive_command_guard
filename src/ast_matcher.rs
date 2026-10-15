//! Default policy for executable heredoc and inline-script source.
//!
//! Source recovery and the configurable AST corpus live in
//! `ast_source_analysis.rs`. This entry point also revalidates Python's
//! temporary-directory producer grants before the evaluator can use them.
//! An unknown or replaced factory keeps the existing recursive-deletion rule.

#[path = "ast_source_analysis.rs"]
mod source_analysis;
#[path = "ast_matcher/tempfile_provenance.rs"]
mod tempfile_provenance;

pub use source_analysis::*;

use crate::heredoc::ScriptLanguage;
use std::ops::Deref;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// The default matcher used by the CLI and hooks, including producer provenance.
/// Explicit `AstMatcher` corpora remain independently configurable as before.
#[derive(Debug, Default)]
pub struct DefaultPolicyMatcher;

/// The entry point used by the evaluator after executable-source extraction.
pub static DEFAULT_MATCHER: LazyLock<DefaultPolicyMatcher> =
    LazyLock::new(DefaultPolicyMatcher::default);

impl Deref for DefaultPolicyMatcher {
    type Target = source_analysis::DefaultPolicyMatcher;

    fn deref(&self) -> &Self::Target {
        &source_analysis::DEFAULT_MATCHER
    }
}

impl DefaultPolicyMatcher {
    /// Match executable source and revalidate its temporary producer exemptions.
    ///
    /// # Errors
    ///
    /// Returns the source matcher's parsing, availability, or timeout error.
    /// An incomplete producer proof instead withholds the optional exemption.
    pub fn find_matches(
        &self,
        code: &str,
        language: ScriptLanguage,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let matches = source_analysis::DEFAULT_MATCHER.find_matches(code, language)?;
        Ok(tempfile_provenance::validate(
            code,
            language,
            matches,
            source_analysis::protected_scan_budget(),
        ))
    }

    /// Match source with an explicit budget. The producer proof uses only the
    /// time remaining after source matching, never an additional time envelope.
    ///
    /// # Errors
    ///
    /// Returns the source matcher's parsing, availability, or timeout error.
    pub fn find_matches_with_timeout(
        &self,
        code: &str,
        language: ScriptLanguage,
        timeout: Duration,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let started = Instant::now();
        let matches =
            source_analysis::DEFAULT_MATCHER.find_matches_with_timeout(code, language, timeout)?;
        Ok(tempfile_provenance::validate(
            code,
            language,
            matches,
            timeout.saturating_sub(started.elapsed()),
        ))
    }

    /// Return the first blocking match from the complete default policy.
    #[must_use]
    pub fn has_blocking_match(&self, code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
        self.find_matches(code, language)
            .ok()?
            .into_iter()
            .find(|hit| hit.severity.blocks_by_default())
    }
}
