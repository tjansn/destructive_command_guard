//! Pattern-based secret redaction for anything dcg persists.
//!
//! dcg writes command text to three places that outlive the hook invocation:
//! the history database, the `[general] log_file`, and the pending-exception
//! store used by allow-once. A blocked command frequently *is* the incident —
//! `curl -H "Authorization: Bearer …"`, a `psql postgres://user:pw@…` URL, an
//! `rm -rf` next to a deploy key — so the command text is exactly where
//! credentials show up.
//!
//! [`redact_secrets`] rewrites recognised credential shapes to bracketed
//! placeholders before any of those writers see the string. It is deliberately
//! conservative: every pattern is anchored on a distinctive prefix, a scheme,
//! or an explicit `key = value` assignment, so ordinary commands pass through
//! untouched. It is a mitigation, not a guarantee — an unrecognised secret
//! shape still reaches storage, which is what `redaction_mode = "full"` is
//! for.
//!
//! Ordering matters: the specific token patterns run before the generic
//! `password=` / `secret=` assignment patterns, and those generic patterns
//! exclude `[` and `]` so they cannot re-redact a placeholder a previous
//! pattern already wrote.

use std::sync::{LazyLock, OnceLock};

use regex::{Regex, RegexSet};

/// Credential shapes recognised by [`redact_secrets`], as
/// `(pattern, replacement)`.
///
/// Replacements are expanded, so `$1` refers to the first capture group; a
/// replacement must never contain a bare `$` otherwise (enforced by a unit
/// test below).
const SECRET_PATTERNS: &[(&str, &str)] = &[
    // ---- Provider API keys -------------------------------------------------
    (r"sk-ant-api[A-Za-z0-9\-_]{20,}", "[ANTHROPIC_KEY]"),
    // OpenAI: sk-…, sk-proj-…, sk-svcacct-… all share the sk- prefix and are
    // long; the length floor keeps this off short `sk-` flag values.
    (r"sk-[A-Za-z0-9\-_]{40,}", "[OPENAI_KEY]"),
    (r"AIza[A-Za-z0-9_\-]{35}", "[GOOGLE_API_KEY]"),
    // Stripe live/test secret and restricted keys.
    (r"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}", "[STRIPE_KEY]"),
    (
        r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
        "[SENDGRID_KEY]",
    ),
    // ---- Cloud provider secrets -------------------------------------------
    (
        r"A(?:KIA|SIA|IDA|ROA|IPA|NPA|NVA)[A-Z0-9]{16}",
        "[AWS_ACCESS_KEY]",
    ),
    (
        r#"(?i)aws_secret_access_key\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s\[\]]+)"#,
        "[AWS_SECRET]",
    ),
    (
        r#"(?i)azure[_\-]?(?:storage|account)[_\-]?key\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s\[\]]+)"#,
        "[AZURE_KEY]",
    ),
    // ---- Forge and registry tokens ----------------------------------------
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "[GITHUB_TOKEN]"),
    (r"github_pat_[A-Za-z0-9_]{22,}", "[GITHUB_TOKEN]"),
    (r"glpat-[A-Za-z0-9\-_]{20,}", "[GITLAB_PAT]"),
    (r"npm_[A-Za-z0-9]{36}", "[NPM_TOKEN]"),
    (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]+", "[PYPI_TOKEN]"),
    (r"dop_v1_[a-f0-9]{64}", "[DIGITALOCEAN_TOKEN]"),
    (r"xox[baprse]-[A-Za-z0-9\-]{10,}", "[SLACK_TOKEN]"),
    (
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
        "[SLACK_WEBHOOK]",
    ),
    // ---- Key material ------------------------------------------------------
    (
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        "[PRIVATE_KEY]",
    ),
    (
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "[PGP_PRIVATE_KEY]",
    ),
    // JWT: header.payload.signature, each segment base64url.
    (
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "[JWT_TOKEN]",
    ),
    // ---- Transport-level credentials --------------------------------------
    // `Authorization: Bearer <token>` / `-H "Authorization: Basic <blob>"`.
    (
        r"(?i)(authorization\s*:\s*)(?:bearer|basic|token)\s+[A-Za-z0-9._\-+/=]+",
        "${1}[AUTH_HEADER]",
    ),
    // Any `scheme://user[:password]@host`, which covers postgres, mysql,
    // mongodb(+srv), redis, amqp, ssh, and the `git clone https://token@host`
    // shape the allow-once documentation describes. The scheme is preserved so
    // the surviving text still identifies the command.
    (
        r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/@]+@",
        "${1}[URL_CREDENTIALS]@",
    ),
    // ---- Generic assignments (last: they must not eat placeholders) -------
    (
        r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s\[\]]{8,})"#,
        "[PASSWORD]",
    ),
    (
        r#"(?i)(?:secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s\[\]]{16,})"#,
        "[SECRET]",
    ),
];

struct SecretPattern {
    source: &'static str,
    replacement: &'static str,
    regex: OnceLock<Option<Regex>>,
}

impl SecretPattern {
    fn compiled(&self) -> Option<&Regex> {
        self.regex
            .get_or_init(|| Regex::new(self.source).ok())
            .as_ref()
    }
}

/// The combined matcher plus lazily compiled capture/replacement matchers.
///
/// A fresh hook process usually redacts one command with no secrets. Building
/// the `RegexSet` already performs the full regex analysis needed to establish
/// that; eagerly compiling every individual `Regex` duplicates cold work.
/// Only a pattern that actually matches needs its capture/replacement matcher.
/// The regex library still determines every candidate, including Unicode case
/// folding and word boundaries; there is no separately maintained text gate.
struct Compiled {
    patterns: Vec<SecretPattern>,
    /// `None` only if `RegexSet` construction itself fails (e.g. the combined
    /// program exceeds the size limit); callers then run every pattern.
    set: Option<RegexSet>,
}

impl Compiled {
    fn new(patterns: &[(&'static str, &'static str)]) -> Self {
        let mut patterns: Vec<SecretPattern> = patterns
            .iter()
            .map(|(source, replacement)| SecretPattern {
                source,
                replacement,
                regex: OnceLock::new(),
            })
            .collect();
        let set = RegexSet::new(patterns.iter().map(|pattern| pattern.source)).ok();
        let set = set.or_else(|| {
            // Preserve the existing fallback exactly: discard patterns whose
            // individual matcher fails, then retry the set over that filtered
            // list. This keeps set indices aligned and retains original-input
            // match selection even when one declaration is malformed. Only a
            // failure of the rebuilt set invokes the ordered per-regex path.
            patterns.retain(|pattern| pattern.compiled().is_some());
            RegexSet::new(patterns.iter().map(|pattern| pattern.source)).ok()
        });
        Self { patterns, set }
    }

    fn redact(&self, command: &str) -> String {
        let Some(set) = self.set.as_ref() else {
            // The set failed to build; fall back to running every pattern.
            return self
                .patterns
                .iter()
                .filter_map(|pattern| pattern.compiled().map(|regex| (regex, pattern.replacement)))
                .fold(command.to_string(), |acc, (regex, replacement)| {
                    regex.replace_all(&acc, replacement).into_owned()
                });
        };

        // One regex-library scan identifies all patterns matching the original
        // input. A non-match compiles no individual capture/replacement regex.
        let matched = set.matches(command);
        if !matched.matched_any() {
            return command.to_string();
        }

        // Indices are ascending, preserving declaration order. As before,
        // only original-input matches participate: a replacement must not
        // introduce a new candidate for a later pattern.
        let mut result = command.to_string();
        for index in &matched {
            if let Some(pattern) = self.patterns.get(index) {
                if let Some(regex) = pattern.compiled() {
                    result = regex.replace_all(&result, pattern.replacement).into_owned();
                }
            }
        }
        result
    }
}

static COMPILED: LazyLock<Compiled> = LazyLock::new(|| Compiled::new(SECRET_PATTERNS));

/// Replace recognised credential shapes in `command` with placeholders.
///
/// Returns the input unchanged when nothing matches. This is a best-effort
/// mitigation over known shapes, not a guarantee that the result is free of
/// secrets.
#[must_use]
pub fn redact_secrets(command: &str) -> String {
    COMPILED.redact(command)
}

#[cfg(test)]
mod tests {
    use super::{Compiled, SECRET_PATTERNS, redact_secrets};

    /// Frozen eager implementation used before #555. Keep the reference's
    /// construction and original-input candidate selection independent of the
    /// lazy implementation so differential tests detect semantic drift.
    struct EagerReference {
        regexes: Vec<(regex::Regex, &'static str)>,
        set: Option<regex::RegexSet>,
    }

    impl EagerReference {
        fn new(patterns: &[(&str, &'static str)]) -> Self {
            let regexes: Vec<_> = patterns
                .iter()
                .filter_map(|(source, replacement)| {
                    regex::Regex::new(source)
                        .ok()
                        .map(|regex| (regex, *replacement))
                })
                .collect();
            let set = regex::RegexSet::new(regexes.iter().map(|(regex, _)| regex.as_str())).ok();
            Self { regexes, set }
        }

        fn redact(&self, command: &str) -> String {
            let Some(set) = self.set.as_ref() else {
                return self.regexes.iter().fold(
                    command.to_string(),
                    |result, (regex, replacement)| {
                        regex.replace_all(&result, *replacement).into_owned()
                    },
                );
            };
            let matched = set.matches(command);
            let mut result = command.to_string();
            for index in &matched {
                if let Some((regex, replacement)) = self.regexes.get(index) {
                    result = regex.replace_all(&result, *replacement).into_owned();
                }
            }
            result
        }
    }

    #[test]
    fn ordinary_commands_do_not_compile_capture_regexes() {
        let compiled = Compiled::new(SECRET_PATTERNS);
        assert!(compiled.set.is_some());
        for command in [
            "",
            "ls -la",
            "git status",
            "python3 <<'PY'\nprint('hello')\nPY",
        ] {
            assert_eq!(compiled.redact(command), command);
        }
        assert!(
            compiled
                .patterns
                .iter()
                .all(|pattern| pattern.regex.get().is_none())
        );

        assert_eq!(compiled.redact("PASSWORD='synthetic'"), "[PASSWORD]");
        let initialized: Vec<_> = compiled
            .patterns
            .iter()
            .filter_map(|pattern| pattern.regex.get().map(|_| pattern.replacement))
            .collect();
        assert_eq!(
            initialized,
            vec!["[PASSWORD]"],
            "only the matching password pattern compiles"
        );
    }

    #[test]
    fn lazy_redaction_matches_eager_reference_for_all_secret_families() {
        let compiled = Compiled::new(SECRET_PATTERNS);
        let reference = EagerReference::new(SECRET_PATTERNS);
        // One synthetic witness per declaration, including capture-preserving
        // replacements and overlaps between provider tokens and assignments.
        let examples = [
            format!("sk-ant-api{}", "A".repeat(48)),
            format!("sk-proj-{}", "aZ09_-".repeat(10)),
            format!("AIza{}", "A".repeat(35)),
            format!("sk_test_{}", "A".repeat(16)),
            format!("SG.{}.{}", "A".repeat(20), "B".repeat(20)),
            format!("AKIA{}", "A".repeat(16)),
            "aws_secret_access_key='synthetic'".to_string(),
            "azure-storage-key='synthetic'".to_string(),
            format!("ghp_{}", "A".repeat(36)),
            format!("github_pat_{}", "A".repeat(22)),
            format!("glpat-{}", "A".repeat(20)),
            format!("npm_{}", "A".repeat(36)),
            "pypi-AgEIcHlwaS5vcmc_SYNTHETIC".to_string(),
            format!("dop_v1_{}", "a".repeat(64)),
            "xoxb-0123456789".to_string(),
            "https://hooks.slack.com/services/SYNTHETIC/EXAMPLE".to_string(),
            "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
            "-----BEGIN PGP PRIVATE KEY BLOCK-----".to_string(),
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl".to_string(),
            "Authorization: Basic dGVzdDp0ZXN0".to_string(),
            "postgres://user:synthetic@db.example/app".to_string(),
            "PASSWORD=correcthorsebattery".to_string(),
            "api_key=abcdefghijklmnop".to_string(),
        ];
        assert_eq!(examples.len(), SECRET_PATTERNS.len());
        let multiline = "print('ordinary data')\n".repeat(300);
        for (index, example) in examples.iter().enumerate() {
            assert!(
                reference.regexes[index].0.is_match(example),
                "missing witness for pattern {index}"
            );
            for command in [
                example.clone(),
                format!("run '{example}' trailing"),
                format!("password=\"{example}\" api_key='{example}'"),
                format!("python3 <<'PY'\n{multiline}print({example:?})\nPY"),
            ] {
                assert_eq!(
                    compiled.redact(&command),
                    reference.redact(&command),
                    "{command}"
                );
            }
        }
        let combined = examples.join("\n");
        assert_eq!(compiled.redact(&combined), reference.redact(&combined));
    }

    #[test]
    fn lazy_redaction_preserves_unicode_folding_boundaries_and_thresholds() {
        let compiled = Compiled::new(SECRET_PATTERNS);
        let reference = EagerReference::new(SECRET_PATTERNS);
        for (command, expected) in [
            ("aws_ſecret_acceſs_\u{212a}ey=synthetic", "[AWS_SECRET]"),
            ("azure_ſtorage_\u{212a}ey='synthetic'", "[AZURE_KEY]"),
            ("paſſword='x'", "[PASSWORD]"),
            ("api_\u{212a}ey=abcdefghijklmnop", "[SECRET]"),
            (
                "\u{212a}://user:synthetic@host",
                "\u{212a}://[URL_CREDENTIALS]@host",
            ),
            ("PASSWORD\u{2003}=\u{2028}'synthetic'", "[PASSWORD]"),
            (
                "AUTHORIZATION\u{2003}:\u{2003}BEARER\u{2003}abc123",
                "AUTHORIZATION\u{2003}:\u{2003}[AUTH_HEADER]",
            ),
        ] {
            assert_eq!(
                reference.redact(command),
                expected,
                "Unicode fixture: {command}"
            );
            assert_eq!(compiled.redact(command), expected, "{command}");
        }

        for length in [
            0, 1, 7, 8, 15, 16, 19, 20, 21, 22, 34, 35, 36, 39, 40, 64, 65,
        ] {
            let value = "a".repeat(length);
            for prefix in ["sk-", "glpat-", "npm_", "api_key=", "password=", "xoxb-"] {
                let command = format!("run {prefix}{value} next");
                assert_eq!(
                    compiled.redact(&command),
                    reference.redact(&command),
                    "{command}"
                );
            }
        }
        for command in [
            "secret=[SECRET] password=[PASSWORD]",
            "PASSWORD='first\nsecond'",
            "PASSWORD='unterminated",
            "💬postgres://user:synthetic@host",
            "λpostgres://user:synthetic@host",
            "[AUTH_HEADER] https://[URL_CREDENTIALS]@host",
        ] {
            assert_eq!(
                compiled.redact(command),
                reference.redact(command),
                "{command}"
            );
        }
    }

    #[test]
    fn malformed_patterns_keep_filtered_indices_and_original_input_selection() {
        const PATTERNS: &[(&str, &str)] = &[
            ("(", "[BROKEN]"),
            ("alpha", "beta"),
            ("beta", "[BETA]"),
            ("[", "[ALSO_BROKEN]"),
        ];
        let compiled = Compiled::new(PATTERNS);
        let reference = EagerReference::new(PATTERNS);
        assert_eq!(compiled.patterns.len(), 2);
        assert!(compiled.set.is_some());
        assert_eq!(compiled.redact("alpha"), "beta");
        for command in ["alpha", "alpha beta", "beta alpha", "ordinary"] {
            assert_eq!(
                compiled.redact(command),
                reference.redact(command),
                "{command}"
            );
        }
    }

    #[test]
    fn unavailable_regex_set_preserves_ordered_fallback() {
        let patterns = [("(", "broken"), ("alpha", "beta"), ("beta", "[BETA]")];
        let mut compiled = Compiled::new(&patterns);
        let mut reference = EagerReference::new(&patterns);
        // Model a combined-program build failure without allocating a huge
        // regex. Both implementations must then run all valid patterns in
        // order, including a later match introduced by a replacement.
        compiled.set = None;
        reference.set = None;
        assert_eq!(compiled.redact("alpha"), "[BETA]");
        for command in ["alpha", "alpha beta", "beta alpha", "ordinary"] {
            assert_eq!(
                compiled.redact(command),
                reference.redact(command),
                "{command}"
            );
        }
    }

    /// Every shipped pattern must compile; `redact_secrets` silently drops the
    /// ones that do not, which would be a silent loss of coverage.
    #[test]
    fn patterns_all_compile() {
        for (pattern, _) in SECRET_PATTERNS {
            assert!(
                regex::Regex::new(pattern).is_ok(),
                "pattern failed to compile: {pattern}"
            );
        }
    }

    /// Replacements are expanded, so a stray `$` would silently swallow the
    /// following characters as a capture-group name.
    #[test]
    fn replacements_use_dollar_only_for_capture_groups() {
        for (_, replacement) in SECRET_PATTERNS {
            for (index, byte) in replacement.bytes().enumerate() {
                if byte == b'$' {
                    assert!(
                        replacement[index..].starts_with("${"),
                        "replacement has a bare $: {replacement}"
                    );
                }
            }
        }
    }

    // Every token below is synthetic and structurally valid only.
    #[test]
    fn redacts_bare_provider_tokens() {
        let command = "deploy AKIAABCDEFGHIJKLMNOP \
             ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \
             sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let redacted = redact_secrets(command);
        assert!(!redacted.contains("AKIAABCDEFGHIJKLMNOP"), "{redacted}");
        assert!(!redacted.contains("ghp_ABCDEFGHIJ"), "{redacted}");
        assert!(!redacted.contains("sk_live_ABCDEF"), "{redacted}");
        assert!(redacted.contains("[AWS_ACCESS_KEY]"), "{redacted}");
        assert!(redacted.contains("[GITHUB_TOKEN]"), "{redacted}");
        assert!(redacted.contains("[STRIPE_KEY]"), "{redacted}");
        assert!(redacted.starts_with("deploy "), "{redacted}");
    }

    #[test]
    fn redacts_url_credentials_but_keeps_the_scheme_and_host() {
        let redacted = redact_secrets(
            "git clone https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@github.com/o/r",
        );
        assert!(!redacted.contains("ghp_ABCDEFGHIJ"), "{redacted}");
        assert!(redacted.contains("https://"), "{redacted}");
        assert!(redacted.contains("@github.com/o/r"), "{redacted}");

        let dsn = redact_secrets("psql postgres://admin:hunter2hunter2@db.internal:5432/app");
        assert!(!dsn.contains("hunter2hunter2"), "{dsn}");
        assert!(!dsn.contains("admin:"), "{dsn}");
        assert!(
            dsn.contains("postgres://[URL_CREDENTIALS]@db.internal:5432/app"),
            "{dsn}"
        );
    }

    #[test]
    fn redacts_authorization_headers_and_assignments() {
        let header = redact_secrets(
            "curl -H 'Authorization: Bearer abc123.def456-ghi789' https://api.example.com",
        );
        assert!(!header.contains("abc123.def456"), "{header}");
        assert!(header.contains("[AUTH_HEADER]"), "{header}");
        assert!(header.contains("https://api.example.com"), "{header}");

        let assignment = redact_secrets("run --env PASSWORD=correcthorsebattery");
        assert!(!assignment.contains("correcthorsebattery"), "{assignment}");
        assert!(assignment.contains("[PASSWORD]"), "{assignment}");
    }

    #[test]
    fn redacts_jwts_and_private_key_headers() {
        let jwt = redact_secrets("auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl next");
        assert!(!jwt.contains("eyJhbGciOiJIUzI1NiJ9."), "{jwt}");
        assert!(jwt.contains("[JWT_TOKEN]"), "{jwt}");

        let key = redact_secrets("echo '-----BEGIN OPENSSH PRIVATE KEY-----' > k");
        assert!(key.contains("[PRIVATE_KEY]"), "{key}");
    }

    /// A placeholder written by an earlier pattern must not be re-matched by a
    /// later generic assignment pattern.
    #[test]
    fn placeholders_are_not_re_redacted() {
        let once = redact_secrets("api_key=sk-ant-apiABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
        let twice = redact_secrets(&once);
        assert_eq!(
            once, twice,
            "redaction is not idempotent: {once} -> {twice}"
        );
        assert!(!once.contains("sk-ant-api"), "{once}");
    }

    /// The overwhelmingly common case: an ordinary command must survive
    /// byte-for-byte.
    #[test]
    fn ordinary_commands_pass_through_unchanged() {
        for command in [
            "rm -rf ./build",
            "git checkout -- src/main.rs",
            "cargo test --workspace -- --nocapture",
            "ssh deploy@example.com 'systemctl restart app'",
            "curl -sSL https://example.com/install.sh | sh",
            "psql -h db.internal -U admin app",
        ] {
            assert_eq!(redact_secrets(command), command, "rewrote: {command}");
        }
    }
}
