//! Shared interpreter argument roles. Classification never runs an interpreter.

use crate::heredoc::ScriptLanguage;

/// Split only a literal leading cd. The caller must still validate the entire
/// remaining command; this function never grants permission for a chain.
pub(crate) fn leading_cd(
    source: &str,
    cwd: &std::path::Path,
    cdpath: Option<&std::ffi::OsStr>,
) -> Option<(std::path::PathBuf, String)> {
    use crate::normalize::{NormalizeTokenKind, tokenize_for_normalization};
    let source = source.trim();
    // The normalization tokenizer and shell_words disagree about comments.
    // Reject even quoted '#' here instead of reviving a commented-out suffix.
    if source.contains('#') {
        return None;
    }
    let tokens = tokenize_for_normalization(source);
    let separator = tokens
        .iter()
        .position(|token| token.kind == NormalizeTokenKind::Separator)?;
    let token = &tokens[separator];
    if &source[token.byte_range.clone()] != "&&" {
        return None;
    }
    let prefix = &source[..token.byte_range.start];
    if prefix.contains(['$', '`', '~', '\n', '\r', '*', '?', '[', '{']) {
        return None;
    }
    let words = shell_words::split(prefix).ok()?;
    let path = match words.as_slice() {
        [cd, path] if cd == "cd" => path,
        [cd, options, path] if cd == "cd" && options == "--" => path,
        _ => return None,
    };
    if path.is_empty() || path.starts_with('-') {
        return None;
    }
    let path = std::path::Path::new(path);
    if !path.is_absolute() && cdpath.is_some_and(|value| !value.is_empty()) {
        return None;
    }
    let target = cwd.join(path).canonicalize().ok()?;
    if !target.is_dir() {
        return None;
    }
    let rest = source[token.byte_range.end..].trim();
    (!rest.is_empty()).then(|| (target, rest.to_owned()))
}

#[derive(Debug)]
pub(crate) struct BoundEnvironment {
    pub values: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
    pub wrapper: Option<(String, std::ffi::OsString)>,
    pub program: String,
    /// Original program/argument text, excluding only the bound prefix.
    pub command: String,
    preload: bool,
}

impl BoundEnvironment {
    pub fn ensure_reviewable(&self) -> Result<(), String> {
        if self.preload {
            Err("inherited preload or command-local startup state cannot be approved by literal-environment review".to_owned())
        } else {
            let stripped = crate::normalize::strip_wrapper_prefixes(&self.command);
            if stripped.wrapper_limit_reached || !stripped.stripped_wrappers.is_empty() {
                return Err("nested environment or execution wrappers cannot be bound for literal-environment review".to_owned());
            }
            Ok(())
        }
    }
}

pub(crate) fn preload_variable(name: &str) -> bool {
    name.starts_with("DYLD_")
        || name.starts_with("LD_")
        || name.starts_with("BASH_FUNC_")
        || matches!(
            name,
            "NODE_OPTIONS"
                | "NODE_PATH"
                | "BASH_ENV"
                | "ENV"
                | "RUBYOPT"
                | "RUBYLIB"
                | "PERL5OPT"
                | "PERL5LIB"
                | "PYTHONPATH"
                | "PYTHONHOME"
                | "ZDOTDIR"
                | "PHPRC"
                | "PHP_INI_SCAN_DIR"
        )
}

fn absolute_search_path(path: &std::ffi::OsStr) -> Result<(), String> {
    // POSIX command data can also be inspected on Windows (e.g. git-bash).
    // Keep slash-rooted POSIX PATH syntax separate from native guard paths.
    if cfg!(windows)
        && path
            .to_str()
            .is_some_and(|value| value.split(':').all(|entry| entry.starts_with('/')))
    {
        return Ok(());
    }
    if path.is_empty() || std::env::split_paths(path).any(|entry| !entry.is_absolute()) {
        return Err(
            "PATH must contain only non-empty absolute directories; desktop review unavailable"
                .to_owned(),
        );
    }
    Ok(())
}

/// Bind literal assignment operands without executing a shell or expanding
/// variables. Unsupported env switches remain unavailable for review.
pub(crate) fn bound_environment(
    source: &str,
    parent: &std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<Option<BoundEnvironment>, String> {
    use crate::normalize::{NormalizeTokenKind, tokenize_for_normalization};
    let tokens = tokenize_for_normalization(source);
    let mut values = parent.clone();
    let mut index = 0;
    let mut bound = false;
    let word = |index: usize| -> Result<(String, &str), String> {
        let token = tokens.get(index).ok_or("environment has no executable")?;
        if token.kind != NormalizeTokenKind::Word {
            return Err("environment executable is not a literal word".to_owned());
        }
        let raw = &source[token.byte_range.clone()];
        let decoded = shell_words::split(raw).map_err(|e| e.to_string())?;
        match decoded.as_slice() {
            [value] => Ok((value.clone(), raw)),
            _ => Err("environment operand is not a literal word".to_owned()),
        }
    };
    let assignment = |value: &str,
                      raw: &str|
     -> Result<Option<(std::ffi::OsString, std::ffi::OsString)>, String> {
        let Some((name, value)) = value.split_once('=') else {
            return Ok(None);
        };
        if name.is_empty()
            || name.starts_with(|ch: char| ch.is_ascii_digit())
            || !name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return Err("invalid literal environment name".to_owned());
        }
        if raw.contains(['$', '`', '~', '\n', '\r', '*', '?', '[', ']', '{', '}']) {
            return Err("environment expansion or substitution cannot be reviewed".to_owned());
        }
        Ok(Some((name.into(), value.into())))
    };
    while let Ok((value, raw)) = word(index) {
        let Some((key, value)) = assignment(&value, raw)? else {
            break;
        };
        values.insert(key, value);
        bound = true;
        index += 1;
    }
    let (outer, _) = word(index)?;
    let mut wrapper = None;
    if outer.rsplit('/').next() == Some("env") {
        wrapper = Some((
            outer,
            values
                .get(std::ffi::OsStr::new("PATH"))
                .cloned()
                .unwrap_or_default(),
        ));
        index += 1;
        if matches!(word(index)?.0.as_str(), "-i" | "--ignore-environment") {
            values.clear();
            bound = true;
            index += 1;
        }
        if word(index)?.0 == "--" {
            index += 1;
        }
        while let Ok((value, raw)) = word(index) {
            let Some((key, value)) = assignment(&value, raw)? else {
                break;
            };
            values.insert(key, value);
            bound = true;
            index += 1;
        }
    }
    if !bound {
        return Ok(None);
    }
    let (program, raw) = word(index)?;
    if program.starts_with('-') || raw.contains(['$', '`', '~', '*', '?', '[', '{']) {
        return Err("environment executable requires a literal path".to_owned());
    }
    if !program.contains('/') && !values.contains_key(std::ffi::OsStr::new("PATH")) {
        return Err(
            "cleared environment requires a literal PATH or absolute executable".to_owned(),
        );
    }
    let preload = [parent, &values].iter().any(|environment| {
        environment
            .iter()
            .any(|(key, value)| !value.is_empty() && preload_variable(&key.to_string_lossy()))
    });
    if let Some(path) = values.get(std::ffi::OsStr::new("PATH")) {
        absolute_search_path(path)?;
    }
    if let Some((wrapper, path)) = &wrapper
        && !wrapper.contains('/')
    {
        absolute_search_path(path)?;
    }
    let command = source[tokens[index].byte_range.start..].to_owned();
    Ok(Some(BoundEnvironment {
        values,
        wrapper,
        program,
        command,
        preload,
    }))
}

#[cfg(test)]
mod literal_environment_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};

    #[test]
    fn leading_cd_is_literal_canonical_and_independent_of_cdpath() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("with space");
        std::fs::create_dir(&child).unwrap();
        let result = leading_cd("cd 'with space' && node --test", temp.path(), None).unwrap();
        assert_eq!(
            result,
            (child.canonicalize().unwrap(), "node --test".to_owned())
        );
        assert!(
            leading_cd(
                "cd 'with space' && node --test",
                temp.path(),
                Some(OsStr::new("/different"))
            )
            .is_none()
        );
        let absolute = format!(
            "cd -- {} && node --test",
            shell_words::quote(child.to_str().unwrap())
        );
        assert!(leading_cd(&absolute, temp.path(), Some(OsStr::new("/different"))).is_some());
        for command in [
            "cd - && node --test",
            "cd $HOME && node --test",
            "cd $(pwd) && node --test",
            "cd .; node --test",
            "cd . || node --test",
            "cd",
            "cd . &&",
            "cd . # && node --test",
            "cd . # comment\n&& node --test",
            "cd . && node --test # comment",
        ] {
            assert!(
                leading_cd(command, temp.path(), None).is_none(),
                "{command}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn clear_environment_binds_only_spelled_out_values() {
        let parent = BTreeMap::from([
            (OsString::from("PATH"), OsString::from("/parent/bin")),
            (OsString::from("SECRET"), OsString::from("not forwarded")),
        ]);
        let bound = bound_environment(
            "env -i HOME='/tmp/with space' PATH=/usr/bin:/bin EMPTY= cargo test",
            &parent,
        )
        .unwrap()
        .unwrap();
        assert_eq!(bound.program, "cargo");
        assert_eq!(bound.command, "cargo test");
        assert_eq!(bound.values.len(), 3);
        assert_eq!(bound.values[OsStr::new("HOME")], "/tmp/with space");
        assert_eq!(bound.values[OsStr::new("PATH")], "/usr/bin:/bin");
        assert_eq!(bound.values[OsStr::new("EMPTY")], "");
        assert_eq!(bound.wrapper, Some(("env".into(), "/parent/bin".into())));
    }

    #[test]
    fn expansions_unsupported_options_and_missing_path_remain_unbound() {
        for command in [
            "env -i HOME=$HOME PATH=/bin cargo test",
            "env -i HOME=$(pwd) PATH=/bin cargo test",
            "env -i HOME=`pwd` PATH=/bin cargo test",
            "env -i HOME=~ PATH=/bin cargo test",
            "env -i HOME=/tmp/* PATH=/bin cargo test",
            "env -i HOME=/tmp cargo test",
            "env -i -u HOME PATH=/bin cargo test",
            "PATH=$PATH cargo test",
        ] {
            assert!(
                bound_environment(command, &BTreeMap::new()).is_err(),
                "{command}"
            );
        }
        let bound = bound_environment("/usr/bin/env -i HOME=/tmp /usr/bin/true", &BTreeMap::new())
            .unwrap()
            .unwrap();
        assert_eq!(bound.program, "/usr/bin/true");
        assert!(
            bound_environment("cargo test", &BTreeMap::new())
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn literal_path_rejects_empty_and_relative_search_entries() {
        let parent = BTreeMap::from([(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))]);
        for path in [
            "",
            ".:/usr/bin",
            ":/usr/bin",
            "bin:/usr/bin",
            "/usr/bin:",
            "/bin::/usr/bin",
        ] {
            for prefix in ["env -i ", ""] {
                let command = format!("{prefix}PATH={path} node scripts/check.js");
                assert!(
                    bound_environment(&command, &parent)
                        .unwrap_err()
                        .contains("absolute directories"),
                    "{command}"
                );
            }
        }
        assert!(
            bound_environment("env -i PATH=/usr/bin:/bin node scripts/check.js", &parent)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn bound_environment_rejects_local_and_inherited_preload_state() {
        for name in [
            "NODE_OPTIONS",
            "NODE_PATH",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "BASH_ENV",
            "PYTHONPATH",
        ] {
            let command = format!("{name}=fixture /usr/bin/true");
            assert!(
                bound_environment(&command, &BTreeMap::new())
                    .unwrap()
                    .unwrap()
                    .ensure_reviewable()
                    .unwrap_err()
                    .contains("preload")
            );
            let parent = BTreeMap::from([(OsString::from(name), OsString::from("fixture"))]);
            assert!(
                bound_environment("/usr/bin/env -i /usr/bin/true", &parent)
                    .unwrap()
                    .unwrap()
                    .ensure_reviewable()
                    .unwrap_err()
                    .contains("preload")
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceRole {
    Executable,
    SyntaxData,
    Startup,
}

#[derive(Debug)]
pub(crate) struct Source {
    pub path: String,
    pub role: SourceRole,
    pub glob: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Invocation {
    pub sources: Vec<Source>,
    pub finite_check: bool,
}

pub(crate) fn literal(raw: &str, glob: bool) -> Result<String, String> {
    if raw.contains(['$', '`', '\n', '\r', '{', '}', '<', '>'])
        || (!glob && raw.contains(['*', '?', '[', ']']))
        || raw.starts_with('~')
    {
        return Err("dynamic source operand requires review".to_owned());
    }
    let values = shell_words::split(raw).map_err(|e| e.to_string())?;
    match values.as_slice() {
        [value] if !value.is_empty() => Ok(value.clone()),
        _ => Err("source operand is not one literal word".to_owned()),
    }
}

pub(crate) fn query_only(source: &str) -> bool {
    shell_words::split(source).is_ok_and(|words| {
        words
            .iter()
            .find(|word| !word.contains('='))
            .is_some_and(|word| word == "command")
            && crate::heredoc::effective_shell_command(&words).is_none()
            && words
                .iter()
                .any(|word| matches!(word.as_str(), "-v" | "-V"))
    })
}

/// Unsupported/dynamic source is the error arm, never an empty source set.
pub(crate) fn classify(
    program: &str,
    args: &[&str],
    language: ScriptLanguage,
) -> Result<Invocation, String> {
    let name = program.rsplit('/').next().unwrap_or(program);
    let node = matches!(name, "node" | "nodejs");
    if matches!(name, "fish" | "pwsh" | "powershell") {
        return Err("unsupported interpreter invocation".to_owned());
    }
    let mut result = Invocation::default();
    let mut syntax = false;
    let mut tests = false;
    let mut inline = false;
    let mut index = 0;
    if name == "deno" {
        match args.first().copied() {
            Some("run") => index += 1,
            Some("eval") => return Ok(result),
            _ => return Err("deno invocation needs explicit run source".to_owned()),
        }
    } else if name == "bun" && args.first() == Some(&"run") {
        index += 1;
    }
    while let Some(raw) = args.get(index) {
        // Globbing is permitted only for the bounded test-source resolver.
        let arg = literal(raw, tests)?;
        index += 1;
        if arg == "--" {
            break;
        }
        if arg == "-" && !tests {
            return Ok(result);
        } // Heredoc/stdin inspection owns this source.
        if arg.starts_with("--watch") || arg == "--inspect" || arg.starts_with("--inspect-") {
            return Err("watch/service mode is not a finite invocation".to_owned());
        }
        if node && arg == "--test" {
            tests = true;
            result.finite_check = true;
            continue;
        }
        if node && matches!(arg.as_str(), "--check" | "-c") {
            syntax = true;
            result.finite_check = true;
            continue;
        }
        if language == ScriptLanguage::Bash && arg.starts_with(['-', '+']) && !arg.starts_with("--")
        {
            if arg.contains(['i', 'l']) {
                return Err("interactive/login shell startup requires review".to_owned());
            }
            if arg.contains('n') {
                syntax = arg.starts_with('-');
                result.finite_check = syntax;
            }
        }
        let inline_option = match language {
            ScriptLanguage::Bash => {
                arg.starts_with('-') && !arg.starts_with("--") && arg.contains('c')
            }
            ScriptLanguage::Python => arg.starts_with("-c"),
            ScriptLanguage::Php => arg.starts_with("-r"),
            ScriptLanguage::Ruby | ScriptLanguage::Perl => {
                arg.starts_with("-e") || arg.starts_with("-E")
            }
            _ => matches!(arg.as_str(), "--eval" | "--print" | "-e" | "-p"),
        };
        if inline_option {
            if syntax || tests {
                return Err("mixed syntax/test/inline modes require review".to_owned());
            }
            inline = true;
            if matches!(
                arg.as_str(),
                "-c" | "-e" | "-E" | "-r" | "-p" | "--eval" | "--print"
            ) || language == ScriptLanguage::Bash
            {
                index += 1;
                if index > args.len() {
                    return Err("inline option has no source".to_owned());
                }
            }
            // Shell/Python/Ruby inline options terminate interpreter parsing;
            // subsequent words are arguments to that source, not source files.
            if !node {
                return Ok(result);
            }
            continue;
        }
        if language == ScriptLanguage::Python && arg == "-m" {
            return Err(
                "Python module execution has no directly inspectable script operand".to_owned(),
            );
        }
        let preload = matches!(arg.as_str(), "--rcfile" | "--init-file")
            || (node && matches!(arg.as_str(), "--require" | "--import" | "-r"));
        let attached = if node {
            arg.strip_prefix("--require=")
                .or_else(|| arg.strip_prefix("--import="))
                .or_else(|| arg.strip_prefix("-r").filter(|s| !s.is_empty()))
        } else {
            None
        };
        let reporter = node && (arg == "--test-reporter" || arg.starts_with("--test-reporter="));
        if preload || attached.is_some() || reporter {
            let attached = attached.or_else(|| arg.strip_prefix("--test-reporter="));
            let path = if let Some(path) = attached {
                path.to_owned()
            } else {
                let value = literal(
                    args.get(index).ok_or("preload option has no source")?,
                    false,
                )?;
                index += 1;
                value
            };
            if reporter && matches!(path.as_str(), "spec" | "tap" | "dot" | "junit" | "lcov") {
                continue;
            }
            result.sources.push(Source {
                path,
                role: SourceRole::Startup,
                glob: false,
            });
            continue;
        }
        if (language == ScriptLanguage::Bash && matches!(arg.as_str(), "-o" | "+o" | "-O" | "+O"))
            || (language == ScriptLanguage::Python && matches!(arg.as_str(), "-W" | "-X"))
            || (node
                && matches!(
                    arg.as_str(),
                    "--test-name-pattern"
                        | "--test-skip-pattern"
                        | "--test-concurrency"
                        | "--test-timeout"
                ))
        {
            index += 1;
            if index > args.len() {
                return Err("option missing its operand".to_owned());
            }
            continue;
        }
        if node
            && [
                "--test-name-pattern=",
                "--test-skip-pattern=",
                "--test-concurrency=",
                "--test-timeout=",
            ]
            .iter()
            .any(|option| arg.starts_with(option))
        {
            continue;
        }
        if arg.starts_with('-') || arg.starts_with('+') {
            if language == ScriptLanguage::Bash
                && arg.starts_with("--")
                && !matches!(arg.as_str(), "--norc" | "--noprofile" | "--posix")
            {
                return Err("unmodeled shell startup option requires review".to_owned());
            }
            if node
                && !matches!(
                    arg.as_str(),
                    "--no-warnings"
                        | "--trace-warnings"
                        | "--test-only"
                        | "--no-addons"
                        | "--no-experimental-strip-types"
                )
            {
                return Err("unmodeled Node startup or runner option requires review".to_owned());
            }
            if matches!(
                language,
                ScriptLanguage::Ruby | ScriptLanguage::Perl | ScriptLanguage::Php
            ) {
                return Err("unmodeled interpreter startup option requires review".to_owned());
            }
            continue;
        }
        index -= 1;
        break;
    }
    if syntax && tests {
        return Err("mixed syntax and test modes require review".to_owned());
    }
    if inline {
        return Ok(result);
    }
    let operands = &args[index..];
    if tests && operands.is_empty() {
        return Err("test runners without explicit files select sources dynamically".to_owned());
    }
    for raw in operands.iter().take(if tests { 32 } else { 1 }) {
        let path = literal(raw, tests)?;
        if path.starts_with('-') {
            return Err("source options after -- require review".to_owned());
        }
        let glob = tests && path.contains(['*', '?', '[']);
        result.sources.push(Source {
            path,
            role: if syntax {
                SourceRole::SyntaxData
            } else {
                SourceRole::Executable
            },
            glob,
        });
    }
    if tests && operands.len() > 32 {
        return Err("test source file limit reached".to_owned());
    }
    Ok(result)
}
