//! Shared interpreter argument roles. Classification never runs an interpreter.

use crate::heredoc::ScriptLanguage;

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
