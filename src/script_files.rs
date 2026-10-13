//! Bounded inspection of file-backed programs before command execution.
//!
//! This is a static backstop, not an OS sandbox. Files are read afresh for
//! every request; no filename-only cache can authorize changed contents.
//! Reentrant evaluator calls share limits and detect recursive helper cycles.

use crate::evaluator::{EvaluationDecision, EvaluationResult};
use crate::heredoc::ScriptLanguage;
use crate::normalize::{ShellDialect, strip_wrapper_prefixes, tokenize_for_shell_dialect};
use crate::perf::Deadline;
use ast_grep_core::AstGrep;
use ast_grep_language::SupportLang;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_TOTAL_BYTES: u64 = 1024 * 1024;
const MAX_FILES: usize = 32;
const MAX_DEPTH: usize = 8;

#[derive(Default)]
struct InspectionBudget {
    files: usize,
    bytes: u64,
    active: HashSet<(PathBuf, Option<String>)>,
}

thread_local! {
    static BUDGET: RefCell<Option<InspectionBudget>> = const { RefCell::new(None) };
}

struct InspectionScope(bool);

impl InspectionScope {
    fn enter() -> Self {
        Self(BUDGET.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                false
            } else {
                *slot = Some(InspectionBudget::default());
                true
            }
        }))
    }
}

impl Drop for InspectionScope {
    fn drop(&mut self) {
        if self.0 {
            BUDGET.with(|slot| *slot.borrow_mut() = None);
        }
    }
}

struct FileScope((PathBuf, Option<String>));

impl FileScope {
    fn enter(path: &Path, bytes: u64, selector: Option<&str>) -> Result<Self, String> {
        BUDGET.with(|slot| {
            let mut slot = slot.borrow_mut();
            let budget = slot.as_mut().ok_or("script inspection scope is missing")?;
            let key = (path.to_path_buf(), selector.map(str::to_string));
            if budget.active.contains(&key) {
                return Err(format!("recursive script cycle at {}", path.display()));
            }
            if budget.active.len() >= MAX_DEPTH || budget.files >= MAX_FILES {
                return Err("script inspection depth/file limit reached".to_string());
            }
            if bytes > MAX_FILE_BYTES || budget.bytes.saturating_add(bytes) > MAX_TOTAL_BYTES {
                return Err("script inspection byte limit reached".to_string());
            }
            budget.files += 1;
            budget.bytes += bytes;
            budget.active.insert(key.clone());
            Ok(Self(key))
        })
    }
}

impl Drop for FileScope {
    fn drop(&mut self) {
        BUDGET.with(|slot| {
            if let Some(budget) = slot.borrow_mut().as_mut() {
                budget.active.remove(&self.0);
            }
        });
    }
}

#[derive(Debug)]
struct Reference {
    path: String,
    language: Option<ScriptLanguage>,
    /// Bare sourced names search PATH before the cwd and are ambiguous.
    sourced: bool,
    format: FileFormat,
}

#[derive(Debug)]
enum FileFormat {
    Script,
    SyntaxOnly(String),
    TestGlob(String),
    FiniteScript(String),
    PackageScript(String),
    Makefile,
}

fn unverified(reason: &str) -> EvaluationResult {
    crate::desktop_review::record_incomplete();
    let mut result = EvaluationResult::denied_by_embedded_sink(
        "heredoc.script_files.unverified",
        &format!("Script-file inspection incomplete: {reason}"),
    );
    if let Some(info) = result.pattern_info.as_mut() {
        if reason.contains("[dcg:bound-input-review]") {
            info.explanation = Some(
                crate::inspection::Outcome::BoundInputs
                    .remediation()
                    .to_owned(),
            );
            return result;
        }
        info.explanation = Some(
            "Static inspection could not establish the executable sources. A sandbox trial \
             or desktop review must verify this exact project, command and source version. \
             Enable sandbox trials and use a hook invoked with --desktop-review for \
             inconclusive results; `dcg trial run -- '<command>'` provides a manual sandbox \
             check. Command-only exceptions do not resolve this inspection boundary."
                .to_owned(),
        );
    }
    result
}

/// Inspect every recognized executable file reference. The callback runs the
/// existing evaluator on source text, never executes the inspected program.
pub(crate) fn evaluate(
    command: &str,
    cwd: Option<&Path>,
    dialect: ShellDialect,
    nonlocal: bool,
    deadline: Option<&Deadline>,
    resolve_unverified: bool,
    mut evaluate_source: impl FnMut(&str, &Path, ScriptLanguage) -> EvaluationResult,
) -> Option<EvaluationResult> {
    let _scope = InspectionScope::enter();
    let local_deadline = Deadline::hook_default();
    let deadline = deadline.unwrap_or(&local_deadline);
    if deadline.is_exceeded() {
        return Some(EvaluationResult::indeterminate_due_to_budget());
    }
    if !matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) {
        // POSIX file-resolution evidence must never authorize another shell.
        return Some(unverified(
            "file inspection currently requires a POSIX shell",
        ));
    }
    let (references, review_reason) = match references(command, deadline) {
        Ok(references) => references,
        Err(reason) => return (!resolve_unverified).then(|| unverified(&reason)),
    };
    let mut first_warning = None;
    let mut first_denial = None;
    let mut incomplete = None;
    for reference in references {
        if deadline.is_exceeded() {
            return Some(EvaluationResult::indeterminate_due_to_budget());
        }
        if nonlocal {
            return Some(unverified(
                "a remote/namespace script cannot be verified from local files",
            ));
        }
        let Some(cwd) = cwd.filter(|path| path.is_absolute() && path.is_dir()) else {
            return Some(unverified("the command's execution directory is unknown"));
        };
        let result = inspect_reference(&reference, cwd, &mut evaluate_source);
        match result {
            Ok(Some(ref result))
                if resolve_unverified
                    && result
                        .pattern_info
                        .as_ref()
                        .is_some_and(crate::trial::eligible) => {}
            Ok(Some(result)) if result.decision != EvaluationDecision::Allow => {
                if definite(&result) {
                    first_denial.get_or_insert(result);
                } else {
                    incomplete.get_or_insert(result);
                }
            }
            Ok(Some(result)) if result.effective_mode.is_some() => {
                first_warning.get_or_insert(result);
            }
            Ok(_) => {}
            Err(reason) if !resolve_unverified => {
                incomplete.get_or_insert_with(|| unverified(&reason));
            }
            Err(_) => {}
        }
    }
    if deadline.is_exceeded() {
        Some(EvaluationResult::indeterminate_due_to_budget())
    } else {
        first_denial
            .or(incomplete)
            .or_else(|| {
                review_reason
                    .filter(|_| !resolve_unverified)
                    .map(|reason| unverified(&reason))
            })
            .or(first_warning)
    }
}

fn definite(result: &EvaluationResult) -> bool {
    result.decision != EvaluationDecision::Allow
        && result.pattern_info.as_ref().is_some_and(|info| {
            crate::inspection::outcome(
                info.pack_id.as_deref(),
                info.pattern_name.as_deref(),
                &info.reason,
            ) == crate::inspection::Outcome::Dangerous
        })
}

fn references(
    command: &str,
    deadline: &Deadline,
) -> Result<(Vec<Reference>, Option<String>), String> {
    if command.len() as u64 > MAX_TOTAL_BYTES {
        return Err("command exceeds script inspection's input bound".to_string());
    }
    let ast = AstGrep::new(command, SupportLang::Bash);
    if ast.root().get_inner_node().has_error() {
        return Err("shell source could not be parsed completely".to_string());
    }
    let mut references = Vec::new();
    let mut review_reason = None;
    let environment = std::env::vars_os().collect();
    let mut pending = vec![ast.root()];
    while let Some(node) = pending.pop() {
        if deadline.is_exceeded() {
            return Err("script inspection deadline exceeded".to_string());
        }
        if node.kind().as_ref() == "command" {
            let text = node.text();
            if crate::invocation::query_only(&text) {
                if crate::heredoc::shell_name_overridden(command, "command") {
                    return Err("query builtin may be shadowed by shell state".to_owned());
                }
                // Keep walking: substitutions in a query's arguments execute.
                pending.extend(node.children());
                continue;
            }
            if let Some(bound) = crate::invocation::bound_environment(&text, &environment)? {
                // Inspection must precede the review marker, including in the
                // relaxed pass. Binding a prefix cannot erase a definite sink.
                references.extend(command_references(&bound.command)?);
                for name in ["BASH_ENV", "ENV"] {
                    if let Some(path) = bound
                        .values
                        .get(std::ffi::OsStr::new(name))
                        .filter(|v| !v.is_empty())
                    {
                        references.push(Reference {
                            path: static_word(&shell_words::quote(&path.to_string_lossy()))?,
                            language: Some(ScriptLanguage::Bash),
                            sourced: true,
                            format: FileFormat::Script,
                        });
                    }
                }
                if let Err(reason) = bound.ensure_reviewable() {
                    review_reason = Some(reason);
                } else {
                    review_reason.get_or_insert_with(|| BOUND_REVIEW_REASON.to_owned());
                }
            } else {
                references.extend(command_references(&text)?);
            }
            if references.len() > MAX_FILES {
                return Err("too many executable file references".to_string());
            }
        }
        if node.kind().as_ref() == "variable_assignment" {
            let assignment = node.text();
            if assignment.split_once('=').is_some_and(|(name, _)| {
                matches!(
                    name,
                    "PATH" | "NODE_OPTIONS" | "NODE_PATH" | "LD_PRELOAD" | "LD_LIBRARY_PATH"
                ) || name.starts_with("DYLD_")
            }) {
                if node
                    .parent()
                    .is_none_or(|parent| parent.kind().as_ref() != "command")
                {
                    return Err(
                        "standalone execution environment changes cannot be bound for review"
                            .to_owned(),
                    );
                }
            }
            if let Some((name, value)) = assignment.split_once('=')
                && matches!(name, "BASH_ENV" | "ENV")
            {
                references.push(Reference {
                    path: static_word(value)?,
                    language: Some(ScriptLanguage::Bash),
                    sourced: false,
                    format: FileFormat::Script,
                });
            }
        }
        if node.kind().as_ref() == "file_redirect" {
            let text = node.text();
            // An interpreter fed a regular stdin file has no argv filename.
            // Resolve that source too, never read a pipe/FIFO as guard input.
            let trimmed = text.trim_start_matches('0');
            if let Some(raw_path) = trimmed.strip_prefix('<')
                && !raw_path.starts_with(['<', '&', '>'])
                && let Some(parent) = node.parent()
            {
                let owner = parent.field("body").unwrap_or(parent);
                if owner.kind().as_ref() != "command" {
                    return Err("compound stdin file redirection requires review".to_string());
                }
                let mut synthetic = owner.text().to_string();
                synthetic.push_str(" ./DCG_STDIN_SOURCE");
                if let Some(bound) = crate::invocation::bound_environment(&synthetic, &environment)?
                {
                    synthetic = bound.command;
                }
                for mut reference in command_references(&synthetic)? {
                    if reference.path == "./DCG_STDIN_SOURCE" {
                        reference.path = static_word(raw_path.trim())?;
                        references.push(reference);
                    }
                }
            }
        }
        pending.extend(node.children());
    }
    Ok((references, review_reason))
}

fn static_word(raw: &str) -> Result<String, String> {
    if raw == "[" {
        return Ok(raw.to_string());
    }
    // Refuse expansion rather than substituting the guard process's variables
    // or treating an unresolved name as a harmless absent file. Quoted literal
    // metacharacter filenames can be reviewed explicitly by the operator.
    if raw.contains(['$', '`', '*', '?', '[', '{', '~']) {
        return Err("an executable or script filename depends on shell expansion".to_string());
    }
    let words = shell_words::split(raw).map_err(|error| error.to_string())?;
    match words.as_slice() {
        [word] if !word.is_empty() => Ok(word.clone()),
        _ => Err("a script filename is not one literal shell word".to_string()),
    }
}

fn assignment(raw: &str) -> bool {
    raw.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|character: char| character.is_ascii_digit())
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
    })
}

const BOUND_REVIEW_REASON: &str = "[dcg:bound-input-review] Literal environment assignments require review of this exact invocation; no reusable trial approval will be recorded.";

fn command_references(source: &str) -> Result<Vec<Reference>, String> {
    // env's assignment operands are removed by the shared wrapper normalizer.
    // Preserve shell startup sources before normalizing those operands away.
    let words = shell_words::split(source).unwrap_or_default();
    let is_env = words
        .first()
        .is_some_and(|word| word.rsplit('/').next() == Some("env"));
    if is_env
        && words.iter().any(|word| {
            word.split_once('=').is_some_and(|(name, _)| {
                matches!(
                    name,
                    "PATH" | "NODE_OPTIONS" | "NODE_PATH" | "LD_PRELOAD" | "LD_LIBRARY_PATH"
                ) || name.starts_with("DYLD_")
            })
        })
    {
        return Err(
            "execution environment inside an unsupported wrapper cannot be bound for review"
                .to_owned(),
        );
    }
    let startup: Vec<_> = words
        .iter()
        .filter(|_| is_env)
        .filter_map(|word| {
            word.split_once('=').and_then(|(name, value)| {
                matches!(name, "BASH_ENV" | "ENV").then(|| value.to_string())
            })
        })
        .collect();
    let mut references = executable_references(source)?;
    for value in startup {
        // Assignment expansion and bare startup paths cannot be resolved
        // using the guard process's environment or PATH.
        references.push(Reference {
            path: static_word(&shell_words::quote(&value))?,
            language: Some(ScriptLanguage::Bash),
            sourced: true,
            format: FileFormat::Script,
        });
    }
    Ok(references)
}

fn executable_references(source: &str) -> Result<Vec<Reference>, String> {
    let stripped = strip_wrapper_prefixes(source);
    if stripped.wrapper_limit_reached {
        return Err("command wrapper inspection limit reached".to_string());
    }
    let source = stripped.normalized.as_ref();
    let tokens = tokenize_for_shell_dialect(source, ShellDialect::Posix);
    let argv = crate::heredoc::local_command_argv(source, &tokens, 0)
        .ok_or("cannot extract executable argv")?;
    let mut words = argv
        .iter()
        .filter_map(|token| token.text(source))
        .peekable();
    while words.peek().is_some_and(|word| assignment(word)) {
        words.next();
    }
    let Some(raw_program) = words.next() else {
        return Ok(Vec::new());
    };
    let mut program = static_word(raw_program)?;
    let mut args: Vec<&str> = words.collect();
    // The shared normalizer handles sudo/env/command. These additional common
    // launchers also execute the following argv without interpreting it.
    for _ in 0..MAX_DEPTH {
        let name = program.rsplit('/').next().unwrap_or(&program);
        let consumed = match name {
            "uv" | "poetry" | "pipenv" if args.first() == Some(&"run") => 1,
            "exec" if args.first() == Some(&"-a") => 2,
            "exec" if matches!(args.first(), Some(&"-c" | &"-l")) => 1,
            "exec" | "builtin" | "nohup" | "setsid"
                if args
                    .first()
                    .is_some_and(|arg| !arg.starts_with('-') || *arg == "--") =>
            {
                usize::from(args.first() == Some(&"--"))
            }
            "timeout" | "gtimeout" if args.first().is_some_and(|arg| !arg.starts_with('-')) => 1,
            "nice" if args.first() == Some(&"-n") => 2,
            "exec" | "builtin" | "nohup" | "setsid" | "timeout" | "gtimeout" | "nice" => {
                return Err("launcher options require explicit review".to_string());
            }
            _ => break,
        };
        program = static_word(args.get(consumed).ok_or("launcher has no executable")?)?;
        args.drain(..=consumed);
    }
    let name = program.rsplit('/').next().unwrap_or(&program);
    if matches!(
        name,
        "env"
            | "sudo"
            | "command"
            | "exec"
            | "builtin"
            | "timeout"
            | "gtimeout"
            | "nice"
            | "nohup"
            | "setsid"
    ) {
        return Err("unresolved command wrapper requires review".to_string());
    }
    if matches!(name, "uv" | "poetry" | "pipenv") && args.first() == Some(&"run") {
        return Err("environment launcher could not be resolved".to_string());
    }
    if matches!(name, "source" | ".") {
        let path = static_word(args.first().ok_or("source has no filename")?)?;
        return Ok(vec![Reference {
            path,
            language: Some(ScriptLanguage::Bash),
            sourced: true,
            format: FileFormat::Script,
        }]);
    }
    if matches!(name, "npm" | "pnpm" | "yarn" | "npx") {
        return package_reference(name, &args);
    }
    if matches!(name, "make" | "gmake") {
        return make_reference(&args);
    }
    if name == "bun" && args.first() == Some(&"run") {
        let task = static_word(args.get(1).ok_or("bun run has no script")?)?;
        if !task.contains('/') && script_extension(&task).is_none() {
            return package_reference("npm", &["run", &task]);
        }
    }
    if name == "go" && args.first() == Some(&"run") {
        let mut references = Vec::new();
        for raw in args.iter().skip(1) {
            let path = static_word(raw)?;
            if path.starts_with('-') {
                return Err("go run options require review".to_string());
            }
            if Path::new(&path)
                .extension()
                .is_none_or(|extension| extension != "go")
            {
                break;
            }
            references.push(Reference {
                path,
                language: Some(ScriptLanguage::Go),
                sourced: false,
                format: FileFormat::Script,
            });
        }
        if references.is_empty() {
            return Err("go run requires explicit local source files".to_string());
        }
        return Ok(references);
    }
    let language = if matches!(name, "tsx" | "ts-node") {
        ScriptLanguage::TypeScript
    } else {
        ScriptLanguage::from_command(name)
    };
    if language != ScriptLanguage::Unknown && name != "go" {
        return interpreter_references(&program, &args, language);
    }
    if program.contains('/') || script_extension(&program).is_some() {
        return Ok(vec![Reference {
            sourced: !program.contains('/'),
            path: program,
            language: None,
            format: FileFormat::Script,
        }]);
    }
    Ok(Vec::new())
}

fn interpreter_references(
    program: &str,
    args: &[&str],
    language: ScriptLanguage,
) -> Result<Vec<Reference>, String> {
    let invocation = crate::invocation::classify(program, args, language)?;
    Ok(invocation
        .sources
        .into_iter()
        .map(|source| Reference {
            path: source.path,
            language: Some(language),
            sourced: source.role == crate::invocation::SourceRole::Startup,
            format: if source.role == crate::invocation::SourceRole::SyntaxData {
                FileFormat::SyntaxOnly(program.to_owned())
            } else if source.glob {
                FileFormat::TestGlob(program.to_owned())
            } else if invocation.finite_check {
                FileFormat::FiniteScript(program.to_owned())
            } else {
                FileFormat::Script
            },
        })
        .collect())
}

fn package_reference(name: &str, args: &[&str]) -> Result<Vec<Reference>, String> {
    if name == "npx" {
        return Err("npx resolves executable code dynamically; review is required".to_string());
    }
    let mut index = 0;
    while args
        .get(index)
        .is_some_and(|arg| matches!(*arg, "-s" | "--silent" | "--if-present"))
    {
        index += 1;
    }
    let Some(raw_action) = args.get(index) else {
        return Ok(Vec::new());
    };
    let action = static_word(raw_action)?;
    let task = match action.as_str() {
        "run" | "run-script" => static_word(
            args.get(index + 1)
                .ok_or("package script name is missing")?,
        )?,
        "test" | "start" | "stop" | "restart" => action,
        "exec" | "dlx" => return Err("dynamic package executables require review".to_string()),
        action if action.starts_with('-') => {
            return Err(
                "package directory/workspace options require review; use an explicit cd"
                    .to_string(),
            );
        }
        "t" | "tst" => "test".to_string(),
        _ if matches!(name, "yarn" | "pnpm") => action,
        _ => return Ok(Vec::new()),
    };
    Ok(vec![Reference {
        path: "package.json".to_string(),
        language: Some(ScriptLanguage::Bash),
        sourced: false,
        format: FileFormat::PackageScript(task),
    }])
}

fn make_reference(args: &[&str]) -> Result<Vec<Reference>, String> {
    let mut path = String::new();
    let mut index = 0;
    while let Some(raw) = args.get(index) {
        let arg = static_word(raw)?;
        index += 1;
        if matches!(arg.as_str(), "-f" | "--file" | "--makefile") {
            if !path.is_empty() {
                return Err("multiple Makefiles require review".to_string());
            }
            path = static_word(args.get(index).ok_or("Makefile option has no path")?)?;
            index += 1;
        } else if arg.starts_with('-') {
            return Err("Make options require review; use a literal Makefile and cwd".to_string());
        }
    }
    Ok(vec![Reference {
        path,
        language: Some(ScriptLanguage::Bash),
        sourced: false,
        format: FileFormat::Makefile,
    }])
}

fn script_extension(path: &str) -> Option<ScriptLanguage> {
    match Path::new(path).extension()?.to_str()? {
        "sh" | "bash" | "zsh" | "dash" | "ksh" => Some(ScriptLanguage::Bash),
        "py" | "pyw" => Some(ScriptLanguage::Python),
        "js" | "mjs" | "cjs" => Some(ScriptLanguage::JavaScript),
        "ts" | "mts" | "cts" => Some(ScriptLanguage::TypeScript),
        "rb" => Some(ScriptLanguage::Ruby),
        "pl" => Some(ScriptLanguage::Perl),
        "php" => Some(ScriptLanguage::Php),
        "fish" | "ps1" | "cmd" | "bat" => Some(ScriptLanguage::Unknown),
        _ => None,
    }
}

fn inspect_reference(
    reference: &Reference,
    cwd: &Path,
    evaluate_source: &mut impl FnMut(&str, &Path, ScriptLanguage) -> EvaluationResult,
) -> Result<Option<EvaluationResult>, String> {
    if let FileFormat::TestGlob(program) = &reference.format {
        verify_syntax_interpreter(program, cwd)?;
        let mut result = None;
        let mut incomplete = None;
        for path in test_glob(&reference.path, cwd)? {
            let item = Reference {
                path,
                language: reference.language,
                sourced: false,
                format: FileFormat::Script,
            };
            match inspect_reference(&item, cwd, evaluate_source) {
                Ok(Some(found)) if definite(&found) => {
                    result.get_or_insert(found);
                }
                Ok(Some(found)) if found.decision != EvaluationDecision::Allow => {
                    incomplete.get_or_insert(found);
                }
                Err(reason) => {
                    incomplete.get_or_insert_with(|| unverified(&reason));
                }
                _ => {}
            }
        }
        return Ok(result.or(incomplete));
    }
    if let FileFormat::SyntaxOnly(program) = &reference.format {
        verify_syntax_interpreter(program, cwd)?;
        return Ok(None);
    }
    if let FileFormat::FiniteScript(program) = &reference.format {
        verify_syntax_interpreter(program, cwd)?;
    }
    let default_makefile =
        if matches!(reference.format, FileFormat::Makefile) && reference.path.is_empty() {
            ["GNUmakefile", "makefile", "Makefile"]
                .into_iter()
                .find(|name| cwd.join(name).exists())
                .ok_or("no inspectable Makefile")?
        } else {
            &reference.path
        };
    let path = Path::new(default_makefile);
    if reference.sourced && !reference.path.contains('/') {
        return Err(
            "bare sourced/preloaded filenames have ambiguous search paths; use an explicit path"
                .to_string(),
        );
    }
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    crate::desktop_review::record_source_path(&path);
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if fs::symlink_metadata(&prefix)
            .map_err(|error| format!("{}: {error}", prefix.display()))?
            .file_type()
            .is_symlink()
        {
            return Err(format!("script path {} contains a symlink", path.display()));
        }
    }
    let path = fs::canonicalize(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file() {
        return Err("script operand is not a regular file".to_string());
    }
    let mut magic = [0u8; 4];
    let length = file.read(&mut magic).map_err(|error| error.to_string())?;
    if reference.language.is_none() && native_binary(&magic) {
        return Ok(None); // Native machine code is outside a script guard's model.
    }
    let selector = match &reference.format {
        FileFormat::PackageScript(task) => Some(task.as_str()),
        _ => None,
    };
    let _file_scope = FileScope::enter(&path, before.len(), selector)?;
    let mut bytes = magic[..length].to_vec();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("script grew beyond the inspection bound".to_string());
    }
    verify_unchanged(&path, &before)?;
    let content = String::from_utf8(bytes).map_err(|_| "script is not UTF-8".to_string())?;
    let language = reference.language.unwrap_or_else(|| {
        if content.starts_with("#!") {
            ScriptLanguage::from_shebang(&content).unwrap_or(ScriptLanguage::Unknown)
        } else {
            script_extension(&reference.path).unwrap_or(ScriptLanguage::Bash)
        }
    });
    if language == ScriptLanguage::Unknown {
        return Err("script language is unsupported".to_string());
    }
    crate::desktop_review::record_script(&path, &content, cwd, language);
    let sources = match &reference.format {
        FileFormat::Script | FileFormat::FiniteScript(_) => vec![content],
        FileFormat::SyntaxOnly(_) | FileFormat::TestGlob(_) => {
            unreachable!("syntax operands were handled before source inspection")
        }
        FileFormat::PackageScript(task) => package_source(&content, task)?,
        FileFormat::Makefile => make_source(&content)?,
    };
    let grammar = match language {
        ScriptLanguage::Bash => Some(SupportLang::Bash),
        ScriptLanguage::Python => Some(SupportLang::Python),
        ScriptLanguage::JavaScript => Some(SupportLang::JavaScript),
        ScriptLanguage::TypeScript => Some(SupportLang::TypeScript),
        ScriptLanguage::Ruby => Some(SupportLang::Ruby),
        ScriptLanguage::Go => Some(SupportLang::Go),
        ScriptLanguage::Php => Some(SupportLang::Php),
        _ => None,
    };
    let mut result = EvaluationResult::allowed();
    for source in sources {
        if grammar.is_some_and(|grammar| {
            AstGrep::new(&source, grammar)
                .root()
                .get_inner_node()
                .has_error()
        }) {
            return Err("script source could not be parsed completely".to_string());
        }
        let candidate = evaluate_source(&source, cwd, language);
        if candidate.decision != EvaluationDecision::Allow {
            if result.decision == EvaluationDecision::Allow
                || (!definite(&result) && definite(&candidate))
            {
                result = candidate;
            }
        } else if candidate.effective_mode.is_some() && result.decision == EvaluationDecision::Allow
        {
            result = candidate;
        }
        if matches!(
            language,
            ScriptLanguage::JavaScript | ScriptLanguage::TypeScript
        ) && !definite(&result)
        {
            match inspect_js_inputs(
                &source,
                path.parent().unwrap_or(cwd),
                cwd,
                language,
                evaluate_source,
            ) {
                Some(found) if result.decision == EvaluationDecision::Allow || definite(&found) => {
                    result = found;
                }
                _ => {}
            }
        }
    }
    verify_unchanged(&path, &before)?;
    if let Some(info) = result.pattern_info.as_mut() {
        info.reason = format!("In script {}: {}", path.display(), info.reason);
        // Nested source offsets never index the outer command string.
        info.matched_span = None;
        info.matched_text_preview = None;
    }
    Ok(Some(result))
}

/// Expand a finite, local pattern without following directory symlinks or
/// letting an unbounded directory enumeration consume the inspection budget.
fn test_glob(pattern: &str, cwd: &Path) -> Result<Vec<String>, String> {
    if Path::new(pattern).is_absolute() || pattern.contains("**") {
        return Err("test globs must be finite local paths without **".to_owned());
    }
    let components: Vec<_> = pattern.split('/').filter(|p| *p != ".").collect();
    if components.len() > MAX_DEPTH || components.iter().any(|p| matches!(*p, ".." | "")) {
        return Err("test glob path/depth is unsupported".to_owned());
    }
    let mut paths = vec![cwd.to_path_buf()];
    let mut visited = 0;
    for component in components {
        let matcher = glob::Pattern::new(component).map_err(|e| e.to_string())?;
        let mut next = Vec::new();
        for parent in paths {
            for entry in fs::read_dir(&parent).map_err(|e| e.to_string())? {
                visited += 1;
                if visited > 1024 {
                    return Err("test glob enumeration limit reached".to_owned());
                }
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name();
                let name = name.to_str().ok_or("non-UTF-8 test glob entry")?;
                if matcher.matches_with(
                    name,
                    glob::MatchOptions {
                        require_literal_leading_dot: true,
                        ..glob::MatchOptions::new()
                    },
                ) {
                    if entry.file_type().map_err(|e| e.to_string())?.is_symlink() {
                        return Err("test glob contains symlink".to_owned());
                    }
                    next.push(entry.path());
                    if next.len() > MAX_FILES {
                        return Err("test source file limit reached".to_owned());
                    }
                }
            }
        }
        paths = next;
    }
    if paths.is_empty() {
        return Err("test glob matched no files".to_owned());
    }
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            p.into_os_string()
                .into_string()
                .map_err(|_| "non-UTF-8 test source".to_owned())
        })
        .collect()
}

fn js_literal(source: &str) -> Result<String, String> {
    let source = source.trim();
    if source.len() >= 2
        && source.starts_with(['\'', '"'])
        && source.ends_with(source.chars().next().unwrap())
        && !source[1..source.len() - 1].contains(['\\', '\n', '\r'])
    {
        Ok(source[1..source.len() - 1].to_owned())
    } else {
        Err("computed or escaped JavaScript input requires review".to_owned())
    }
}

fn builtin_module(name: &str) -> bool {
    // Explicit names only: an arbitrary `node:` URL is not evidence of a
    // supported builtin. Unknown/bare package imports remain unresolved.
    matches!(
        name.strip_prefix("node:").unwrap_or(name),
        "assert"
            | "assert/strict"
            | "async_hooks"
            | "buffer"
            | "child_process"
            | "cluster"
            | "console"
            | "constants"
            | "crypto"
            | "dgram"
            | "diagnostics_channel"
            | "dns"
            | "dns/promises"
            | "events"
            | "fs"
            | "fs/promises"
            | "http"
            | "http2"
            | "https"
            | "module"
            | "net"
            | "os"
            | "path"
            | "path/posix"
            | "path/win32"
            | "perf_hooks"
            | "process"
            | "punycode"
            | "querystring"
            | "readline"
            | "readline/promises"
            | "repl"
            | "stream"
            | "stream/promises"
            | "stream/web"
            | "string_decoder"
            | "sys"
            | "test"
            | "test/reporters"
            | "timers"
            | "timers/promises"
            | "tls"
            | "trace_events"
            | "tty"
            | "url"
            | "util"
            | "util/types"
            | "v8"
            | "vm"
            | "wasi"
            | "worker_threads"
            | "zlib"
    )
}

fn inspect_js_inputs(
    source: &str,
    source_dir: &Path,
    cwd: &Path,
    language: ScriptLanguage,
    evaluate_source: &mut impl FnMut(&str, &Path, ScriptLanguage) -> EvaluationResult,
) -> Option<EvaluationResult> {
    let ast = AstGrep::new(
        source,
        if language == ScriptLanguage::TypeScript {
            SupportLang::TypeScript
        } else {
            SupportLang::JavaScript
        },
    );
    let mut pending = vec![ast.root()];
    let mut imports = Vec::new();
    let mut children = Vec::new();
    let mut incomplete = None;
    while let Some(node) = pending.pop() {
        let kind = node.kind();
        if matches!(kind.as_ref(), "import_statement" | "export_statement")
            && let Some(value) = node.field("source")
        {
            imports.push(js_literal(&value.text()));
        }
        if kind.as_ref() == "call_expression"
            && let (Some(function), Some(args)) = (node.field("function"), node.field("arguments"))
        {
            let function = function.text();
            let name = function.rsplit('.').next().unwrap_or(&function);
            let args: Vec<_> = args
                .children()
                .filter(|c| !matches!(c.kind().as_ref(), "(" | ")" | "," | "comment"))
                .collect();
            if matches!(function.as_ref(), "require" | "import") {
                imports.push(if args.len() == 1 {
                    js_literal(&args[0].text())
                } else {
                    Err("unresolved import arguments".to_owned())
                });
            } else if matches!(
                name,
                "exec" | "execSync" | "execFile" | "execFileSync" | "spawn" | "spawnSync" | "fork"
            ) {
                let child = (|| {
                    let program = js_literal(&args.first().ok_or("child has no command")?.text())?;
                    if matches!(name, "exec" | "execSync") {
                        if args.len() != 1 {
                            return Err("child options/callback require review".to_owned());
                        }
                        return Ok(program);
                    }
                    if args.len() != 2 || args[1].kind().as_ref() != "array" {
                        return Err("child argv/options are unresolved".to_owned());
                    }
                    let mut words = vec![program];
                    for arg in args[1]
                        .children()
                        .filter(|c| !matches!(c.kind().as_ref(), "[" | "]" | "," | "comment"))
                    {
                        words.push(js_literal(&arg.text())?);
                    }
                    if name == "fork" {
                        words.insert(0, "node".to_owned());
                    }
                    Ok(shell_words::join(words))
                })();
                children.push(child);
            }
        }
        pending.extend(node.children());
    }
    let mut result = None;
    for import in imports {
        let found = (|| {
            let import = import?;
            if builtin_module(&import) {
                return Ok(None);
            }
            if !import.starts_with("./") && !import.starts_with("../") {
                return Err("external or unresolved module source requires review".to_owned());
            }
            if !matches!(
                script_extension(&import),
                Some(ScriptLanguage::JavaScript | ScriptLanguage::TypeScript)
            ) {
                return Err("module extension/resolution requires review".to_owned());
            }
            let path = source_dir.join(&import);
            let item = Reference {
                path: path.to_str().ok_or("non-UTF-8 module path")?.to_owned(),
                language: script_extension(&import),
                sourced: false,
                format: FileFormat::Script,
            };
            inspect_reference(&item, cwd, evaluate_source)
        })();
        match found {
            Ok(Some(found)) if definite(&found) => {
                result.get_or_insert(found);
            }
            Ok(Some(found)) if found.decision != EvaluationDecision::Allow => {
                incomplete.get_or_insert(found);
            }
            Err(reason) => {
                incomplete.get_or_insert_with(|| unverified(&reason));
            }
            _ => {}
        }
    }
    for child in children {
        match child {
            Ok(command) => {
                let found = evaluate_source(&command, cwd, ScriptLanguage::Bash);
                if definite(&found) {
                    result.get_or_insert(found);
                } else if found.decision != EvaluationDecision::Allow {
                    incomplete.get_or_insert(found);
                }
            }
            Err(reason) => {
                incomplete.get_or_insert_with(|| unverified(&reason));
            }
        }
    }
    result.or(incomplete)
}

fn verify_syntax_interpreter(program: &str, cwd: &Path) -> Result<(), String> {
    if std::env::vars_os().any(|(key, value)| {
        !value.is_empty() && {
            let key = key.to_string_lossy();
            matches!(
                key.as_ref(),
                "NODE_OPTIONS" | "BASH_ENV" | "ENV" | "ZDOTDIR" | "LD_PRELOAD" | "LD_LIBRARY_PATH"
            ) || key.starts_with("DYLD_")
                || key.starts_with("BASH_FUNC_")
        }
    }) {
        return Err("syntax-only invocation has unverified startup/preload context".to_owned());
    }
    let path = if program.contains('/') {
        cwd.join(program)
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join(program))
            .find(|path| path.is_file())
            .ok_or("syntax interpreter cannot be resolved")?
    };
    let real = path
        .canonicalize()
        .map_err(|_| "syntax interpreter cannot be resolved")?;
    let name = program.rsplit('/').next().unwrap_or(program);
    let system = ["/bin", "/usr/bin"].iter().any(|base| {
        Path::new(base)
            .join(name)
            .canonicalize()
            .is_ok_and(|p| p == real)
    });
    let node = matches!(name, "node" | "nodejs")
        && ["/opt/homebrew/Cellar", "/usr/local/Cellar"]
            .iter()
            .any(|root| {
                real.strip_prefix(root).is_ok_and(|p| {
                    p.components().next().is_some_and(|c| {
                        let name = c.as_os_str().to_string_lossy();
                        name == "node" || name.starts_with("node@")
                    })
                })
            });
    if !system && !node {
        return Err("syntax interpreter identity is not a trusted system executable".to_owned());
    }
    let mut magic = [0; 4];
    std::fs::File::open(real)
        .and_then(|mut file| file.read_exact(&mut magic))
        .map_err(|_| "syntax interpreter cannot be read")?;
    if !native_binary(&magic) {
        return Err("syntax interpreter is a wrapper, not a native executable".to_owned());
    }
    Ok(())
}

fn verify_unchanged(path: &Path, before: &fs::Metadata) -> Result<(), String> {
    let after = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !after.is_file()
        || after.file_type().is_symlink()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err("script changed during inspection".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err("script was replaced during inspection".to_string());
        }
    }
    Ok(())
}

fn package_source(content: &str, task: &str) -> Result<Vec<String>, String> {
    let package: serde_json::Value =
        serde_json::from_str(content).map_err(|error| format!("invalid package.json: {error}"))?;
    let scripts = package
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .ok_or("package has no scripts object")?;
    if !scripts.get(task).is_some_and(serde_json::Value::is_string) {
        return Err(format!("package script {task} is not defined"));
    }
    let names = [
        format!("pre{task}"),
        task.to_string(),
        format!("post{task}"),
    ];
    // Reuse scan mode's structural extractor, with no keyword filter: helper
    // launchers without destructive words must still reach file inspection.
    let extracted = crate::scan::extract_package_json_from_str("package.json", content, &[]);
    let mut sources = Vec::new();
    for name in names {
        for command in &extracted {
            if command
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata["script_name"].as_str() == Some(&name))
            {
                // Lifecycle hooks run in separate shells. A pre-hook's cd
                // must not change which main/post-hook helper we inspect.
                sources.push(command.command.clone());
            }
        }
    }
    Ok(sources)
}

fn make_source(content: &str) -> Result<Vec<String>, String> {
    // This first implementation scans all recipes conservatively. Make's
    // expansion/include language cannot be treated as literal shell source.
    if content.contains('$')
        || content.lines().any(|line| {
            let line = line.trim_start();
            [
                "include ",
                "-include ",
                "sinclude ",
                ".include",
                ".RECIPEPREFIX",
                ".ONESHELL",
                ".SHELLFLAGS",
                "SHELL",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
                || (!line.starts_with('#') && line.contains(':') && line.contains(';'))
        })
    {
        return Err(
            "Make expansions, includes, inline recipes or custom shells require review".to_string(),
        );
    }
    let extracted = crate::scan::extract_makefile_from_str("Makefile", content, &[]);
    // Make's ordinary recipes each start a separate shell; continued recipe
    // lines remain one source in the existing structural extractor.
    Ok(extracted
        .into_iter()
        .map(|command| {
            command
                .command
                .trim_start_matches(['@', '-', '+'])
                .to_string()
        })
        .collect())
}

fn native_binary(magic: &[u8; 4]) -> bool {
    matches!(
        magic,
        [0x7f, b'E', b'L', b'F']
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xfe, 0xed, 0xfa, 0xce]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [b'M', b'Z', _, _]
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn env_prefix_keeps_definite_findings_and_sources_in_the_relaxed_pass() {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().canonicalize().unwrap();
        let source = "git reset --hard\n";
        fs::write(cwd.join("check.sh"), source).unwrap();
        for relaxed in [false, true] {
            for command in [
                "bash check.sh",
                "env -i HOME=/tmp/h PATH=/usr/bin:/bin bash check.sh",
                "env -i PATH=/usr/bin:/bin bash < check.sh",
            ] {
                let capture = crate::desktop_review::ReviewCapture::start();
                let mut inspected = false;
                let result = evaluate(
                    command,
                    Some(&cwd),
                    ShellDialect::Posix,
                    false,
                    None,
                    relaxed,
                    |text, _, _| {
                        assert_eq!(text, source);
                        inspected = true;
                        EvaluationResult::denied_by_embedded_sink(
                            "heredoc.posix.git-reset-hard",
                            "destructive fixture source",
                        )
                    },
                )
                .unwrap();
                assert!(inspected, "{command}, relaxed={relaxed}");
                assert_eq!(result.decision, EvaluationDecision::Deny);
                let info = result.pattern_info.unwrap();
                assert_eq!(info.pattern_name.as_deref(), Some("git-reset-hard"));
                let snapshot = capture.snapshot();
                assert!(snapshot.resolved_paths().contains(&cwd.join("check.sh")));
                assert!(
                    snapshot
                        .description(command, &cwd, &info, "codex")
                        .is_some(),
                    "definite evidence must remain reviewable: {command}"
                );
            }
        }
    }
}
