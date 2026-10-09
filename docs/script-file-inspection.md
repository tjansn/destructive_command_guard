# Pre-execution script-file inspection

This fork inspects recognized file-backed invocations before keyword rejection
can allow their opaque command lines. It reuses DCG's command evaluator,
language AST rules, package.json extractor and Makefile recipe extractor.
There is no LLM, cloud request, executable script invocation or filename cache.

## Enable globally

Build the pinned Rust toolchain's checkout with `cargo build --release --locked`.
Install `target/release/dcg` at the executable path already used by your hooks.
In `~/.config/dcg/config.toml` enable:

```toml
[general]
fail_closed = true
unverified_decision = "deny"
update_pin = true

[policy]
default_mode = "deny"

[heredoc]
enabled = true
scan_script_files = true
fallback_on_parse_error = false
fallback_on_timeout = false
```

Merge these settings into existing sections. Do not create duplicate TOML
tables. `dcg config --format json` reports `heredoc.scan_script_files`.
The new setting defaults to false for existing upstream configurations. In
Tom's user configuration it is always enabled. Automatically discovered,
untrusted project configuration cannot turn a trusted user's true setting off.
An explicitly trusted configuration or operator override remains authoritative.

Use native PreToolUse hooks for Claude Code and Codex. Pi's global `tool_call`
extension must call `dcg --robot test --dialect posix --stdin --enforce-budget`
from the tool's execution directory and deny malformed output, errors and
timeouts. The same executable/configuration must be reachable in cmux and Orca;
their terminals do not add a separate security boundary. Orca's isolated
Codex home also needs its own native hook entry. Start a fresh agent process
after changing hook configuration; changing the referenced binary alone takes
effect on the next invocation of an already loaded hook.

## What is checked

- Literal shell/interpreter file operands, direct script paths, `source`/dot,
  interpreter stdin-file redirects and common literal launch wrappers.
- Shell helpers reached recursively, including helpers in inline shell/SSH
  payloads. Remote/namespace file references are denied as unverifiable rather
  than reading an unrelated local file with the same name.
- Selected npm/pnpm/yarn/bun package scripts with their pre/post lifecycle
  hooks. Nested package tasks share the same inspection budget.
- Literal Makefiles: all extracted recipes are inspected conservatively.
  Expansion, includes, custom shells and inline recipes require review.
- Shell startup files specified explicitly through `BASH_ENV`/`ENV`, and
  supported separate-operand interpreter preload options.
- Python, JavaScript, TypeScript, Ruby, Perl, Go and PHP source through DCG's
  existing language rules. File source is passed directly to that analysis,
  avoiding a shell quoting round trip.

Unreadable/missing sources, unknown execution directories, dynamic filenames,
unsupported syntax, invalid UTF-8, symlink components, helper cycles and
inspection limits deny execution. Attached preload options and dynamic
test/watch/module/package runners require review. This deliberately adds
friction where the guard cannot establish what would execute.

## Bounds and limitations

Each evaluation permits at most 256 KiB per file, 1 MiB total, 32 file reads and
8 simultaneously active files. The existing hook evaluation deadline also
applies. Bounds are shared across recursive evaluation. Exceeding a bound never
authorizes a truncated prefix. Files must be regular, non-symlink files;
nonblocking opens prevent a FIFO from hanging the guard. Metadata is compared
before and after reading and after analysis. Contents are read afresh on every
tool request.

This is a static guard, not an OS sandbox or a proof of arbitrary program
safety. It does not follow every language import, compiler, generated script,
dependency install lifecycle, PATH executable, native binary or arbitrary
framework runner. Language rules retain their existing detection limits.
An attacker can still change a file after the final check and before execution
(TOCTOU), or modify a writable guard/configuration. Trusted overrides can
intentionally permit commands. Filesystem permissions, sandboxing and backups
remain necessary for a stronger boundary.

`dcg scan` remains the offline reporting command. It does not independently
enable hook enforcement. Its extracted-source context does not recursively
resolve executable operands against the scanner's own working directory.

## Verification

`tests/script_file_inspection.rs` uses the real DCG binary and passes candidate
commands as data; the candidate programs are never executed. Regressions cover
the failed-setup/unset-tempdir `find -delete` incident and the local wrapper →
SSH deletion helper incident, plus benign documentation, language sinks, native
hook bytes, cwd handling, lifecycle hooks, source replacement and fail-closed
bounds. Run:

```sh
cargo test --locked --test script_file_inspection
cargo check --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

Measure the installed release build locally: process startup, file size,
language and helper count all affect latency. A small shell helper benchmark
does not establish an upper bound for all scripts.

The initial upstream base `c255094a` has four reproducible failing tests on
this macOS toolchain: the library's
`literal_transfers_and_remote_commit_messages_stay_data_543` and the integration
suite's `issue_544_dangerous_subprocesses_and_executable_interpolation_stay_denied`,
`issue_544_opaque_calls_and_rebound_data_sinks_are_not_exempted`, and
`issue_544_quoted_delimiters_and_written_programs_keep_language_context`.
They fail identically in an untouched archive of that base. These tests remain
unchanged in meaning; this fork does not claim a green complete upstream suite
or comprehensive protection against arbitrary language indirection.
