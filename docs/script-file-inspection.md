# Pre-execution script-file inspection

This fork inspects recognized file-backed invocations before keyword rejection
can allow their opaque command lines. It reuses DCG's command evaluator,
language AST rules, package.json extractor and Makefile recipe extractor.
Static inspection uses no LLM, cloud request or script execution. When static
inspection is incomplete, the optional [sandbox trial](sandbox-trials.md) can
execute the command in a disposable copy and cache an exact-version approval.

## Enable globally

Build the pinned Rust toolchain's checkout with `cargo build --release --locked`.
On macOS, Apple's Command Line Tools (including Swift) are required at build
time for the embedded native Touch ID dialog (macOS 26 SDK or newer); the installed binary requires
no compiler and downloads no helper code at runtime. The native helper targets
macOS 12 or later and is built for the selected Rust target architecture.
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

Use native PreToolUse hooks for Claude Code and Codex. For blocking without
human review, Pi can use `dcg --robot test --dialect posix --stdin --enforce-budget`.
For local desktop review use the fork's
[Pi extension](../integrations/pi/dcg-guard.ts), which sends a native hook JSON
payload and requires an explicit DCG allow verdict. It denies malformed output,
errors and timeouts. The same executable/configuration must be reachable in cmux and Orca;
their terminals do not add a separate security boundary. Orca's isolated
Codex home also needs its own native hook entry. Start a fresh agent process
after changing hook configuration; changing the referenced binary alone takes
effect on the next invocation of an already loaded hook.

## Routine commands and source ownership

Inspection follows executable inputs, not every string that resembles code.
Python/JavaScript heredoc bodies are not also searched for Bash script filenames;
actual shell expansions and interpreter execution sinks still receive their
independent checks. Documentation strings and literal argv data remain data.

A leading literal absolute `cd … && …` can establish an inspection-only directory
for a following pipeline. Sandbox trials, desktop review and remembered script
approvals bind the pipeline's executables in that same directory. This does not
supply a blanket path-scoped allowlist exception. Backgrounding, OR/semicolon
branches, later directory changes, any command or process substitution
(`$(…)`, backticks, `<(…)`), subshell or group after the leading `cd`,
`eval`/sourcing and ambiguous executable sources still require verification.
When the directory is unknown, an absolute native executable can be recognized
without inventing an execution directory for a script.

Exact native metadata queries (`bash --version`/`--help`, Node version queries,
and `env` without an executable operand) have no script-source operands.
Standard absolute SSH diagnostics using `uptime`, `memory_pressure -Q`, or
read-only dotted `sysctl` keys also do not refer to local scripts. This is
argument-role classification, not an allowlist: siblings, substitutions, writes,
preloads, extra operands and project-local namesakes keep their normal checks.

Grammar errors are separate from resource exhaustion. A proven source-only
interpreter body uses the configured bounded grammar-error fallback; disabling
`fallback_on_parse_error` blocks it. An opaque consumer cannot use a different
language's grammar error to establish its stdin as inert. Time, worker, source
size, node-count and payload limits remain incomplete analysis, never a clean
allow. Tom's strict configuration continues to disable grammar-error fallback.

## One-request desktop approval (macOS)

Set the trusted user hook command to `/absolute/path/dcg --desktop-review`
and its host timeout to at least **150 seconds** for static review, or
`trial.timeout_secs + 180` (**780 seconds** by default) with sandbox trials.
Keep `default_mode = "deny"`,
`unverified_decision = "deny"` and `scan_script_files = true`. Copy the fork's
[Pi extension](../integrations/pi/dcg-guard.ts) to
`~/.pi/agent/extensions/dcg-guard.ts`, adjusting its absolute executable path.
Restart each agent after changing its hook/extension.
Claude hook self-repair preserves an existing `--desktop-review` option and its
host timeout when large enough for enabled trials, including when repairing a
stale executable path. It raises shorter deadlines to fit trials. It never copies
arbitrary arguments from the previous hook command.

After a verified rule-based denial, the hook waits for a compact local native
macOS window. The detected agent, Orca/cmux context when available and project
name appear above a short German action summary followed by its consequences.
For a single literal removal target, the summary names the file or folder
without its full path; multiple targets are counted. Long names and non-path
targets retain a general action summary. The nearest `.git` directory or
worktree marker identifies the repository without executing Git. A folder is
shown when none is found.
**Details** expands the exact execution directory and complete
command, all literal target paths/search roots and Git names, rule and the full
contents of small inspected scripts. Nothing is discarded from those details.
On macOS 26 or newer the surface uses native **Liquid Glass**; older supported
systems use a native translucent material. System appearance and accessibility
preferences remain in control of the material.
Agent and project form one quiet inset surface; the action and consequences
have stronger visual weight. The footer combines the real Touch ID view and
the reject button. The 460-point-wide layout uses concentric 28/12-point corners
with a 16-point inset, a modest 16-point action heading and concise consequences.
Full paths and technical command text appear only in the expanded details.
Details expand immediately, with no decorative movement on this frequent flow.

macOS **Touch ID** is embedded directly in this window through
[LAAuthenticationView](https://developer.apple.com/documentation/localauthenticationembeddedui/laauthenticationview).
Authentication starts once the populated window is visible, key and active.
There is no preliminary approval click or second authentication alert: read
the action, then put a finger on Touch ID to approve this request. A fresh
LocalAuthentication context requires biometrics, verifies that the device uses
Touch ID, disables reuse of a previous unlock and offers no code/password
fallback. Fingerprint data remains with macOS; DCG receives only success or
failure. **Ablehnen** and Escape cancel. Closing, switching to another app/window
while authentication is pending, failed authentication,
unavailable/locked-out Touch ID, no response after 120 seconds,
a busy dialog, backend failure or changed script bytes leaves the denial in
place. The process watchdog terminates a stuck dialog after 125 seconds.
The authentication uses [Apple's LocalAuthentication framework](https://developer.apple.com/documentation/localauthentication).

The helper is compiled once and embedded in the Rust executable. On first use,
DCG materializes it in its private configuration cache and verifies its exact
bytes and executable permissions before each use. Modified files and symlink
paths are refused. Commands and script contents travel as JSON on stdin, not as
shell code or process-list-visible arguments. A random per-request nonce binds
the helper reply; it is a transport token, never a user-entered approval code.

Approval releases only the pending tool request. It writes no allowlist or
reusable allow-once grant and does not bypass the host's own permissions. Script
hashes and execution-directory identity are checked before and after the dialog.
All recognized sibling helpers/lifecycle sources are inspected even after the
first destructive finding, so later helper edits also invalidate approval.
For this static review path, incomplete inspection, dynamic deletion operands, oversized reviews (over 5000 bytes),
multi-entry tool batches, unsupported platforms and disabled script inspection
never gain desktop approval. Revise ambiguous commands to use literal targets.

Sandbox trials have a separate review contract: an inconclusive observed run can
be approved for the fingerprinted command and source version. The dialog says
that the evidence is incomplete and that the approval is reusable until that
version changes. Unsafe trials are denied. Missing/unresolvable inputs cannot
be bound to a version and therefore cannot receive that reusable approval.

This avoids Codex's unsupported hook `ask` value: Codex receives an ordinary
blocking verdict unless the human directly approves the local dialog. See
[official hook limitations](https://learn.chatgpt.com/docs/hooks).
`test`, `explain`, `scan` and JSONL batch mode never show approval dialogs or
change their decision APIs. The option is explicit in the trusted hook command;
projects cannot turn it on via an automatically discovered config file.

Touch ID adds operating-system authentication to the local review. It does not
protect against a process able to replace DCG itself or its hook configuration
under the same user account. Native executables, imports and the remaining
check-to-execution race retain the limitations below. Full script contents
appear only locally in the dialog; the explanation uses templates, no LLM/API.

Run `cargo test --lib desktop_review::tests` for automated checks. The ignored
`native_dialog_manual_preview` test shows a harmless live dialog and real
Touch ID authentication without ever executing a candidate command. Automated
tests exercise invalid helper input, altered/symlinked cache entries and bound
success replies; they do not simulate a successful fingerprint.
Context tests cover nested repositories, linked worktrees, ordinary folders and
visible escaping of control characters in identity labels. Agent/host labels
are contextual information from the invoking integration/environment, not an
attestation of an agent's identity against other processes in the same account.

Codex's per-tool `tool_input.workdir` takes precedence over the session cwd.
Malformed or relative overrides fail closed for file inspection and scoped
approval. A multi-entry batch with an override is not given a guessed cwd.
Some Codex runtimes pass only the canonical shell command and the session cwd
to hooks, omitting the underlying exec tool's `workdir`. DCG cannot recover a
directory the host did not send. In that case, express directory changes with
an explicit literal `cd /absolute/project && ...` so both the guard and shell
resolve relative scripts in the same directory. Do not approve an unverified
script against a guessed directory. Absolute removal targets remain explicit.

When desktop review cannot start, or authentication does not approve the
request, its reason is included in the blocking JSON as well as stderr. This
keeps missing hook options, incomplete inspection and cancelled authentication
visible in Codex hosts that display only the JSON reason. It never changes the
original blocking verdict or creates a grant.

Run `node --experimental-vm-modules tests/pi_desktop_bridge.mjs` for the Pi
bridge's explicit-verdict, malformed-output and process-failure regressions.

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

Static inspection is not a proof of arbitrary program safety. The separate
[sandbox-trial flow](sandbox-trials.md) can resolve its unverified rule with
an observed run and an exact-version grant. Static inspection itself does not
follow every language import, compiler, generated script,
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
