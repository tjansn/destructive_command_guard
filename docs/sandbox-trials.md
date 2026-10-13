# Sandboxed trials for unverified commands

## Continuing confinement for finite commands

On macOS, Claude Code and the updated pi bridge run eligible finite commands
**once in the real workspace under continuing confinement**. This takes precedence
over observational trials, including when static inspection already allows a finite
command. No approval or learned entry is recorded. Definite static denials still
block; unsupported dynamic script inspection alone can proceed under enforcement
after the remaining rules pass.

Claude Code receives `hookSpecificOutput.updatedInput`, preserving every original
tool-input field except `command`, as specified in the
[PreToolUse contract](https://code.claude.com/docs/en/hooks#pretooluse-decision-control).
The pi bridge advertises rewrite support and mutates `event.input.command` in place,
as permitted by pi's
[tool-call event contract](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/extensions/types.ts).
It fails closed if that mutation fails. A confined receipt is distinct from an
ordinary allow receipt. An older pi bridge, Codex, OpenCode and other protocols keep
the observational trial path; they never receive an assumed rewrite capability.

The replacement invokes this dcg executable's `run --confined --request` entrypoint.
A bounded base64url JSON envelope carries the command, cwd, shell, profile version
and deadline. The original command is an argument to the fixed launcher, without
shell interpolation while constructing the replacement. There is no unconfined
fallback if setup or execution fails.

Supported forms are explicit Node test/syntax inputs, system-shell syntax checks,
finite tsc/eslint/biome commands and npm/pnpm/yarn test/check/lint/build scripts whose
pre/main/post entrypoints meet the same contract. A single leading `cd <literal dir>
&& <finite command>` is also supported: dcg canonicalizes the directory and launches
the finite command there. Quoted spaces and `cd --` work. Expansion, substitution,
`cd -`, relative paths affected by `CDPATH`, and additional chains are excluded.
Other chains, substitutions, background,
watch, service-start and unsupported runner forms are excluded. This identifies
runner intent, not guaranteed termination of arbitrary imported code; all runtime
code and descendants remain subject to the kernel profile and resource bounds.

Git discovery grants writes only to ignored paths. Absent `build`, `dist`, `target`,
`.build`, `.cache` and `coverage` directories must also be ignored as whole directories.
Tracked and non-ignored sources, `.git`, dcg state/executables and hook configuration
remain unwritable. A writable ancestor containing protected data is excluded;
symlink roots and existing hard links in writable trees fail setup, and creating
hard links is denied. The per-run home and temp directories are writable. Project
files are readable; the Part C credential, external-read, network and Mach boundaries
continue to apply. Real-project Unix sockets are not considered owned by the run.
By default **all outbound TCP remains denied**, including exchanges with the run's
own listener. Trusted `[trial] confined_loopback = "all"` opens outbound TCP to
**every localhost service**, including pre-existing host services. It does not prove
endpoint ownership: such a service can act outside the child's filesystem sandbox
as a confused deputy. This is Tom's explicit Part F2 choice after the failed F1
ownership probes, not a replacement isolation backend. Non-loopback outbound and
the existing read/write/Mach restrictions stay denied. Observational trials always
keep deny-all outbound TCP, even with this setting.

The rewrite receipt includes `approvalScope = "confined"`, `confinedLoopback` and
plain-language policy text; the runner repeats that policy on stderr. The request
binds the choice, and the runner rejects it if current trusted config differs.
Automatically discovered project config cannot enable it. No reusable approval is
created by a confined run in either mode.

The real environment is retained except for the following case-insensitive removals:

- Names containing `TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `CREDENTIAL`, `COOKIE` or `AUTH`.
- Prefixes `AWS_`, `AZURE_`, `GOOGLE_`, `GCP_`, `DCG_`, `DYLD_`, `LD_`, `BASH_FUNC_`,
  `NPM_CONFIG_` and `GIT_CONFIG_`.
- `NODE_OPTIONS`, `NODE_PATH`, `NODE_REPL_EXTERNAL_MODULE`, `BASH_ENV`, `ENV`,
  `ZDOTDIR`, `PYTHONPATH`, `PYTHONHOME`, `RUBYOPT`, `RUBYLIB`, `PERL5OPT`, `PERL5LIB`,
  `PHP_INI_SCAN_DIR`, `PHPRC`, `SSH_AGENT_PID`, `SSH_AUTH_SOCK`, `DOCKER_HOST`,
  `KUBECONFIG`, `OPENSSL_CONF` and `OPENSSL_MODULES`.

`HOME`, `USERPROFILE`, `CFFIXED_USER_HOME`, the four XDG home variables and
`TMPDIR`/`TMP`/`TEMP` point into the disposable run directory. npm is forced offline
with update notification disabled. Values such as `DATA_DIR` remain real inputs,
but do not expand filesystem permissions. This name-based credential filter cannot
identify secrets placed in arbitrary innocuous variable names.

The command's exit status and stdout/stderr are returned; observed kernel denials
are appended as `[dcg:confined-denial]` with operation and target. Reporting limits
use `[dcg:confined-limit]`. Both enforcement canaries must pass before execution.
After execution a failed subscriber does not discard the actual result. The bounded
one-second log drain improves reporting but cannot guarantee delivery of every
asynchronous kernel report; enforcement does not depend on those reports.
When the command itself reports `EPERM`/`EACCES`, a separate notice points to its
preserved output. This is untrusted program text, never a synthetic kernel
observation or evidence for an approval. Native fixtures check the denied syscall
and target in the kernel report or the real Node error, as well as the failing
status and unchanged victims.

Runtime is capped at the configured trial deadline and 600 seconds, including setup.
The hook also reserves five seconds below Claude's millisecond tool deadline
(120 seconds by default) or pi's optional deadline in seconds. Timeout returns 124
after terminating the process group. Each output stream retains at most 8 MiB;
CPU, descriptors and per-file output are bounded. Explicit background modes are
unsupported. A process deliberately escaping its group still inherits confinement,
but is outside the cleanup guarantee. An externally killed supervisor can likewise
prevent orderly cleanup; this is not a service lifecycle implementation.

## Static inspection outcomes and finite inputs

Hook denials identify `definite-dangerous-operation`, `unsupported-dynamic`,
`analysis-limit`, or `review-unavailable-or-cancelled`. Claude receives `outcomeCode`;
strict protocols retain their schemas and carry `[dcg:<code>]` in the reason. Robot
`dcg test` output includes `outcome_code`. Incomplete script-file inspection does not
advertise an ineffective command-only code or broad rule allowlist as a remedy.
The existing tar-helper exact-command human exception remains available because
that gate consumes it; its diagnostic still identifies unresolved dynamic input,
and does not present the exception as static verification.

Interpreter argument roles distinguish executable, syntax-only and startup sources.
Native Node `--check` and system shell `-n` do not scan their data operands for
execution, but startup injection, shadowed commands, substitutions and siblings still
require inspection. Query-only `command -v/-V` shares the heredoc wrapper model.

Explicit Node test files and local single-level glob components are resolved with
32-file, 8-level, 1-MiB-total and 256-KiB-per-file limits (glob enumeration: 1,024
entries). Static local JS/TS imports, literal import/require calls, preloads, custom
reporters and literal child entrypoints are inspected; npm pre/main/post scripts use
separate shell contexts. Definite findings outrank unresolved siblings. External
packages, computed sources, unsupported options, default test discovery, recursive
globs and watch modes remain review/trial cases. Node CLI semantics were checked
against [the official reference](https://nodejs.org/api/cli.html); older Node versions
that do not support quoted test globs may reject them at runtime.

Transient AST failures get one parse-only reading, capped at 200 ms and the remaining
hook budget, with one concurrent reader, 64 content/language/policy/context cache
entries and bounded source/match sizes. A clean second reading never authorizes a
timed-out command: it can only supply a definite finding or preserve incompleteness.

## Observational trials

Sandboxed trials resolve supported file-backed commands whose static
inspection is incomplete, starting with `heredoc.script_files.unverified`.
They do not override definite destructive matches. On protocols without input
rewriting, or for commands outside the finite contract, the hook waits while dcg
observes a run in a disposable copy of the project, then checks the remaining
rules before allowing the real command.

The [approved design](design/sandbox-trials.md) records the decisions and
acceptance tests. This page describes the operating contract; it does not
certify an untested macOS release or a particular project's runtime.

## Configuration

Use a trusted dcg configuration file:

```toml
[trial]
enabled = true
timeout_secs = 600
network = "localhost"
confined_loopback = "none"
max_copy_bytes = 2_000_000_000
keep_artifacts = false
```

These are the defaults. `localhost` is the only accepted observational network
policy and permits binding/listening, not outbound TCP. For continuing confinement
only, `confined_loopback` accepts `none` or `all`. To opt in after validated
installation, Tom may add **`confined_loopback = "all"`** under `[trial]` in trusted
user config. This task does not change that live file.
The timeout and fallback copy cap must be positive. Set `enabled = false` to
keep the static decision and one-time desktop-review path. With trials disabled,
stored exact-version approvals are ignored and desktop review neither reads nor
writes the trial approval store or its hash cache. Automatically
discovered repository configuration cannot alter these execution settings;
trusted user, system and explicitly selected configuration layers can.

Keep script inspection enabled with `[heredoc] scan_script_files = true`.
Use the existing `--desktop-review` hook option for Touch ID review of an
inconclusive trial. When desktop review is unavailable or not approved, dcg
keeps the command blocked.

Literal execution-affecting assignments such as
`env -i HOME=/tmp/example PATH=/usr/bin:/bin cargo test` are classified as
`bound-input-review`. Their raw values and the executable resolved through that
PATH are bound into the reviewed identity and rechecked after Touch ID. This path
offers **one-request** review, with no trial or reusable approval for the override.
Expansion, substitution, unsupported `env` switches, an unresolved executable and
inherited preload/startup variables still fail closed. The diagnostic advertises
desktop review and never suggests an ineffective command-only code or trial grant.

## What happens during a trial

dcg finds the project root and maps the command's working directory into a
temporary copy. Copy-on-write cloning is preferred; the plain-copy fallback
has the configured byte cap. The command runs with closed stdin, an empty
home and an allowlisted environment. Secrets, cloud credentials and the SSH
agent socket are not inherited. `NODE_OPTIONS` is also excluded because it can
inject preloads outside the fingerprinted project. Package-manager offline
and update-notifier settings suppress lazy downloads and telemetry; software
that needs omitted settings may require review. Captured output is bounded.

The macOS sandbox restricts writes to the trial directories and necessary
devices. Reads are limited to those directories and documented OS/runtime trees
(`/System`, `/usr`, `/bin`, `/sbin`, Apple/Developer libraries, Nix packages and
Homebrew Cellar/opt), a few system data files and random/null devices. The root
directory entry is readable for dyld initialization; this does not allow reading
its descendants. Host credential stores, browser profiles, other projects and
the learner database lie outside the read boundary. Mach lookups are limited to
the OS notification center, directory lookup, logd and diagnosticd bootstrap
services needed by the runtime; credential brokers and LaunchServices are denied.
Inspection of other processes is denied, as are external signals and AppleEvents.
Child processes inherit the sandbox. The
timeout applies to the process group; temporary artifacts are removed unless
`keep_artifacts = true` is selected for debugging.

Only trial-local Unix sockets and loopback **binding/listening** are permitted.
TCP outbound connections, including localhost, are denied: this profile does not
establish ownership of a TCP peer. Even a connection to the trial's own listener
therefore requires review. This conservative fallback prevents a pre-existing
host service from acting as a deputy. A disposable HTTP fixture verifies that its
victim remains unchanged. No host service or real credential store is probed.

On macOS 27.0.1 the implementation observes an active `log stream` subscription;
the tagged events were not retained for a later `log show` query. Denied canary
writes and a disposable read canary verify enforcement and observation before any user command starts and
after it ends. Missing markers, a failed subscriber, or a capped log are
inconclusive. This follows Apple's recommendation to
[stream sandbox violations](https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations).
Permission failures from tools that preflight access without a kernel report
also require review. CPU time, open descriptors and per-file output size are
bounded in the child shell. There is no hard address-space limit: modern
Node/V8 reserves large virtual ranges even for small test suites.

A literal leading `cd /absolute/project &&` maps into the cloned directory.
Other absolute paths embedded in scripts are not rewritten; attempts to write
back to those original paths are blocked. The fallback copy has a byte cap;
copy-on-write cloning does not count shared blocks against that cap.

| Observation | Result |
|---|---|
| Complete observation, no denied operations, only permitted build/cache/temp writes | Observed safe in one sandboxed run: record the version and allow after other rules pass |
| Denied outside writes, external signals, AppleEvents, or deleted tracked/source files | Unsafe: deny and explain the attempted operations |
| Denied read/IPC/network attempt, timeout, modified source files, interactive input, unavailable sandbox, or incomplete observation | Inconclusive: request existing desktop review |

Test failures and other nonzero exit codes are not destructive evidence by
themselves. A formatter that changes source files needs review; a test that
writes only disposable build output can pass. A command needing internet
access cannot earn an automatic safe verdict from an offline run.

## Exact-version approvals

Approval binds the command, canonical project and working directory,
resolved executable identity and project input content. Verified entries have
no time expiry. A changed input stops matching and requires verification
again. A timestamp change without a content change keeps the content identity.

Reliable unprivileged file-read tracing is not assumed. The conservative
fallback fingerprints all non-ignored project files, using content hashes
cached by file metadata. This means an unrelated source edit can require a
new trial. Known ignored runtime inputs are also bounded and hashed; unresolved
external inputs remain limitations. This is an observation of one execution, not a proof of
arbitrary script behaviour.

Use `dcg allowlist list` to inspect verified trial entries. Revoke an entry with
`dcg allowlist remove verified_trial:<fingerprint>`, using the identifier from
the list. `dcg allowlist prune --dry-run` previews stale entries; omit
`--dry-run` to remove them. `--project` restricts these operations to the current
project. Verified entries live in the user's allowlist storage and are bound
to a canonical project root; a repository cannot approve itself.
Approvals made by Touch ID are labelled `user-review`; automatically verified
entries are labelled `trial`.

## Manual trials and explanations

```sh
dcg trial run -- 'npm test'
dcg trial show <id>
```

Run the command from the relevant project directory. The trial command
executes in the temporary copy, so a safe result does not itself perform the
requested work in the real project. Stored summaries identify the observed
operations and trial ID. They abbreviate paths under the user's home to `~`,
cap item counts and avoid storing file contents or environment values. Review
the summary, adjust the command when appropriate, then retry through the
normal hook.

## Hook and agent timeouts

The host must let dcg finish a trial and any subsequent review. When trials and
script-file inspection are enabled, the configured hook timeout is
`trial.timeout_secs + 180` seconds: **780 seconds** with the defaults. This is
separate from the short static evaluator budget in `general.hook_timeout_ms`.

After deliberately deploying the rebuilt binary and enabling script-file
inspection, run `dcg install` to refresh Claude Code and registered Codex hook
timeouts; use the corresponding install option for other agents, such as
`dcg install --opencode` for the owned OpenCode plugin. Restart the agents.
Larger existing JSON hook deadlines are preserved. Generated plugin files
use the current configuration's deadline when refreshed. Claude Code's Bash
tool timeout, Codex's calling tool timeout and other parent watchdogs can
still end a request earlier; configure those to cover the trial and the real
command where applicable. The hook prints a single progress line to stderr
while verification runs.

Pi's user-authored bridge needs its own change; dcg does not edit the user's
Pi extension. Raise the older 140-second timer to at least
`(timeout_secs + 180) * 1000` milliseconds, **780_000** by default. See
[Pi](pi-integration.md), [Codex](codex-integration.md) and
[OpenCode](opencode-integration.md) integration notes.

## Limits and rollout

Apple has deprecated `sandbox-exec`. A missing or unusable sandbox, or an
observer that cannot establish complete evidence, must produce an
inconclusive result and desktop review. Availability must be tested on each
target macOS release; do not infer macOS 27 support from a macOS 26 result.
Other platforms retain the review path instead of claiming a successful trial.
Native integration tests have been exercised on macOS 27.0.1. macOS 26 and
other releases still need their own native validation. The tagged-report
canary requirement fails closed if a release changes the reporting format.

The cloned repository's own `.git` state remains unwritable. Launchers such as
Apple's `/usr/bin/python3` may try to update an external Xcode cache; that write
is blocked and counts as unsafe evidence even if the program subsequently exits
successfully. Zsh runs with `-f` to prevent host startup files from replacing the
sanitized environment. Shell startup customization is therefore not reproduced.

### Website workflow acceptance

The 2026-10-12 website-session report identified a grant-ordering mismatch:
script inspection returns before ordinary exact-command and allow-once grants.
For `heredoc.script_files:unverified`, dcg now emits neither an ineffective
allow-once code nor exact-command allowlisting advice. Existing command-only
grants remain unconsumed; they do not attest executable or project versions.
The supported reusable approval is an observation of one sandboxed run or an explicit version-bound
desktop review. Other rules keep their own approval and denial authority.

An owned loopback listener can bind and close; TCP exchanges require review.
A long-running preview server is not certified by reaching a timeout or by
detaching. Top-level background commands are not started automatically; they
go directly to inconclusive exact-version review. Timeouts and surviving child
processes discovered inside a script are also inconclusive. Process groups are
terminated before inspecting the clone.
There is no dedicated HTTP readiness, fixed document-root, port-ownership or
service-lifecycle certificate. Such services require version-bound human review;
loopback access alone is not a safety verdict. Processes that deliberately escape
their process group are outside the cleanup guarantee, though they inherit
the sandbox restrictions.

Local Node test suites can learn an unchanged safe version, including execution
from a relative subdirectory. Rebuilding non-ignored generated HTML changes a
source manifest and requires review. Browser inspection and screenshot loops use
the same path only when their command, working directory and executables can be
bound; dynamic unresolved wrappers remain blocked with an explanation. There is
no browser-specific approval or rewriting of a blocked command. The reported live
preview command and website were not executed or changed during this work.

The Pi bridge still needs the operator's deployment update to its old 140-second
watchdog. The repository bridge now uses 780 seconds and passes the existing
controlled bridge tests. Updating this checkout changes no installed binary,
live policy or hook.

The native acceptance suite includes a relative `cd site && node --test` workflow,
its cached second invocation, blocked TCP exchanges, and a background HTTP
preview request that produces review guidance without starting a server. It also
checks that a sibling warning cannot release an unresolved command. Browser DOM
evaluation and screenshot loops have no dedicated end-to-end fixture; the original
feedback lacked their complete command strings, so those cases remain design
review items rather than claimed successful runs.

The success label is **observed safe in one sandboxed run**. Scripts can branch on time,
environment, data, network or sandbox detection; a real run has different
inputs and permissions. Exact-version binding reduces stale approvals but
does not close the check-to-execution race or attest a mutable guard binary.
Keep OS permissions and backups as independent protection.

Runtime fingerprints include ignored lockfiles, `.env`, helper/config sources and
the actual installed dependency bytes within bounded file/byte limits. Oversized,
symlinked or unresolved runtime inputs require a one-request desktop review and
cannot produce a reusable entry. Environment values are hashed without appearing
in diagnostics or persisted records. A variable cleared by the trial, such as
`NODE_OPTIONS`, a credential or a `DATA_DIR` override, prevents reuse and automatic
trial approval. The macOS text-encoding variable is forwarded with locale settings.
Existing shell startup customization also requires review. This deliberately
reduces the workflows eligible for observation-based grants.

On the tested Mac, the installed npm runtime probes host global preferences and
LaunchServices even for a finite fixture. Those reads/IPC remain denied and the
observational path requires review. The Node fixture tests the workload directly;
this is a measured compatibility loss from the tighter boundary, not a new npm
exemption. Python networking fixtures use `-S` to isolate socket behavior from
machine-specific site packages. The `.git` write fixture uses a real temporary
Git repository so dependency discovery completes before exercising enforcement.

Verified native Node `--check` and system shell `-n` operands are syntax data, so
their content does not spend the executable-source AST budget. Preloads, startup
context, sibling commands and substitutions retain inspection. Unshadowed builtin
`command -v/-V` queries share the shell evaluator's query semantics. Unsupported
or shadowed forms continue to require review.

For rollout, first run the temporary-directory trial and hook tests on the
target Mac, measure a representative project, then build with
`cargo build --release --locked`. Installing that binary and refreshing hook
configuration are separate operator actions. The implementation worktree
does not replace an installed binary or edit agent home directories.
