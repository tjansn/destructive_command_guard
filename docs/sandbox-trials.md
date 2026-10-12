# Sandboxed trials for unverified commands

Sandboxed trials resolve supported file-backed commands whose static
inspection is incomplete, starting with `heredoc.script_files.unverified`.
They do not override definite destructive matches. The hook waits while dcg
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
max_copy_bytes = 2_000_000_000
keep_artifacts = false
```

These are the defaults. `localhost` is the only accepted network policy.
The timeout and fallback copy cap must be positive. Set `enabled = false` to
keep the previous static decision and desktop-review path. Automatically
discovered repository configuration cannot alter these execution settings;
trusted user, system and explicitly selected configuration layers can.

Keep script inspection enabled with `[heredoc] scan_script_files = true`.
Use the existing `--desktop-review` hook option for Touch ID review of an
inconclusive trial. When desktop review is unavailable or not approved, dcg
keeps the command blocked.

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
devices, permits loopback networking and trial-local Unix sockets, and blocks
external signals and AppleEvents. Child processes inherit the sandbox. The
timeout applies to the process group; temporary artifacts are removed unless
`keep_artifacts = true` is selected for debugging.

On macOS 27.0.1 the implementation observes an active `log stream` subscription;
the tagged events were not retained for a later `log show` query. Denied canary
writes verify enforcement and observation before any user command starts and
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
| Complete observation, no denied operations, only permitted build/cache/temp writes | Safe: record the version and allow after other rules pass |
| Denied outside writes, external signals, AppleEvents, or deleted tracked/source files | Unsafe: deny and explain the attempted operations |
| Network attempt, timeout, modified source files, interactive input, unavailable sandbox, or incomplete observation | Inconclusive: request existing desktop review |

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
new trial. Ignored dependencies, files outside the project and runtime inputs
remain limitations; this is an observation of one execution, not a proof of
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
The supported reusable approval is a safe trial or an explicit version-bound
desktop review. Other rules keep their own approval and denial authority.

Finite loopback exchanges are tested with sockets owned and closed by the test.
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
its cached second invocation, a loopback socket exchange, and a background HTTP
preview request that produces review guidance without starting a server. It also
checks that a sibling warning cannot release an unresolved command. Browser DOM
evaluation and screenshot loops have no dedicated end-to-end fixture; the original
feedback lacked their complete command strings, so those cases remain design
review items rather than claimed successful runs.

One observed run proves the behaviour of that run. Scripts can branch on time,
environment, data, network or sandbox detection; a real run has different
inputs and permissions. Exact-version binding reduces stale approvals but
does not close the check-to-execution race or attest a mutable guard binary.
Keep OS permissions and backups as independent protection.

For rollout, first run the temporary-directory trial and hook tests on the
target Mac, measure a representative project, then build with
`cargo build --release --locked`. Installing that binary and refreshing hook
configuration are separate operator actions. The implementation worktree
does not replace an installed binary or edit agent home directories.
