# dcg: a dialog that survives focus steals, and learning from real effects

2026-10-12 · Tom's fork (`main` = `98d84018`, 0.15.3+tom.9) · approved decisions marked **Tom**

## Part A: the Touch ID dialog declines itself inside Orca (bug, fix first)

### Evidence (unified log, 2026-10-12 19:38:39 local, a real Claude Code PreToolUse hook)

- dcg spawned the helper (`~/Library/Application Support/dcg/desktop-review/3594…/DCG`, pid 54477); the window became
  key, `beginAuthentication()` started Touch ID (`coreauthd … MechanismTouchId … will start matching`).
- 30 ms later: `launchservicesd SETFRONT: pid=31925 (Orca) … oldFrontPid=54477`. Orca re-took the front because Orca's own
  PreToolUse hook (`~/.orca/agent-hooks/claude-hook.sh`, matcher `*`) fires for the same tool call at the same moment.
- `windowDidResignKey` → `finish(false)` (`src/desktop_review.swift:349-351`) → `context.invalidate()` → LAError -9
  (appCancel) → `denied`. Total hook time ≈ 0.3 s. Tom saw no dialog. dcg reported
  "Nicht per Fingerabdruck freigegeben: abgelehnt, abgelaufen, Dialog nicht verfügbar …".
- The same request fed to `dcg --desktop-review` by hand (no concurrent Orca hook) shows the dialog and Tom approved it
  (14–24 s). So every desktop review requested from Claude Code inside Orca has been auto-declining.

### Fix (keep the security property, lose the self-decline)

The property to keep: a fingerprint is only ever accepted while the dcg window is key and dcg is the active app, so a
fingerprint meant for another app can never approve dcg's request.

- On resign-key while authenticating: cancel the running LAContext evaluation (new `LAContext` per attempt — an invalidated
  context cannot be reused), keep the window on screen (floating, all spaces), show "Klicke auf den Dialog, um mit Touch ID
  fortzufahren", and do NOT finish.
- Re-activation: if focus was lost within the first 1.5 s after the window appeared (a programmatic steal, not the user),
  re-activate dcg once automatically (`activate(ignoringOtherApps:)` + `makeKeyAndOrderFront`). After that, only a user
  click on the dialog re-activates it. Restart authentication on `windowDidBecomeKey` (fresh context).
- Success is still only accepted when `success && NSApp.isActive && window.isKeyWindow` at the reply.
- The overall 120 s timeout, Esc/"Ablehnen" and window close still deny. The hook waits as before.
- Tests: a UI-less controller test with a fake LA evaluator and injected resign/become-key events (steal during auth →
  no finish, restart on become key, success only while key; a second steal after the first re-activation → wait for
  click; timeout → denied). A native acceptance note on how it was tried live with Orca in front.

## Part B: learn safe outcomes for definite rules, not just unverified scripts

**Tom:** "Dcg must be able to learn that this is safe." **Tom:** changes to dcg itself are never learned — always ask.

### Scope

Today only `heredoc.script_files:unverified` can earn a reusable approval (sandbox trial or Touch ID exact-version
review). Definite rules (e.g. `core.filesystem:mv-sensitive-source-root-home`, `rm-recursive-general`) judge the command's
shape. Many of them guard a hazard that the actual filesystem state can rule out. Add:

1. **Effect checks for filesystem rules** (new, deterministic, before the dialog). For a single-segment command (no `&&`,
   `;`, pipes, subshells, globs, variables, command substitution) whose operands are literal absolute or `~` paths, inspect
   the real paths with `lstat` (no following symlinks) and decide what the command would actually do:
   - `mv`/`cp`: source is a regular file (not a directory, not a symlink to one, not a dotfile tree root, not a home
     root or top-level home folder), destination is a regular file or absent, same parent directory or a non-sensitive
     directory; no recursion possible. Effect = "replace/create one file". Such a command is not the relocate-then-delete
     bypass the rule exists for.
   - `rm` without `-r`: regular files only (already allowed); `rm -r` on a directory: count entries/bytes and check git
     tracking — never auto-allowed, but the dialog shows the real effect ("deletes folder X: 12 files, 3.4 MB, 2 tracked
     by git").
   - Outcome of the check: `allow` only for the bounded single-file cases above when the rule's documented hazard is
     provably absent; otherwise the existing review, with the measured effect in the dialog text.
2. **Learned approvals for definite rules.** When the user approves a definite-rule command by Touch ID, record a
   `user-review` entry bound to: the exact command, the canonical cwd, the rule id, and the identity of every operand path
   (dev, inode, type, size, mtime, and a content hash for regular files ≤ 64 MiB; for directories: a manifest hash of
   names/types/sizes, capped). The next identical command with unchanged operands is allowed without a dialog; any change
   requires review again. Same storage, listing, removal and pruning as trial entries (`dcg allowlist list`, `remove`,
   `prune`). No expiry (consistent with trials), but entries are pruned when an operand disappears.
3. **Never learned (Tom):** any command whose operands touch dcg itself — the running dcg executable and its directory's
   `dcg*` files, `~/.config/dcg/**`, `~/Library/Application Support/dcg/**`, every installed hook configuration dcg
   manages (`~/.claude/settings*.json`, `~/.codex/hooks.json` and `config.toml`, OpenCode plugin, Grok/agy hook files) and
   `~/.pi/agent/extensions/dcg-guard.ts`. Those always get the Touch ID review, are never auto-allowed by effect checks,
   never recorded as learned entries, and the dialog says "Änderung an dcg selbst – wird nie gemerkt".

### Tests (CI-safe, temp HOME, never the real account)

- Effect checks: single-file `mv`/`cp` replace within one folder → allow; directory source, symlink source, dotfile tree
  root, home root, multi-segment, glob/variable operands → review; `rm -r` effect text.
- Learned entries: approve once (fake dialog) → identical command with unchanged operands allowed; a changed operand
  (content, size, inode, type) → review again; listing/removal/pruning; definite-rule entries cannot satisfy a different
  rule or command.
- Self-protection: every path in the list above → review every time, nothing recorded, even after approval.
- Existing suites stay green (`cargo test --offline --no-fail-fast -- --test-threads=1`), clippy `-D warnings`, fmt.

### Deliverables

Feature branch in the Orca worktree, separate commits for A and B, the design copied to `docs/design/`, docs updated
(`docs/sandbox-trials.md` or a new `docs/learned-approvals.md`), a report at
`/Users/tom/Documents/Codex/2026-10-09/k/work/dcg-learning-REPORT.md` with exact test totals. Do not install, push, or
change live configuration; the operator installs.

## Part C: harden sandbox trials (independent review by Distill, requested by Tom; verified 2026-10-12)

Verified in `src/trial_profile.rs`: line 32 `(allow default)` (all host file reads allowed, incl. `~/.ssh`, `~/.aws`,
keychains, other projects); line 40 `(allow network-inbound network-outbound (remote ip "localhost:*"))` (a trial can
connect to services that already run on the host — local servers, Docker over TCP, Ollama, the pi-os harness — which can
then write outside the sandbox on its behalf, unobserved). A "safe" verdict is therefore an observation of one run, not
proof about later unsandboxed runs, and must never be presented as more.

1. **Owned-only loopback.** A trial may connect only to loopback ports/sockets that the trial itself bound. Connecting
   to a pre-existing host listener is denied (or, if SBPL cannot express it, observed and turned into `inconclusive`,
   e.g. by reporting allowed connects and comparing them against the trial's own binds). Unix sockets only inside the
   trial directories.
2. **Secret-read isolation.** Deny (and report → `unsafe`/`inconclusive`, decide and document) reads of credential
   stores: `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc` tokens,
   `~/Library/Keychains`, browser profile folders, `~/.config/dcg`, password-manager agents' sockets. Also deny reading
   other processes' environments (`ps eww`-style task inspection) if SBPL allows (`process-info*` on others).
3. **Bind what the trial did not reproduce.** The exact-version fingerprint also covers the dependency lockfile(s) and
   the resolved contents of directly executed ignored dependencies where cheap (e.g. `node_modules/.package-lock.json`
   hash), and the real run's relevant environment (`NODE_OPTIONS`, `DATA_DIR`-style overrides, `PATH` already bound): if
   the real environment sets a variable the trial cleared, the learned grant does not apply → review.
4. **Semantic regression cases** (not allowlists):
   - `node --check public/app.js` was denied because target-source AST scanning hit 21 ms > 20 ms: a syntax check
     must not depend on a timing race — classify `node --check` / `bash -n`-style syntax-only operands without executing
     or budget-sensitive denial.
   - `command -v dcg` / `command -v orca` denied as an unresolved wrapper although `heredoc.rs effective_shell_command`
     already models `-v`/`-V` as query-only: share wrapper semantics so query-only forms are allowed.
   - Distinguish "inspection incomplete" from an actual destructive match in the message and the decision path.
5. **Wording.** Trial summaries and docs say "observed safe in one sandboxed run", never "safe"/"proven".

Order: A, B, then C. C may ship in the same release as A+B; Tom installs once.

## Part D: Distill's full review (in scope after C)

Read `/Users/tom/dev/Projects/distill/work/feed-fix-qa/dcg-review.md` completely. Implement, in this order, with the
acceptance-matrix rows that belong to each (fixtures only, never real credential stores or services):

1. Shared invocation semantics (review §1): executable source vs syntax/data operand vs startup/preload source vs
   dynamic source, for the interpreters dcg already inspects; reuse `heredoc.rs effective_shell_command`'s query-only
   `command -v/-V` classification in `script_files.rs` (unshadowed builtin only; substitutions still inspected).
2. Outcome-specific results and diagnostics (§2): definite dangerous operation / unsupported-dynamic / analysis
   limit / review unavailable-or-cancelled, each with its own machine-readable code and remediation text; an analysis
   timeout gets a bounded slow path that parses only (never runs the candidate), cached by content+language+policy, and
   never turns into an allow.
3. Finite test inputs (§3): bounded resolution of explicit `node --test` operands, finite local globs, npm
   pre/main/post lifecycle scripts, static imports, preload options; dynamic cases stay inconclusive and fall back to
   the existing trial (no second trial implementation).
4. Part C already covers §4 (read boundary, owned loopback, runtime identity, honest labels); use the review's
   "Trial network/read boundary" and "Version trust" matrix rows as its acceptance tests, and add canaries for reads and
   delegated side effects (a disposable fixture host service must remain unchanged).

Out of scope until Tom decides: §5 long-running service capability, and §4 "observation versus enforcement" (running the
requested task itself under continuing confinement instead of trial-then-host). Keep trial-then-host, labelled honestly.

## Part E: enforcement instead of trial-then-host for finite commands (Tom approved 2026-10-12)

### F3 clarification: Node preloads and dependency findings (2026-10-13)

Node `--import`, `--require` and `-r` operands are module specifiers, distinct
from shell `source` filenames. Static resolution uses the selected package
script's directory, the nearest package self-reference and a bounded ancestor
`node_modules` walk. It binds the manifest and selected JavaScript file, honors
explicit exports and conditional insertion order for import/require, and uses
legacy main/index lookup when exports are absent. No interpreter or loader is
executed to resolve a name. See Node's [ESM resolution algorithm](https://nodejs.org/api/esm.html#resolution-algorithm-specification)
and [CommonJS file resolution](https://nodejs.org/api/modules.html#file-modules).

The bounded implementation leaves export wildcards/arrays, runtime-dependent
`module-sync` conditions, custom loaders, package imports/maps, native addons,
JSON preloads and symlinks inconclusive. Unresolved package names never become
static proof of safety. Manifest reads are capped at 256 KiB each and 1 MiB per
resolution; each ancestor walk has 64 steps, export maps have 256 entries and
conditional selection has 16 levels. Captured manifests and resolved sources
participate in the existing exact-version input evidence.

For a finite command on a host capable of continuing-confinement rewriting,
the hook may re-evaluate dependency findings in a dedicated scope. That scope
uses the runner's Git-derived writable and protected paths. JavaScript and
TypeScript dependency files beneath `node_modules` may defer dynamic cleanup
or bounded fallback findings to kernel enforcement. Literal filesystem targets
outside those writable paths still deny, including symlink escapes and protected
paths. Explicit child commands are evaluated normally; only bounded deletion
commands whose literal operands are writable can defer. Config blocks, dcg's
internal-command protection, credential writes, Git findings, and findings in
the command or project-owned test sources remain in force. Static analysis is
bounded and does not claim to resolve arbitrary dynamic targets; the unchanged
kernel profile enforces every actual access throughout execution.

This scope can only produce a confined replacement. It creates no ordinary
allow, observed-safe trial result, learned approval or exception. Failed scope
setup or re-evaluation preserves the original denial. Non-capable protocols,
disabled trials and observational trial evaluation never enter it. Workspace
boundaries are checked again by the actual runner before execution.

The pi-os acceptance must first submit the unmodified `npm test` command to the
real Claude Code hook, require `updatedInput` and a confined receipt, then run
that decoded request in the disposable CoW workspace. Direct runner acceptance
alone cannot detect a hook that rejects preloads before confinement. Require
real exit 0, CDP test success and completion within the existing 595-second limit.

Decision (Tom): for finite commands (test runs, `--check`/syntax checks, linters, builds whose outputs go to ignored
paths) dcg does not run a trial and then allow an unconfined host run. It runs the requested command ONCE, in the real
workspace, under continuing confinement, and the agent gets that real result.

- Mechanism: where the agent's hook protocol can rewrite the tool input, dcg rewrites the command to a confined
  invocation (e.g. `dcg run --confined --profile <id> -- <original>`), never through shell interpolation of the original.
  Claude Code: PreToolUse `hookSpecificOutput.updatedInput` (verify against current Claude Code hook docs). pi bridge
  (`integrations/pi/dcg-guard.ts`): rewrite the bash tool's command if pi's tool_call event allows mutation; otherwise keep
  trial-then-host there. Codex/OpenCode/others: support rewriting only where their protocol documents it; else keep
  trial-then-host with honest labels.
- Confinement profile (reuses Part C): writes only to the project's git-ignored paths, declared build/cache dirs and a
  per-run temp dir; tracked/non-ignored source files and `.git` unwritable; no reads of credential stores; loopback only to
  endpoints the run itself bound; no AppleEvents, no signals to others, the same Mach restrictions; process group
  supervision, CPU/time/output bounds; the run's environment is the agent's real environment minus credential/preload
  variables (document exactly which).
- Violations are enforced (denied by the kernel), reported to the agent in the result with the attempted operations, and
  never turned into an approval. Exit status of the command is passed through.
- Eligibility: only commands Part D's invocation semantics classifies as finite and self-contained (no detach/background,
  no watch mode, no service start). Everything else: Part B effect checks / learned Touch ID approvals, or the existing
  trial path where rewriting is unsupported.
- No learned entries are needed for confined runs (each run is enforced); do not record them as approvals.
- Tests: confined run of a fixture test suite that writes build output (passes, outputs in ignored dir); a fixture that
  writes a tracked file / outside the project / reads a fixture "credential" / connects to a pre-existing fixture
  listener (each blocked, reported, fixture victims unchanged); exit code passthrough; rewrite output for Claude Code and
  the pi bridge; unsupported protocol falls back unchanged; timeout/cleanup.
- Native acceptance on Tom's Mac: `npm test` in a temporary copy of pi-os runs confined once and reports its real result
  (pi-os no longer writes outside temp; commit 1f894f5 on pi-os branch feat/file-commands moved its fx cache).

Order: A, B, C, D, E. Same branch, separate commits, one REPORT; then Tom installs once.
