# dcg: sandboxed trial runs for inconclusive commands (design)

Status: approved by Tom 2026-10-12, to be implemented in the dcg fork
(`/Users/tom/Documents/Codex/2026-10-09/k/work/dcg-fork`, github.com/tjansn/destructive_command_guard).

## Why

Tom: "DCG thinks sth shouldn't be done, then needs a way to really test that. like in this case, it should be able to
run the script in a secure sandbox, check what actually happens, then determine safety again. if safe, approve and
whitelist this exact version of the script. if unsafe explain why, so you can check and make adjustments or contact me
for clarification."

The trigger case: with `Inspect script files: true`, `cd /Users/tom/dev/Projects/pi-os/node-harness && npm test` is
denied by rule `heredoc.script_files.unverified` ("test/watch runners select additional sources dynamically"), and
`host-macos/scripts/refresh-install.sh` by the same rule ("package directory/workspace options require review"). These
are not destructive; dcg just cannot prove it statically. Agents (Claude Code, Codex, pi) are blocked and the user has
to run such commands by hand.

## Decisions (binding, from Tom)

1. **Wait in place.** The agent's command waits while dcg runs the trial (a test suite can take 1–2 minutes). The
   hook timeouts dcg installs are raised so the trial fits (see §8). Later runs of an approved version are instant.
2. **Network off in the trial, localhost only.** A trial that needs the internet (npm install, downloads) is
   *inconclusive* and goes to the existing desktop review (Touch ID), showing what it tried.
3. **Approval lasts until any file the run read changes.** Exact-version approval per project, no time expiry.

## 1. When a trial runs

- Only for **inconclusive** verdicts: `heredoc.script_files.unverified` and any other "inspection incomplete /
  unverifiable" result the evaluator produces for file-backed scripts, package scripts, test/watch runners and
  similar. Enumerate them in code and test the list.
- **Never** for definite destructive matches (`core.filesystem:*`, `core.git:*`, …). Those keep today's deny /
  desktop review. A trial never downgrades a definite match.
- Not for commands that need a TTY or user interaction; not when `trial.enabled = false`.
- Before running a trial, look up the verified-version store (§5). A matching approved version is allowed at once.

## 2. The trial run (macOS)

1. **Workspace clone.** Find the project root (the git work-tree root containing the cwd, else the cwd). Clone it
   copy-on-write with `clonefile(2)` (directories clone recursively on APFS) into
   `$TMPDIR/dcg-trial-<id>/project`. If clonefile is unavailable (not APFS, cross-volume), fall back to a plain
   recursive copy with a size cap; above the cap the trial is inconclusive. The command's cwd maps into the clone.
2. **Isolated home and environment.** `HOME=$TMPDIR/dcg-trial-<id>/home` (empty). Start from an **allowlisted**
   environment (PATH, LANG, LC_*, TERM, TMPDIR → a trial temp dir, USER, LOGNAME, SHELL, NODE_OPTIONS, CI=1, plus
   tool-specific non-secret variables you justify), never the full parent environment. No `*_TOKEN`, `*_KEY`,
   `*SECRET*`, `AWS_*`, `GITHUB_*`, `OPENAI_*`, `ANTHROPIC_*`, SSH agent socket, etc.
3. **Sandbox profile** (generated SBPL, run with `/usr/bin/sandbox-exec -p`; verify it still works on macOS 26/27 and
   document the fallback if it does not):
   - `(allow default)` as the base, then:
   - `(deny file-write* …)` everywhere except the clone, the trial home, the trial temp dir, `/dev/null`, `/dev/tty*`,
     `/dev/dtracehelper`; covers unlink, rename, create, mode/xattr changes and truncation.
   - `(deny network*)` except loopback (`localhost`, `127.0.0.1`, `::1`) and unix sockets inside the trial dirs.
   - `(deny appleevent-send)`, Keychain/SecurityServer mach lookups, `user-preference-write`,
     `(deny signal (target others))` (no signals to processes outside the trial's process group).
   - Tag every deny so it can be attributed: `(with message "dcg-trial-<id>")` if supported; otherwise attribute by the
     trial's process-tree PIDs.
   - Inherited by all children (sandbox-exec semantics); verify with a child-process test.
4. **Limits.** Wall-clock timeout (`trial.timeout_secs`, default 600 s), kill the whole process group on timeout,
   CPU/memory limits via `setrlimit` where reasonable, output captured with a byte cap (kept only for the verdict
   summary, never logged in full).
5. **Run** the original command string through the same shell the agent would use (`/bin/zsh -c` / `bash -c` as the
   hook payload implies), cwd mapped into the clone, stdin closed.
6. **Clean up** the trial directory afterwards (always, also on panic/timeout), except when `trial.keep_artifacts`
   is set for debugging.

## 3. Observation

- **Denied operations**: read the sandbox violation reports for this trial (unified log,
  `log show --predicate 'sender == "Sandbox"' --start <t0>` / `log stream` during the run, filtered by the trial tag
  or PIDs). Parse operation (`file-write-unlink`, `file-write-create`, `file-write-data`, `file-write-mode`,
  `network-outbound`, `signal`, `appleevent-send`, …) and target (path, host:port).
- **Clone diff**: manifest (path, size, mtime, hash for tracked files) of the clone before and after. Classify:
  - deleted **tracked** files (git-tracked or pre-existing non-ignored) → destructive evidence;
  - modified tracked files → needs review (formatters legitimately do this);
  - new or changed files only in ignored/build/cache/temp locations (per `.gitignore`, `node_modules/.cache`,
    `dist/`, `build/`, `target/`, `.build/`, `__pycache__/`, tool caches) → fine.
- Exit status is **not** a safety signal: failing tests are safe.

## 4. Verdict

| Observation | Verdict | What dcg does |
|---|---|---|
| No denied writes/signals/AppleEvents, no network attempts, only allowed writes (ignored/build/temp) | **safe** | Record a verified version (§5), allow the real command now |
| Denied write/unlink/rename outside the workspace, signals to other processes, AppleEvents, or tracked files deleted in the clone | **unsafe** | Deny with an explanation (§6) |
| Network attempted (denied), timeout, tracked files modified, trial could not start (no clone, sandbox unavailable), TTY needed | **inconclusive** | Existing desktop review (Touch ID) with the trial summary; approve → record this exact version as verified-by-user (§5); deny → deny with the summary |

The real command still passes through every other dcg rule afterwards; a trial only resolves the
"unverified" verdict, nothing else.

## 5. Verified-version store ("this exact version")

- Fingerprint (SHA-256) over: the normalized command string; the canonical cwd relative to the project root; the
  project root path; the resolved executables (realpath + content hash or size+mtime of the first program and of
  any interpreter/script dcg already resolves); and **the files the run read inside the project root**.
- "Files the run read": record them if the platform allows it without root (prefer a reliable mechanism; document
  what you used). If file-read tracking is not reliably possible without elevated privileges, fall back to the
  manifest of all **non-ignored project files** (git ls-files -co --exclude-standard, with the content hash per file
  cached by size+mtime) — i.e. any change to the project's sources re-verifies. Document which mode is used and keep
  hashing under ~200 ms for a repo like pi-os (use the size+mtime cache).
- Store entries in dcg's allowlist storage (new entry kind, e.g. `verified_trial`) with: fingerprint, project root,
  command, created_at, verdict source (`trial` or `user-review`), and a short trial summary. No expiry; an entry
  simply stops matching when the fingerprint changes. `dcg allowlist list` shows them; `dcg allowlist remove` and
  `prune` work on them.
- Lookup happens before a new trial: matching fingerprint → allow at once (with a short "verified by trial on
  <date>" note in the hook output).

## 6. Explanations (unsafe / inconclusive)

Concise, actionable, content-limited text in the hook denial reason and in the desktop review, e.g.:

```
dcg ran `npm test` in a sandboxed copy of /Users/tom/dev/Projects/pi-os and it tried to:
  • delete ~/pi-os-dcg-probe (blocked by the sandbox)
  • connect to registry.npmjs.org:443 (blocked: no network in trials)
Not run. Adjust the command or ask the user. Review: dcg trial show <id>
```

- Paths under the user's home shown with `~`; at most N items per category with counts; no file contents, no
  environment values, no output beyond a short tail when it explains the failure.
- `dcg trial show <id>` prints the stored summary of a recent trial; `dcg trial run -- <command>` runs a trial
  manually (useful for the user and for agents to pre-verify).

## 7. Configuration

`config.toml` / `config.schema.json`:

```toml
[trial]
enabled = true
timeout_secs = 600
network = "localhost"      # only value for now; documented as such
max_copy_bytes = 2_000_000_000   # fallback copy cap when clonefile is unavailable
keep_artifacts = false
```

## 8. Hook integration and timeouts ("wait in place")

- The hook (Claude Code PreToolUse, Codex pre_tool_use, OpenCode plugin, the pi `dcg-guard` bridge via
  `--desktop-review --agent pi`) runs the trial synchronously and answers when it is done.
- The installer (`dcg install` / self-repair) sets a hook timeout that fits `timeout_secs` + margin for every agent
  that supports one (Claude Code `settings.json` hook `timeout` in seconds; Codex hooks.json; OpenCode). Document the
  agent-side tool timeouts that also apply (Claude Code's Bash tool timeout) and print a hint when the trial may
  exceed them.
- The pi bridge in `~/.pi/agent/extensions/dcg-guard.ts` uses a 140 s timer: document the needed change (raise to
  `timeout_secs` + margin) in the docs/integrations for pi; do not edit the user's home files from the repo.
- While a trial runs, print a single progress line to stderr (agents surface it), e.g.
  "dcg: verifying `npm test` in a sandboxed copy (≤ 10 min)…".

## 9. Tests (must pass; run them)

All tests use temporary directories only. Never touch the user's real files, never use the network.

1. Unit: trigger list (unverified → trial; definite destructive → never), fingerprint stability and invalidation
   (edit a read file → mismatch; touch without change → match via hash), env allowlist (no secrets survive), SBPL
   generation (paths escaped, loopback only), violation-log parsing from fixture log lines, clone-diff classification,
   verdict table (each row), explanation rendering (home → `~`, caps, no contents).
2. Integration on macOS (skip with a clear message elsewhere):
   - a safe script that writes only to `build/` in its project → safe, verified entry stored, second invocation allowed
     instantly without a trial;
   - a script that tries `rm -rf <tmp-outside-dir>/victim` (a temp dir outside the project, created by the test) →
     unsafe, explanation names the path, **the victim still exists**;
   - a script that deletes a tracked file in its project → unsafe (the real project is untouched, only the clone);
   - a script that runs `curl https://example.com` → inconclusive (network), nothing reached the network;
   - a script that sleeps past a short timeout → inconclusive, process group killed, trial dir cleaned up;
   - a script that tries to signal a process outside its group → unsafe;
   - editing a file the safe script reads → next invocation runs a new trial.
3. End-to-end through the hook protocol (JSON on stdin, like the existing hook tests): an "unverified" `npm test`-style
   command in a fixture npm project → trial → allow; the same with a malicious test script → deny with explanation.
4. `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` all green; existing tests unchanged.

## 10. Deliverables

- Code (new modules, e.g. `src/trial.rs`, `src/trial_profile.rs`, verified-version support in the allowlist store,
  evaluator/hook integration), config + schema, CLI (`dcg trial run`, `dcg trial show`), docs (README section,
  `docs/` page with this design, CHANGELOG entry, integration notes for timeouts), tests above.
- One feature branch, small reviewed commits, no push to `main` without Tom.
- A short final report: what works, measured trial overhead for the pi-os `npm test` case (clone time, trial
  duration), limits (what file-read tracking mode was used, sandbox-exec status), and how to roll it out (rebuild,
  `dcg install` to update hook timeouts).

## 11. Honest limits (state them in the docs)

- One observed run proves the behaviour of that run. Scripts can branch on environment, time or network. Exact-version
  fingerprints, no network, an isolated home and the workspace clone keep the gap small; the real run still goes
  through all of dcg's rules.
- `sandbox-exec` is deprecated by Apple; if it stops working, trials report "sandbox unavailable" (inconclusive) and
  dcg falls back to today's behaviour plus desktop review.
