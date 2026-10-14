# Desktop review, effect checks, and learned approvals

The approved specification is [learning-and-dialog.md](design/learning-and-dialog.md).

## Focus changes during Touch ID

Losing focus cancels the current biometric attempt, without declining the request.
The floating dialog remains visible across Spaces and asks the user to click it.
One focus loss within 1.5 seconds of appearance may reactivate the dialog automatically;
subsequent losses wait for the user. Returning to the key window creates a fresh
`LAContext`, with no recent-unlock reuse or password fallback. Replies from cancelled
attempts are ignored. A successful reply is accepted only while DCG is active and its
window is visible and key. The original 120-second deadline continues across attempts;
Escape, Ablehnen, closing, and timeout still deny.

The main panel shows the command and cwd in bounded, middle-truncated monospace
fields. Details retain the full bounded command. Prose is German and uses the system
font; paths, commands and script excerpts use monospace. A single typed approval
scope supplies both the displayed sentence and the decision to store an approval:

- `one_time`: this invocation only; no reusable entry.
- `exact_version`: exact command and project inputs; changes require review again.
- `learned_filesystem`: command, rule and unchanged filesystem operands.
- `approved_scripts`: command in this project until a reviewed script changes
  (see [Approved scripts](#approved-scripts)).
- `confined`: one execution under continuing confinement; no stored approval.

Learning storage failure cannot silently convert a consented learned entry into a
one-time approval. The request stays blocked. Changes to dcg remain one-time.

Each fresh Touch ID view is constrained to a clipped 48×48 container. Focus loss
removes the cancelled view and shows **Prüfung pausiert** with a click-to-continue
instruction and opaque readable backing. Layout, resizing and attempt changes
invalidate the window shadow. Native light/dark acceptance is still required.

`cargo test desktop_review -- --test-threads=1` includes a UI-less Swift controller
suite with fake biometric evaluators and delayed replies. The native acceptance entry
in `tests/desktop_review_focus_acceptance.swift` uses the production window and real
LocalAuthentication, brings Orca forward twice, checks first/recreated glyph bounds,
and captures key/paused states before closing without executing a command. Compile
it with `src/desktop_review.swift` and
`-D DCG_UI_PREVIEW`; run with `light|dark` and an existing absolute temporary
screenshot directory. It requires an interactive macOS session with Orca running,
available Touch ID and screen-recording permission. Do not authenticate during the
preview. Eight screenshots (four per appearance) must be inspected for clipping,
contrast and the rectangular shadow; layout assertions alone cannot prove these.

On 2026-10-12 the native acceptance entry compiled, but the installed guard denied
launching the temporary helper because its `/tmp` path contains a symlink. It was not
rerouted or bypassed. Therefore the automated controller behavior is verified, while
live focus recovery with Orca remains an operator acceptance step before installation.

## Approved scripts

When script-file inspection cannot fully verify a command
(`heredoc.script_files:unverified`, or `core.filesystem:tar-options-unresolved` for
a script whose tar options are only known at runtime) and you approve it with Touch
ID, dcg remembers the approval as `approved_scripts` (dialog title **Skripte prüfen
und merken**). A tar helper dcg identified but cannot verify
(`core.filesystem:tar-exec-unverified`: `--to-command`, checkpoint actions,
compression programs, volume/rmt scripts) is never covered, even inside an approved
script. Existing allowlist and policy entries for `tar-exec-unverified` also cover
`tar-options-unresolved` unless an entry names that rule itself.

Long scripts are excerpted in the dialog: each shows its path, line count and a
SHA-256 prefix, and a note says how many lines are hidden. The approval still binds
every byte of every reviewed script. The exact command is always shown in full; if
it alone does not fit, no dialog is offered.
The approval binds:

- the exact command text and its canonical working directory in the project;
- the full content and permissions of every script file inspection resolved for
  it: the scripts shown in the dialog plus every literal input path;
- the executables the command resolves to, including the content of executables
  inside the project;
- the values of inherited preload variables (`NODE_OPTIONS`, `BASH_ENV`, `DYLD_*`,
  `LD_*`, `PYTHONPATH`, …).

Edits to other project files do not ask again, and neither sandbox
reproducibility nor `[trial] enabled` affects it. Every hook for the project
reuses it, including one without `--desktop-review`. Changing any bound script,
its permissions, the command or the directory asks again. An input that is missing
at review time cannot be remembered, so a file created later never inherits the
approval. Definite destructive findings are evaluated first on every request and
are never covered.

Limit: only files dcg resolved are bound. Code a script loads dynamically (for
example `import(process.env.MODULE)`) is not part of the approval and can change
without a new review.

`dcg allowlist list` shows `approved_scripts:<fingerprint>` entries;
`dcg allowlist remove approved_scripts:<fingerprint>` revokes one, and
`dcg allowlist prune` removes approvals whose scripts changed or disappeared.
Sandbox-observed (`trial`) entries remain exact-version entries.

## Filesystem evidence and remembered approvals

Literal, single-segment system `mv`/`cp` commands can resolve the sensitive-source
rule when both operands establish a single regular-file replacement or creation.
Symlinks (including ancestors), shell expansion, relative operands, unknown options,
custom executables and inherited startup/preload context cannot supply that proof.
The other rules are evaluated again before allowing the command. Recursive removal
never gets an automatic effect approval; the dialog reports bounded file/byte counts
and Git tracking instead.

A Touch ID approval for a definite filesystem rule can be remembered as
`learned_filesystem`, with `source = user-review`. Its key binds the raw command,
canonical cwd, system executable, rule and every operand's identity and content.
Small files are hashed; files larger than 64 MiB retain their full metadata identity.
Directory manifests have 10,000-entry, 64-level and 64-MiB total content-hash limits.
Failure to obtain complete evidence leaves a one-request review. Operands are checked
again after the dialog and immediately before a learned approval is used.

Entries have no expiry. `dcg allowlist list` includes them; `remove` revokes their
fingerprint and `prune` removes changed or missing versions. Only the trusted user
store records these approvals; project allowlists cannot manufacture entries.

DCG executables, state and managed hook configurations always require review, including
parent directories containing those files. An unreadable or oversized parent tree is
also excluded from learning. The dialog says **Änderung an dcg selbst – wird nie
gemerkt**. Approving such a request never records a reusable filesystem entry.
