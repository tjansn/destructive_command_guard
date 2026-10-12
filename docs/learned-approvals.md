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

`cargo test desktop_review -- --test-threads=1` includes a UI-less Swift controller
suite with fake biometric evaluators and delayed replies. The native acceptance entry
in `tests/desktop_review_focus_acceptance.swift` uses the production window and real
LocalAuthentication, brings Orca forward twice, and closes without approving or
executing a command. Compile it with `src/desktop_review.swift` and
`-D DCG_UI_PREVIEW`; it requires an interactive macOS session with Orca running.

On 2026-10-12 the native acceptance entry compiled, but the installed guard denied
launching the temporary helper because its `/tmp` path contains a symlink. It was not
rerouted or bypassed. Therefore the automated controller behavior is verified, while
live focus recovery with Orca remains an operator acceptance step before installation.
