# dcg: review dialog correctness and polish (Part F2, after F1)

2026-10-13. Found in Tom's first live tom.10 dialog (Claude Code, node-harness,
`cd /Users/tom/dev/Projects/workOS-worktrees/pi-os-fft/node-harness && npm test`,
title "Unvollständigen Sandbox-Test prüfen"). Screenshot evidence was described
by Tom; reproduce with the `DCG_UI_PREVIEW` build. Start only after F1's report
is written. Branch `tjansn/dcg-dialog-polish` from the F1 branch head (or main if
F1 is not committed). No install, push or live hook/config change.

## Consent correctness (highest priority)

1. Contradictory approval scope. Details said, in English, "Runtime inputs or
   environment are not reproduced by the sandbox. This request requires
   one-time desktop review; no reusable approval will be recorded." and then,
   in German, "Die Freigabe gilt für diese exakte Befehls- und Projektversion
   bis eine geprüfte Datei geändert wird." Only one can be true. Every dialog
   must state the scope that will actually be recorded: one-time, exact
   version, learned filesystem entry, or confined (none). Derive the sentence
   from the same value that decides what is stored; add tests per scope.
2. The command is not visible. Tom approved without seeing `npm test`. Show the
   exact command (bounded, monospace, middle-truncated with full text in
   Details) and the working directory in the main body, not only in Details.
3. Language: the dialog is German. Translate the reason/explanation prose shown
   in the dialog; keep English only for the hook's agent-facing text. Use the
   proportional system font for prose and monospace only for commands, paths
   and script excerpts.

## Visual defects

4. The Touch ID glyph renders far too large (about 250 px), red, faded and
   clipped at the bottom left, overlapping "Finger auflegen". Likely cause:
   `makeAttempt()` (src/desktop_review.swift ~486, from Part A) creates a fresh
   `LAAuthenticationView(controlSize: .large)` with `view.frame =
   container.bounds` and autoresizing in a 48×48 container that may not be laid
   out yet and does not clip. Pin it with constraints to the container (or a
   fixed 48×48), clip the container, and verify for the first attempt and for
   each re-created attempt after a focus loss.
5. A thin black rectangular frame with square corners shows around the rounded
   glass panel (borderless window, `hasShadow = true`, NSGlassEffectView
   cornerRadius 28). Likely a shadow computed before the glass rendered:
   call `invalidateShadow()` after layout/resize and after each attempt swap;
   verify on macOS 27 with light and dark backgrounds.
6. When the window is not key, the glass panel turns flat grey with low text
   contrast. When paused (focus lost), show the "click to continue" state
   clearly (Part A's wording) rather than a dimmed panel with "Finger auflegen".

## Confined-run coverage

7. `cd <literal dir> && <finite command>` is the most common agent form, but it
   is excluded from Part E as a chain, so it fell back to the observational
   trial and a desktop review. Support a single leading literal `cd` (resolve
   and canonicalise the directory, reject expansions, substitutions, `-`,
   CDPATH effects and further chaining), so it is confined like the plain
   command. Keep every other chain excluded. Add hook-rewrite tests.

## Literal environment assignments (found by F1)

8. Under tom.10 the isolated validation form
   `env -i HOME=/tmp/x … PATH=/usr/bin:/bin … cargo test …` is a hard block
   (`[dcg:unsupported-dynamic]`, "command-local PATH requires desktop review"),
   yet no desktop review is offered, so dcg development can no longer validate
   itself. The message contradicts the outcome. Literal, fully spelled-out
   assignments are bound inputs, not dynamic ones: bind them into the reviewed
   identity and offer the review (or the trial/confinement path where
   eligible). Keep expansions, substitutions and inherited preload variables
   blocked. Make the message match what happens.

## Confined runs may use localhost (Tom's decision after F1)

9. F1 showed Seatbelt cannot exclude individual loopback ports. Tom chose
   (2026-10-13): **confined runs (Part E) may connect to any localhost port**,
   accepting the confused-deputy risk that Distill described, so local test
   suites that start their own servers (pi-os CDP tests) work. Scope:
   - Only Part E continuing confinement. Observational trials (Part C) keep
     deny-all outbound TCP, because a trial can lead to a reusable approval.
   - A trusted-config setting records the choice, e.g. `[trial]
     confined_loopback = "all" | "none"`; code default "none" (upstream-safe),
     and give Tom the one config line to add with `!` at install time.
     Automatically discovered project config must not be able to set it.
   - Non-loopback outbound stays denied. Other Part C/E read/write/Mach
     boundaries are unchanged.
   - The confined receipt and docs say plainly that localhost was open.
   - Tests: owned listener reachable under E with "all"; unreachable with
     "none"; a trial stays deny-all under "all"; external address denied.

Validation for F2: the installed dcg still blocks the `env -i` form until this
ships, so prepare the exact validation commands for Tom to run with `!`
(one line each, absolute paths, output to log files in a temp dir) and stop
when they are ready; do not reroute or split blocked commands.

## Acceptance

- Preview screenshots (light/dark, key/not key, first attempt and after a focus
  loss) attached to the report, plus the unit tests per approval scope.
- Same validation discipline as A–E/F1 (serial full suite, check/clippy/fmt,
  pi bridge tests, recounted totals).
- Report: /Users/tom/Documents/Codex/2026-10-09/k/work/dcg-dialog-polish-REPORT.md
  with a short plain-language summary for Tom.
# F3 frame follow-up (2026-10-13)

The active-state square outline is addressed at the compositing boundary:
the borderless window has no window-server shadow, and both material variants
sit inside the same 28-point rounded clipping view. A transparent 20-point
margin holds an explicit rounded Core Animation shadow. Its interior is cut
out so it does not darken the glass. macOS 26 glass used the clear style; the
existing readable paused-state fill and all Touch ID focus behavior are retained.

2026-10-14 (tom.18): Tom found the clear glass nearly see-through over dark
windows and without contrast over light ones. The panel now uses the regular
style under an 86 % window-background fill (`ReviewPanelContent`); a side-by-side
capture over white, black and multicolour backdrops in both appearances showed
clear and unfilled regular glass losing text contrast, and the fill keeping it.

The native focus helper asserts the rounded surface, clipping, padding and
disabled window shadow in every capture. Visual acceptance still requires the
eight light/dark active/paused screenshots; geometry assertions alone do not
prove that WindowServer rendered clean edges. Use `dcg-f2-preview.sh` with the
fresh F3 validation directory; it rebuilds the helper before capturing.
