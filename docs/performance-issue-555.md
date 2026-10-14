# Hook latency investigation: issue #555

Paired fresh-process measurements of the first integrated stage reduced the
300-line Python median from 108.3 to 65.4 ms with history disabled and from
97.7 to 55.7 ms with a small history database. Large quoted-data and
commit-message cases also used substantially less CPU. This document records
the measured binaries, raw observations, phase attribution, security checks,
and the remaining storage and tail-latency limits.

## Problem and scope

[Issue #555](https://github.com/Dicklesworthstone/destructive_command_guard/issues/555)
reports fresh-process Claude Code `PreToolUse` hook latency in DCG 0.15.3. On the
reporter's loaded eight-core Linux host, median wall times were approximately
84 ms for `ls -la`, 274 ms for a 40-line Python heredoc, 563 ms for a 300-line
Python heredoc, and 146 ms for a compound command. The reported history contained
247,625 commands over 30 days, with roughly 1.0-second p95, 2.2-second p99, and a
5-second maximum. Those observations motivate the investigation; they are not
universal timings or a controlled attribution to AST analysis or history I/O.

This work measures the complete hook process, attributes work inside the hook,
and removes repeated analysis without reducing the circumstances that require
deep inspection. Quoted executable Python is still executable Python. Shell
substitutions, nested interpreters, pipelines, uncertain source ownership, and
incomplete syntax retain their security checks. Completing less analysis and
silently allowing a command is not a performance improvement.

The inspected incumbent is source commit
`00a1c8b5325544568758766e45649215cb88f350`. It includes the separate temporary-root
deletion fix; that fix is not evidence that the latency report was resolved.

## Three measurements answer different questions

| Measurement | What it measures | Principal limitation |
|---|---|---|
| Paired fresh hook processes | User-visible process wall time and child CPU for incumbent and candidate | Includes process creation, executable loading, scheduling, protocol work, and synchronous shutdown |
| `DCG_PROFILE=1` on a separate invocation | Instrumented phase wall times and call counts inside hook mode | Instrumentation adds work; worker wall time overlaps the hook thread |
| Criterion and paired in-process oracles | Specific AST, extraction, evaluation, and stdin-provenance costs | Does not reproduce every fresh-process, history, or storage cost |

Use uninstrumented paired processes to establish an improvement. Use profiles
and in-process comparisons to explain it. Keep the raw observations, binary
identities, source snapshots, compiler identity, build profile, and host/load
conditions together. A dirty candidate can embed the same Git SHA as an
incumbent, so the embedded SHA alone does not identify its compiled contents.

## Hook phase diagnostics

Set `DCG_PROFILE` to exactly `1` for a hook invocation. For example, this sends
command text to DCG for inspection; the fixture command is not executed:

```sh
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}' |
  DCG_PROFILE=1 /absolute/path/to/dcg --agent claude-code \
    > /tmp/dcg-hook.stdout 2> /tmp/dcg-hook.stderr
```

The hook preserves its normal stdout protocol and appends one stderr line
beginning with `DCG_PROFILE ` followed by a JSON object. Ordinary denial
diagnostics may also appear on stderr. Unset or `0` leaves profiling disabled.
Robot mode suppresses profile output to preserve its stderr-silent contract.
The profile contains timings and fixed phase names, without command text or
paths. The implementation and protocol regressions are in
[`src/perf.rs`](../src/perf.rs), [`src/main.rs`](../src/main.rs), and
[`tests/profile_hook.rs`](../tests/profile_hook.rs).

### Schema version 1

| Field | Meaning |
|---|---|
| `schema_version` | `1` |
| `clock` | `"monotonic_wall"`; these are wall durations, not CPU measurements |
| `scope` | `"hook"` |
| `total_ns` | Interval from hook profiling initialization through hook shutdown |
| `uninstrumented_ns` | Main-thread interval not attributed to an exclusive phase |
| `phases` | Aggregated main-thread phase measurements |
| `worker_phases` | Separately aggregated measurements from attached analysis workers |

Each phase row contains four unsigned nanosecond/count fields:

| Row field | Meaning |
|---|---|
| `calls` | Number of phase entries |
| `completed_calls` | Number of phase exits included in the duration sums |
| `elapsed_ns` | Sum of completed inclusive durations, including nested phases |
| `exclusive_ns` | Sum after subtracting nested phases on the same thread |

Both maps currently emit all 24 phase keys. A phase that was not visited has
zero counts and durations.

| Phase key | Operation |
|---|---|
| `input_read` | Waiting for and reading stdin |
| `request_parse` | UTF-8/request decoding and JSON parsing, including fallback parsing |
| `config_load` | Configuration loading and invoking-agent detection |
| `request_setup` | Request setup, allowlists, and enabled-pack indexes |
| `self_heal` | Hook registration verification or repair when enabled |
| `evaluation` | Safety evaluation, including recursive evaluation |
| `normalization` | Shell normalization and preparation of data-masked views |
| `heredoc_detect` | Detection of constructs requiring embedded-source inspection |
| `heredoc_extract` | Extraction of executable and data content |
| `pattern_evaluation` | Enabled pack evaluation and semantic checks |
| `pattern_selection` | Existing keyword and semantic selection of candidate packs |
| `pattern_preparation` | Source views and segment preparation for selected packs |
| `pattern_rules` | Compilation and evaluation of selected pack rules |
| `shell_tokenization` | Tokenization used by normalization and semantic checks |
| `shell_segmentation` | Execution-domain and substitution segmentation |
| `heredoc_masking` | Proof and masking of non-executable heredoc data |
| `regex_compile` | First-use regex compilation and mandatory-prefix syntax proofs |
| `regex_match` | Matching a compiled shell pack regex after any proven prefix rejection |
| `ast_parse` | Parsing source into a tree-sitter AST |
| `ast_pattern_compile` | Compilation of ast-grep structural patterns |
| `ast_match` | AST matching on a worker, or waiting for analysis on the hook thread |
| `history_init` | Resolving/opening history storage and starting its writer |
| `history_record` | Constructing, redacting, and queueing a history entry |
| `history_flush` | Explicit flushes and the bounded wait during writer shutdown |

### Accounting and interpretation

Use **main-thread exclusive durations** to attribute shares of `total_ns`.
Inclusive durations overlap and recursive calls can make their sum exceed the
hook interval. For ordinary non-saturated measurements, the sum of main-thread
`exclusive_ns` plus `uninstrumented_ns` equals `total_ns`. Request decoding and
JSON parsing can contribute separate entries, so `request_parse.calls` need
not equal the number of requests.

Worker durations belong to a separate map because they overlap the main
thread's wait. Do not add them to the main-thread total or describe them as
CPU usage. Multiple workers can also overlap each other. A worker row with
`calls > completed_calls` identifies work still in flight when the diagnostic
was emitted. Its elapsed fields contain completed calls only; zero elapsed
time on such a row does not establish that the unfinished work was cheap.
Open main-thread phases are closed at diagnostic emission, including paths
that exit early.

The profiled interval starts after CLI dispatch. It excludes OS process
startup and CLI setup, includes stdin waiting in `input_read`, and includes
synchronous history setup/record construction and the writer's bounded
shutdown wait. Serialization and writing of the diagnostic occur after the
reported endpoint. The SQLite writer's complete CPU activity is not a
separately attributed worker phase; process CPU and the controlled history
profiles provide complementary evidence.

Disabled instrumentation does not read a clock, acquire a profiling lock, or
allocate at an instrumented call site. Enabled instrumentation necessarily
changes the work being measured. In particular, thousands of tiny spans can
produce material overhead; interpret their call counts alongside separate
uninstrumented timings.

## Paired fresh-process reproduction

Build the untouched incumbent and candidate with the repository's pinned Rust
toolchain and the same shipping release profile, using `cargo build --release
--locked` in their respective source snapshots. Preserve the resulting binaries
at distinct paths before reusing a target directory. Finish builds and other
controlled background work before collecting final measurements.

[`scripts/perf_baseline.py`](../scripts/perf_baseline.py) has a separate paired
investigation mode:

```sh
python3 scripts/perf_baseline.py \
  --bin /absolute/path/to/candidate/dcg \
  --compare-bin /absolute/path/to/incumbent/dcg \
  --runs 30 --warmup 3 \
  --history-profiles disabled,enabled,seeded,locked \
  --history-seed-rows 247625 \
  --output /tmp/dcg-issue-555-comparison.json
```

Omitting `--compare-case` selects all 16 timed command shapes. Repeating that
option selects an explicitly recorded subset for a diagnostic run; for example,
`--compare-case short_ls --compare-case python_300_safe`. The two line counts
refer to the safe Python body; destructive-start/end variants add two lines.
These are controlled reproductions of the reported shapes, not a claim to
possess the reporter's complete workload.

The default history selection is `disabled,enabled`; the explicit command
above runs all four profiles. The artifact kind is
`paired_heredoc_investigation`, with `schema_version: 1`. Use its recorded case
IDs and profile IDs when processing results rather than assuming a fixed
number of rows.

### Earlier comparison interface and retained evidence

The [earlier published comparison](../perf/baselines/2026-10-12-issue-555-comparison.json)
and its [baseline notes](../perf/baselines/README.md) remain unchanged. That
artifact has kind `issue_555_interleaved` and measures an isolated
stdin-provenance change: 11 shapes across history disabled, enabled, and
`contended`, with 25 measured pairs and five warmups. It predates the broader
AST, redaction, and profiling work covered here. Its numbers must not be
reported as measurements of the final integrated candidate.

The current `--compare-bin` interface uses the 16-case runner documented below
and calls the writer-lock profile `locked`. Its default profile selection and
JSON shape differ from that earlier experimental interface. Structured phase
probes use `DCG_PROFILE=1`; the older `DCG_LOG=dcg_perf=debug` trace remains a
separate diagnostic. Consumers of the retained artifact should continue to
interpret its original schema. The absolute-gate case list and the
`hook_latency` Criterion group retain the earlier 1/40/300-line scaling cases.

### Current comparison cases

| Case IDs | Shape | Required timed verdict |
|---|---|---|
| `short_ls` | `ls -la` | Allow |
| `compound_pipeline` | Ordinary compound command with a pipeline | Allow |
| `python_40_safe`, `python_300_safe` | Quoted executable Python heredoc with assignments and a final print | Allow |
| `python_40_deny_start`, `python_300_deny_start` | Python deletion before the ordinary body | Deny |
| `python_40_deny_end`, `python_300_deny_end` | Python deletion after the ordinary body | Deny |
| `quoted_data_40`, `quoted_data_300` | Quoted `cat` data containing shell-looking text and awkward quotes | Allow |
| `commit_message_40`, `commit_message_300` | The same quoted data inside a commit-message command substitution | Allow |
| `nested_inline_interpreter` | Bash heredoc invoking an inline destructive Python program | Deny |
| `expanding_data_substitution` | An executable substitution inside unquoted heredoc data | Deny |
| `data_pipe_to_shell` | Quoted producer data piped into Bash | Deny |
| `unterminated_executable_heredoc` | Destructive Python with a missing terminator | Deny |

Every invocation starts a new DCG process. JSON construction occurs before
the timer; wire verification occurs after it. The runner alternates both
incumbent/candidate order and full/bypass order, retaining adjacent pairs and
all raw observations. Warmup invocations can warm OS/file caches but do not
turn subsequent invocations into a persistent DCG process with a warm matcher.

The runner creates isolated HOME/config/work directories, scrubs ambient
`DCG_*` settings, disables hook self-healing, and keeps fixture text away from
a shell evaluator. It records the effective DCG environment, binary hashes
before/after, embedded compiler/source identity, current repository state,
and host/load information. Check `same_toolchain` and preserve the actual
build commands; this comparison mode is not a source-bound release certificate.

### History profiles

Each binary receives a separate isolated history database. The initialization
hook creates the real schema before history-specific measurements.

| Profile | Setup | Question answered |
|---|---|---|
| `disabled` | History disabled | What costs remain without history construction and persistence? |
| `enabled` | Fresh history database, normal writer | What does ordinary recording add on this storage environment? |
| `seeded` | 247,625 synthetic benign rows inserted through the real schema/index/FTS triggers | Does database cardinality materially change recording cost? |
| `locked` | A separate SQLite connection holds `BEGIN IMMEDIATE` for the profile | How does the hook behave with a competing database writer? |

The seeded count is in addition to the initialization row. Its rows use a
current timestamp and repeated benign command text. This exercises cardinality
and the real database structures, not the reporter's command distribution,
30-day retention pattern, fragmentation, or secret distribution. No user
history is copied. The artifact records row counts before/after, journal mode,
database location/size, and whether a writer lock was held.

The lock experiment models SQLite writer contention. It is not a complete
simulation of slow storage, filesystem synchronization, memory pressure, or
the reporter's loaded host. Record the backing filesystem and available CPU
conditions when reporting results. History remains best-effort telemetry;
storage behavior must not weaken the security verdict.

### CPU, wall, and bypass deltas

For supported Unix hosts, child CPU is the difference in `RUSAGE_CHILDREN`
user-plus-system time around each sequential invocation, including DCG's
threads. It excludes CPU used by unrelated builds or by the Python harness.
On platforms without Python's `resource` module, CPU fields are unavailable;
wall and profile measurements remain available.

Wall time includes descheduling, I/O waits, process creation, and the harness's
wait/capture boundary. A large wall increase with little CPU increase suggests
waiting, but does not by itself identify storage as the cause. CPU and wall
also need not subtract into a meaningful nonnegative I/O duration because
multiple threads can execute concurrently.

`DCG_BYPASS=1` is a matched process/protocol floor using the same payload and
environment. It is not a pure measurement of OS spawn time. For each binary,
`full - bypass` estimates additional evaluator-related work at that boundary.
The artifact also records signed `incumbent - candidate` deltas for wall and
CPU; positive values indicate a reduction. Negative paired observations are
retained. Do not replace paired differences with a subtraction of unrelated
percentiles, or discard an inconvenient negative sample.

### Invalid samples and existing gates

Every timed invocation must have the expected exit status, stdout verdict,
and stderr behavior. A silent allow for a destructive fixture, an unexpected
`ask`, a process timeout, invalid JSON, or an invalid protocol result stops the
comparison with ERROR. The artifact retains partial samples, the failed
binary/mode/iteration, and failed wire output. It does not publish that failed
case as a successful timing summary. A phase probe is a separate untimed
process and also has its wire result checked; an old binary without profiling
is recorded as unsupported.

The known incumbent nested-heredoc silent allow is an **untimed security
control**. Its actual incumbent verdict is retained as a gap, while the
candidate must deny it. It supplies no favorable baseline latency. The more
extensive precise-rule regressions cover here-strings and receiver variants
separately.

The existing absolute gate remains separate and cannot be combined with
`--compare-bin`. It requires clean source/compiler binding, the shipped
positive hook budget, and at least 59 measured samples for its 95/95 one-sided
binomial tolerance rule. Its default margin is 50%; margins above 60% are
rejected. Its 20-case inventory includes the matched bypass control and 19
evaluated cases, preserving the ten additions for executable/data/destructive
heredocs at 1/40/300 lines and an ordinary compound command. Generate the gate
artifact outside the repository, using the budget read from
[`src/perf.rs`](../src/perf.rs), as specified in
[`AGENTS.md`](../AGENTS.md). Investigation PASS means the requested observations
and security controls completed; it does not assert an absolute latency bound
or that every case became faster.

## Preliminary attribution and implemented changes

### Repeated multiline shell processing

The [retained preliminary development profile](../perf/baselines/2026-10-12-issue-555-development-phase2-profiles.json)
contains a history-disabled `python_300_safe` profile with **52,133 completed
main-thread shell tokenizations** and 325 completed shell segmentations. Its
wire verdict was allow. The profile preceded the stdin-context optimization
and the final regex phase enrichment. These counts identify repeated work;
the instrumented durations are not final end-to-end improvement evidence.

Inspection connected the repeated work to stdin provenance queries in the
filesystem evaluator. For every segment, the legacy path could split the
whole command and tokenize preceding segments while asking whether an earlier
`exec` redirected stdin. On multiline input this repeated prefix work grows
quadratically even when the source contains neither an `exec` nor a pipeline.

`RmStdinContext` now computes two necessary source facts once and shares them
across queries: whether the exact source contains `|`, and whether it contains
both contiguous `exec` and `<`. The existing pipeline and prior-`exec` parsers still decide
the answer whenever their prerequisite is present. Direct pipeline handling
is preserved before the dialect-specific checks. This follows the current
parser's exact raw-token `exec` recognition; changing that parser to decode
additional spellings requires revisiting the prerequisite. Differential tests
retain the unfiltered algorithm and compare source offsets and dialects.
See [`src/packs/core/filesystem.rs`](../src/packs/core/filesystem.rs) and its
call site in [`src/evaluator.rs`](../src/evaluator.rs).

The byte keyword search also uses `memchr`/`memchr2` to locate possible first
bytes before applying the unchanged ASCII-insensitive comparison. It retains
the earliest match, byte offsets, empty-needle behavior, and arbitrary-byte
semantics. Large masked data bodies can therefore avoid a byte-by-byte scan
for every keyword without excluding any candidate the old search would find.
Differential tests cover all byte values, Unicode input, offsets beyond the
input, and densely repeated near-matches in [`src/packs/mod.rs`](../src/packs/mod.rs).

### Cold safe-regex preparation

The first integrated profile identified regex preparation as the largest
remaining exclusive phase for a 300-line Python body. The next optimization
targets the 32 anchored backtracking safe patterns in `core.filesystem`.
Each opts into a lazy proof of its mandatory literal prefix using the
`fancy_regex::Expr` syntax tree. A mismatching prefix proves only that this
particular safe regex cannot match; every possible match still runs the
complete original regex and its existing exclusion logic.

The proof requires an absolute start anchor and case-sensitive literals.
Unsupported constructs, ambiguous alternatives, backreferences, lookbehind,
control verbs, excessive proof depth, or parse errors retain the ordinary
engine. Generic patterns, owned patterns, and destructive patterns keep their
existing path. No shell receiver or executable-body decision is inferred from
this regex optimization. The authored regex text is unchanged.

Differential tests compare all affected built-in patterns against the original
compiled engine, including complete match spans and every relevant source
offset. A paired benchmark separately checks cold and warm behavior and
asserts that ordinary Python assignment lines compile zero of these 32
backtracking VMs instead of all 32. Prefix syntax parsing is included in the
`regex_compile` phase, so that phase's call count is a preparation count, not
an exact count of compiled VMs. See
[`src/packs/regex_engine.rs`](../src/packs/regex_engine.rs).

### AST work and position metadata

The ast-grep engine now compiles a language's complete pattern corpus on first
use, shares its immutable compiled index with workers through `Arc`, and walks
each AST once with ast-grep's own necessary node-kind conditions. Patterns
without such a condition still receive every candidate node. Matches are
returned in the previous pattern/source order, and cancellation is checked
even on walks with no findings. A nested interpreter still initializes all of
its own language's patterns when needed.

The matcher computes newline positions once instead of recounting the source
prefix for each finding. Shell command extraction uses parser-provided line
positions while retaining the previous byte offsets and line convention.
These changes target repeated traversal, pattern cloning/compilation, and
prefix processing; they do not exempt executable bodies based on quoting or
absence of unrelated shell-pack keywords. Legacy traversal differential tests
and position regressions accompany the changes in
[`src/ast_pattern_engine.rs`](../src/ast_pattern_engine.rs) and
[`src/heredoc.rs`](../src/heredoc.rs).

### Synchronous history construction

History work includes synchronous entry construction and redaction before a
queued write, plus writer initialization and a bounded shutdown wait. The
secret redactor previously built both the combined regex set and every
individual capture/replacement regex in a fresh process. The new path uses
the regex library's combined set to identify matches, then initializes only
the individual matchers needed for replacements. It preserves original-input
candidate selection, replacement order, and the previous compilation-failure
fallback. Differential tests include every built-in credential shape, quoted
and multiline data, overlaps, Unicode cases, and malformed custom patterns.
See [`src/redaction.rs`](../src/redaction.rs).

This removes avoidable CPU from recording; it does not establish that storage
is insignificant. The enabled, seeded, and locked history experiments are
needed to separate that question from regex startup costs.

## Security gaps uncovered while reproducing the workload

The investigation added correctness requirements rather than accepting the
incumbent's fast incomplete results:

- Recursive shell extraction could discard heredoc/here-string redirection
  wrappers, leaving only an interpreter command such as `python3 -` without
  its source. Complete embedded stdin statements are retained for recursion.
- The recursive Bash gate used only enabled shell-pack keywords. Independent
  embedded-interpreter triggers now keep a Python deletion reachable even
  when it contains no such keyword.
- Here-string extraction assigned Bash to every body because `<<<` is Bash
  syntax. The receiving interpreter must also receive executable body analysis.
  Direct and Bash-nested Python deletion exposed this silent-allow gap.
- Receiver-language analysis supplements the original Bash analysis. A
  here-string to Python, Ruby, or Node retains an independent Bash-first pass,
  including its rule IDs, allowlist boundaries, language exemptions, and
  incomplete-analysis behavior. This matters when an interpreter name is
  rebound to a shell function: allowlisting one core rule must not silently
  discard a separate Bash AST rule. Exact-rule tests cover all four existing
  Bash destructive rules and both direct and rebound receivers.
- Regex-only quoted extraction could truncate concatenated shell quote
  fragments before a destructive tail. The full operand is recovered and
  decoded with shell-aware logic; ambiguous forms retain conservative checks.
  Quoted and versioned Python receiver spellings are included in the tests.

The regressions in
[`tests/regression_heredoc_masking.rs`](../tests/regression_heredoc_masking.rs)
cover small and large executable bodies, destructive code at both ends,
literal quoted data, commit-message substitutions, sequential and nested
interpreters, pipelines, here-strings, malformed syntax, and rebound consumers.
Definitive Python deletion cases require `heredoc.python:shutil_rmtree`, so an
incomplete-analysis fallback cannot stand in for the repaired AST route.
Safe siblings must remain allowed.

## Unchanged budgets and benchmark reproduction

The ordinary hook evaluation deadline remains **1,000 ms**; the existing broad
Windows company preset retains its 3,000 ms default. Default extraction limits
remain 50 ms, 1 MiB per body, 10,000 body lines, and 10 contents. The production
AST matcher's first-pass budget remains 20 ms, with the existing bounded
fallback/recheck behavior. The fast-path tier remains 75/150/500 microseconds
for target/warning/panic assertions; the full-heredoc tier remains 5/15/20 ms.
Those tier expectations are distinct from fresh-process wall time. These
definitions live in [`src/perf.rs`](../src/perf.rs),
[`src/heredoc.rs`](../src/heredoc.rs), and
[`src/ast_pattern_engine.rs`](../src/ast_pattern_engine.rs).

Semantic regressions use generous existing test overrides where needed to
assert precise rule ownership under parallel scheduling. The paired hook
harness scrubs those overrides and exercises shipped defaults. An exhausted
safety evaluation remains explicitly indeterminate/reviewed or blocked; no
deadline increase or faster silent allow is counted as an optimization.

Run the focused Criterion groups with the shipping benchmark configuration:

```sh
cargo bench --locked --bench heredoc_perf -- issue_555_ast
cargo bench --locked --bench heredoc_perf -- issue_555_pipeline
```

The AST group separates a reused matcher from a newly constructed matcher and
includes 40/300-line assignment bodies, dense benign calls, and a late nested
deletion. The pipeline group measures complete evaluation and extraction,
including short, compound, executable-heredoc, and literal-data cases. Each
timed iteration checks its expected result. A fresh matcher in one process is
not the same as a fresh process: process-global and OS caches can still be warm.

Four ignored release tests compare the current implementation with an embedded
legacy oracle during the same invocation:

```sh
cargo test --locked --release --lib paired_ast_traversal_benchmark_issue_555 \
  -- --ignored --nocapture --test-threads=1
cargo test --locked --release --lib paired_stdin_provenance_benchmark_issue_555 \
  -- --ignored --nocapture --test-threads=1
cargo test --locked --release --lib paired_keyword_search_benchmark_issue_555 \
  -- --ignored --nocapture --test-threads=1
cargo test --locked --release --lib paired_safe_regex_prefix_benchmark_issue_555 \
  -- --ignored --nocapture --test-threads=1
```

The AST comparison covers parsing, traversal, refinement, and exact match
equivalence; it excludes process/worker startup and corpus construction. The
stdin comparison covers repeated provenance queries at 40, 300, and 1,000
lines, including context construction. The keyword comparison covers sparse
masked input and frequent near-matches; the safe-regex comparison covers cold
and warm rule sweeps with exact VM compilation counts. None substitutes for
the complete hook comparison. Their generous test-only timing allowances must not be
reported as changes to production budgets.

## First integrated stage measurements: 2026-10-12

### Retained evidence and binary identity

| Artifact | Contents |
|---|---|
| [Disabled/enabled raw comparison](../perf/baselines/2026-10-12-issue-555-integrated-diagnostic-disabled-enabled.json) | All 16 shapes, 30 measured pairs and three warmups per shape/profile, full wire observations and separate phase probes |
| [Seeded/locked raw comparison](../perf/baselines/2026-10-12-issue-555-integrated-diagnostic-seeded-locked.json) | Six representative shapes, 15 measured pairs and three warmups per shape/profile, database metadata and separate phase probes |
| [Complete comparison summary](../perf/baselines/2026-10-12-issue-555-integrated-diagnostic-summary.json) | All 44 case/profile rows, wall/CPU p50 and p95, signed paired differences, rule identities, phase attribution, and verification counts |
| [Host and storage snapshot](../perf/baselines/2026-10-12-issue-555-integrated-diagnostic-host-storage.json) | CPU affinity/quota, memory limit, and backing filesystem |

The summary's `rows` array is the complete 44-row results appendix. It includes
the smaller data cases, destructive-start/end controls, nested interpreter,
substitution, pipeline, and incomplete-syntax cases omitted from the compact
table below. Raw artifacts preserve their original paths and metadata; they
were copied into this directory without changing their measurements.

| Binary | SHA-256 |
|---|---|
| Untouched incumbent | `d0c034a1408c74fe99894039cf40d6c2d50c1f44ff7587f23ddc9bab8ad0a124` |
| Measured integrated candidate | `77265aab4c6444a5094ca9408e6e0b038f9702dc3686460fef37cd11296bd89d` |

The incumbent was built from
`00a1c8b5325544568758766e45649215cb88f350`. The candidate was built from the
dirty integrated working tree containing upstream changes through
`ecf3fc08ccb04485aef58c584c8c24d81295c712` plus this investigation's AST,
profiling, redaction, stdin-provenance, and security changes. Its embedded Git
SHA still reports `00a1c8b5325544568758766e45649215cb88f350`, so that field does
not attest the candidate source. The separate robot-output-only correction
and a test repair came after this binary was compiled. A subsequent
optimization of built-in filesystem regex preparation is also outside this
measured stage. These measurements apply to the identified normal-hook
candidate; they are not an exact-head release certificate or measurements of
those subsequent edits.

Both binaries used `cargo build --release --locked`, the repository's shipping
release profile, and pinned `nightly-2026-08-31`. Their embedded compiler
identities match: `1.100.0-nightly`, compiler commit
`90850177249efe0321573c569aec5d12b257f8d6`, commit date `2026-08-30`, host
`x86_64-unknown-linux-gnu`. Binary hashes were checked before and after each
comparison and remained unchanged.

### Coverage and host conditions

The first invocation selected `--history-profiles disabled,enabled --runs 30
--warmup 3` and all 16 cases. The second selected `--history-profiles
seeded,locked --history-seed-rows 247625 --runs 15 --warmup 3`, with these six
repeated `--compare-case` selections: `short_ls`, `compound_pipeline`,
`python_40_safe`, `python_300_safe`, `quoted_data_300`, and
`commit_message_300`. Both used the candidate/incumbent pairing described
above, shipped hook budgets, and disabled self-healing.

The host was Linux `6.18.44`, x86-64, with nine visible CPUs and CPU affinity
0–8. The container had an eight-core CPU quota (`800000/100000`) and an 8 GiB
memory limit. Temporary history databases were on `overlayfs`. Project builds
were paused for timing; CPU frequency, scheduling, and unrelated host activity
were not pinned. The first run's one-minute load average changed from 0.417 to
0.771; the second changed from 0.749 to 1.319. This was materially less loaded
than the reporter's described environment.

Both runs returned PASS. In total, **4,560 measured fresh processes** and
**528 warmup invocations** passed the required wire-verdict checks. The runner
also checked 88 separate phase invocations and eight untimed security-control
invocations. No failed or unexpected verdict was admitted as a timing sample.
The incumbent's nested-heredoc silent allow occurred in all four profiles and
remains recorded as an untimed gap; the candidate denied it in every profile.

The timed Python deletion cases at both ends of both body sizes retained
`heredoc.python:shutil_rmtree`, as did the nested inline Python case. The
expanding-data substitution retained `heredoc.shell:launcher-unverified`, the
data-to-shell pipeline retained `core.filesystem:rm-rf-root-home`, and the
unterminated executable heredoc retained
`heredoc.shell:incomplete-analysis`. Incomplete syntax was not reclassified as
a cheap allow.

### Representative process medians

All durations below are milliseconds. These are full fresh-process medians;
the bypass floor has not been subtracted. Each of the first two profiles uses
30 measured pairs per row; each of the last two uses 15.

| History | Shape | Incumbent wall | Candidate wall | Incumbent CPU | Candidate CPU |
|---|---|---:|---:|---:|---:|
| Disabled | Short `ls` | 6.051 | 5.747 | 5.820 | 5.506 |
| Disabled | Compound/pipeline | 11.982 | 11.867 | 11.767 | 11.573 |
| Disabled | Python, 40 lines | 37.910 | 31.176 | 37.038 | 30.483 |
| Disabled | Python, 300 lines | 108.326 | 65.393 | 107.915 | 62.939 |
| Disabled | Quoted data, 300 lines | 53.022 | 25.983 | 51.047 | 24.238 |
| Disabled | Commit message, 300 lines | 78.266 | 40.347 | 75.087 | 37.583 |
| Enabled | Short `ls` | 10.220 | 7.423 | 9.787 | 7.260 |
| Enabled | Compound/pipeline | 15.986 | 13.451 | 15.071 | 13.137 |
| Enabled | Python, 40 lines | 39.682 | 33.510 | 37.549 | 31.991 |
| Enabled | Python, 300 lines | 97.694 | 55.745 | 88.877 | 51.597 |
| Enabled | Quoted data, 300 lines | 56.588 | 28.625 | 55.029 | 26.950 |
| Enabled | Commit message, 300 lines | 79.977 | 43.329 | 76.225 | 40.111 |
| Seeded | Short `ls` | 9.686 | 7.265 | 9.592 | 7.183 |
| Seeded | Compound/pipeline | 15.319 | 13.183 | 14.918 | 12.975 |
| Seeded | Python, 40 lines | 38.826 | 33.647 | 37.486 | 32.878 |
| Seeded | Python, 300 lines | 99.680 | 55.039 | 95.120 | 52.775 |
| Seeded | Quoted data, 300 lines | 61.833 | 31.445 | 59.124 | 29.416 |
| Seeded | Commit message, 300 lines | 82.702 | 42.854 | 78.860 | 38.859 |
| Locked | Short `ls` | 55.895 | 55.356 | 9.716 | 7.416 |
| Locked | Compound/pipeline | 55.828 | 55.831 | 16.394 | 13.654 |
| Locked | Python, 40 lines | 63.607 | 56.700 | 37.037 | 30.784 |
| Locked | Python, 300 lines | 116.945 | 75.769 | 88.699 | 48.202 |
| Locked | Quoted data, 300 lines | 83.202 | 56.582 | 56.369 | 26.561 |
| Locked | Commit message, 300 lines | 111.933 | 72.330 | 81.775 | 42.966 |

The 300-line Python wall median decreased by 39.6–44.8% in the three unlocked
profiles, with corresponding CPU decreases, and by 35.2% under the writer
lock. Unlocked quoted-data medians decreased by 49.1–51.0%; unlocked
commit-message medians decreased by 45.8–48.4%. This is evidence of reduced
analysis CPU, not just a favorable storage wait in one process.

Short-command results are more limited. With history disabled, the compound
command's median of paired wall savings was **-0.166 ms**, despite its slightly
lower candidate marginal median. It should be treated as essentially
unchanged. The short `ls` paired median saved only 0.158 ms in that profile.
With history enabled or seeded, the short-command CPU improvement was larger,
consistent with removing cold redaction compilation from history construction.

Across all case/profile rows, median bypass wall times ranged from 2.168 to
3.013 ms. The artifacts retain every full/bypass pair and signed
incumbent-minus-candidate observation. Their paired-difference summaries are
separate from the marginal medians shown here.

### History recording and contention

The small enabled databases each grew from one initialization row to 546
rows. Each seeded database contained 247,626 initial rows: 247,625 synthetic
rows plus initialization. Its initial main database file was 147,714,048 bytes
(approximately 140.9 MiB), and it finished with 247,741 rows. Both used WAL.
This demonstrates the real schema/index/FTS workload at the requested
cardinality; it does not recreate the reporter's 30-day distribution,
fragmentation, storage device, or database size.

The seeded results did not show a large cardinality penalty on this host.
Profiles were measured sequentially, however, so subtracting an enabled or
seeded median from a disabled median is not a controlled measurement of the
exact history overhead. In particular, the faster enabled Python-300 median
does not mean history makes evaluation faster.

The writer-lock experiment does establish a remaining wait. Candidate short
`ls` used 7.416 ms of process CPU but took 55.356 ms of wall time. Its separate
instrumented invocation attributed **48.680 ms to `history_flush`**, compared
with 0.692 ms for enabled history and 1.585 ms for seeded history. Entry
construction/enqueue took 0.957 ms under the lock and 0.981 ms with ordinary
enabled history in those probes. Both locked databases remained at their
single initialization row, while all security verdicts remained correct.
The existing bounded, best-effort writer shutdown still costs roughly 49 ms
when storage is write-locked; this change does not remove that wait.

### Phase attribution and remaining work

The integrated history-disabled Python-300 phase probe recorded **6,682
completed shell tokenizations and 23 segmentations**, compared with 52,133
and 325 in the retained earlier development probe. The tokenization count
decreased by 87.2%. This comparison establishes removal of repeated work on
the same fixture; the earlier instrumented development snapshot is not the
untouched incumbent or a release certificate.

The integrated probe's remaining largest exclusive costs included 72 shell
regex compilations taking 23.831 ms and 21,446 regex matches taking 12.877 ms.
Structural AST pattern compilation occurred once and took 0.323 ms; the main
AST-match/wait phase took 1.851 ms, overlapping worker parsing. Shell
tokenization itself accounted for 1.116 ms after optimization. These single
instrumented observations identify remaining work in regex preparation and
repeated rule evaluation; they do not justify bypassing deep analysis.

All 44 candidate phase probes emitted the 24-key schema. Their main-thread
exclusive durations plus `uninstrumented_ns` exactly conserved `total_ns`,
and none reported an incomplete main or worker span. Incumbent structured
profiles were correctly recorded as unsupported. Phase durations remain
wall measurements from separate invocations, with instrumentation overhead
and overlapping workers; they are not substitutes for the process CPU and
uninstrumented timing results.

### Tail and external-validity limits

There is no claim that every tail improved. For example, enabled Python-40
wall p95 increased from 51.167 to 69.151 ms, and history-disabled compound p95
increased from 18.837 to 27.087 ms. All these samples retained their correct
verdicts. Fifteen or thirty pairs provide diagnostic medians and exploratory
tails, not a universal p95/p99 guarantee. The source-bound absolute budget gate
has separate sample and source requirements.

These measurements do not reproduce the reporter's heavily loaded host,
long-lived storage contention, cold-device behavior, complete command
distribution, or observed 1–5 second tail. The retained results show
substantial reductions for the specified multiline cases while preserving
security decisions, and expose the remaining writer-lock delay explicitly.

## Validation scope

The comparison harness passed `--help`, its mutation-sensitive `--self-test`,
and a real-binary negative control that deliberately expected deny for an
ordinary `ls -la` payload. That control produced ERROR and no successful
timing summary. Merge reconciliation preserved all 20 absolute-gate cases,
their required case IDs and certificate logic, and the earlier published raw
comparison artifact. The measured process/profiling/security counts above
are verified against the retained JSON.

### Rust and repository validation

After the robot-output correction and test repair, the integrated source
passed these checks:

- Formatting with `cargo fmt --check`.
- Strict Clippy across all targets (1 minute 6 seconds).
- The combined nextest library suite: 4,670 passed, seven ignored
  (32.455 seconds).
- `profile_hook`, `regression_heredoc_masking`, and `agent_hook_output`:
  71 passed (10.797 seconds), including the repaired robot-output path.

These checks postdate the measured binary and precede the subsequent built-in
filesystem regex optimization. Broader E2E and absolute-gate outcomes are
tracked separately. Completion of the paired comparisons does not establish
release readiness or an exact-head performance certificate.
