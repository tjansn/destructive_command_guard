# dcg: run-owned loopback for confined runs and trials (Part F1)

2026-10-13. Approved by Tom as the follow-up to the A–E rollout ("queue the
own-localhost fix with Codex right after"). 0.15.3+tom.10 (main 20c2c979) is
installed; do not touch the installed binary, hooks, config or pi bridge.

## Problem

Part C/E deny all outbound TCP, including connections to a listener the run
itself created. Your pi-os acceptance (`npm test`, 2026-10-12) lost exactly the
seven CDP tests that start their own WebSocket server on 127.0.0.1:<ephemeral>
and connect to it (denials on ports 62081–62087). Every local test suite that
starts its own HTTP/WebSocket server has the same loss.

The rule we must keep: a run may never reach a loopback service it did not
create (the confused-deputy finding from Distill's review). Loopback alone is
not a boundary.

## Requested capability

Allow a confined run (E) and an observational trial (C) to connect to TCP
listeners created by its own process tree, and nothing else on loopback.
Fail closed: if ownership cannot be established, keep today's deny-all.

## Candidate design (evaluate; choose with reasons, or propose better)

1. Before building the profile, enumerate every listening TCP socket on the
   machine without root (e.g. the `net.inet.tcp.pcblist_n` sysctl that
   `netstat -anv` reads, which includes root-owned sockets and owning pids).
   Profile: allow `localhost:*` outbound, then explicitly deny each port that
   already listens on a loopback or wildcard address (verify Seatbelt
   precedence; verify that "localhost" covers 127.0.0.0/8 and ::1, and how
   IPv4-mapped IPv6 behaves).
2. While the run executes, watch for new listening sockets (bounded polling
   or a better kernel source). A new loopback/wildcard listener whose owner is
   not in the run's process tree ends the run: terminate the group, report
   `[dcg:confined-limit]` (or the trial equivalent) and never allow/learn.
3. State the residual risk honestly: a host service that starts listening
   and is contacted inside the detection window. Measure that window.
4. Enumeration failure, an unparseable table, or too many ports to express
   in the profile → today's deny-all, with a clear diagnostic.

Rejected or deprioritised alternatives should be listed briefly with the
reason (port pre-reservation, interposition, pf/root, proxies).

## Acceptance

- Positive: a fixture that starts its own listener on 127.0.0.1:0 and ::1:0
  and connects to it passes under E and under a trial.
- Negative: a pre-existing fixture listener (started by the test before the
  run) stays unreachable; a fixture listener started by an unrelated process
  during the run terminates the run; neither fixture victim records a request.
- pi-os: rerun the confined `npm test` on a CoW copy of
  /Users/tom/dev/Projects/workOS-worktrees/pi-os-fft (feat/file-commands, use
  whatever HEAD is there; do not modify that checkout). Report the CDP results
  and the full suite's duration. Claude Code caps a Bash call at 600 s, so the
  confined run gets at most 595 s; report whether the suite fits.
- Same validation discipline as A–E: temporary HOME, serial full suite,
  check/clippy/fmt, pi bridge tests, counts recounted from logs, failures
  investigated rather than removed.

## Process

Branch `tjansn/dcg-owned-loopback` from `main` (20c2c979) in the same
worktree. No install, no push, no live hook/config change. Commit in small
signed commits. Report to
/Users/tom/Documents/Codex/2026-10-09/k/work/dcg-owned-loopback-REPORT.md,
including a short plain-language summary for Tom (what changes for him, what
risk remains). Service capability (long-running preview servers) stays out of
scope.

## Implementation gate: native findings, 2026-10-13

Status: **blocked before enabling the candidate policy**. The production
deny-all TCP policy is unchanged. This is not an implementation of F1.

On macOS 27.0.1 (26A434), arm64, the proposed unprivileged enumeration and
port exclusions did not meet their safety prerequisites:

- `/usr/sbin/netstat -anv -p tcp` exited 0 with empty stdout/stderr while a
  disposable Python listener was open. Unprivileged `lsof` saw that listener
  and other listeners. Empty output must not be accepted as an empty machine.
- A raw `net.inet.tcp.pcblist_n` read succeeded with 664 bytes, including a
  generation header whose count was 144, but only one socket record. The
  reason for the incomplete view was not established. No root enumeration
  or host networking configuration change was attempted. `lsof` alone does
  not establish complete coverage across users.
- `(allow network-outbound (remote ip "localhost:*"))` allowed disposable
  IPv4, IPv6, and IPv4-mapped IPv6 connections. Adding a deny for
  `localhost:<fixture-port>` **after** it still let the IPv4 and IPv6
  victims receive the fixture bytes. Only the mapped IPv6 case was denied.
  Adding the deny before the allow let all three through.
- Moving the port exclusion inside the allow with `require-all` /
  `require-not` also failed to block IPv4 and IPv6, for both `ip` and `tcp`
  predicates and both `localhost:<port>` and `*:<port>` forms. Numeric
  `127.0.0.1:<port>` and `[::1]:<port>` forms were rejected by the compiler.
- A `target same-sandbox` network filter compiled but denied both an owned
  connection and an outside fixture connection. Compilation is not proof
  of an ownership capability.
- `127.0.0.2` could not be bound (`EADDRNOTAVAIL`) without interface changes.
  No claim about the entire 127/8 range follows from these probes.

These are observations from disposable fixtures, not a claim that the same
behavior occurs on every macOS release. The installed `sandbox-exec` and
system socket-table tools were used without root. No existing host service
was contacted. There were 9 simple allow/deny policy cases, 16 conjunctive
exclusion cases, and 2 same-sandbox connection attempts; these are diagnostic
experiments, not passing F1 acceptance tests.

Even on a platform where both prerequisites pass, polling is a detector,
not an atomic ownership check. A listener can appear, receive a request and
disappear between samples. A kill after detection cannot undo the request.
A nominal polling interval is not a hard upper bound under scheduler delay.
No monitor was enabled here, so there is no measured detection-window claim.
The 21.44–26.97 ms successful process-spawn/connect samples are not monitor
latency measurements.

### Alternatives and next decision

- Port pre-reservation cannot transparently hand arbitrary `listen(0)`
  calls to Node descendants, and releasing a reservation reopens a race.
- Runtime interposition does not confine arbitrary native descendants or
  direct syscalls and is not a security boundary.
- A privileged firewall/helper requires a separate design, permissions,
  lifecycle and recovery plan; it is outside the no-live-config scope.
- A userspace proxy requires cooperation or enforced redirection and still
  needs an atomic ownership/connection boundary. An optional proxy alone
  cannot enforce this requirement.
- A separate network namespace/VM can provide a real private loopback, but
  introduces a new execution backend, runtime and filesystem contract.

Retain deny-all on this host. Choose a separately reviewed isolation backend
or demonstrate an enforceable macOS ownership primitive before opening
loopback. Do not substitute same-user `lsof` results or a passing parser
unit test for a complete socket view and native connection-denial evidence.

### Primary-source context

[Apple netstat's implementation](https://github.com/apple-oss-distributions/network_cmds/blob/main/netstat.tproj/inet.c)
reads `net.inet.tcp.pcblist_n`. Apple's published
[XNU socket-list implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcblist.c)
contains generation headers and snapshot construction. These explain the
intended API shape, but do not establish completeness on the tested host;
the native contradictory evidence above controls this decision.
