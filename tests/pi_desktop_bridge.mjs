// Exercise the actual Pi extension with controlled child-process failures.
// No candidate command, native dialog or real DCG binary is executed.
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";
import vm from "node:vm";

const source = stripTypeScriptTypes(await readFile(
  new URL("../integrations/pi/dcg-guard.ts", import.meta.url), "utf8",
));
const deny = { hookSpecificOutput: {
  permissionDecision: "deny", permissionDecisionReason: "Human declined",
} };
const confinedCommand = "/fixture/dcg run --confined --request 7b7d";
const confined = { dcg_verdict: "confined", dcg_approval_scope: "confined", dcg_confined_loopback: "none", hookSpecificOutput: {
  hookEventName: "PreToolUse", permissionDecision: "allow", updatedInput: { command: confinedCommand, timeout: 1 },
} };
const update = (updatedInput, permissionDecision = "allow") => ({ ...confined,
  hookSpecificOutput: { ...confined.hookSpecificOutput, permissionDecision, updatedInput },
});
const cases = [
  { name: "explicit_allow", code: 0, verdict: { dcg_verdict: "allow" }, blocked: false },
  { name: "confined_rewrites_in_place", code: 0, verdict: confined, blocked: false, rewritten: true },
  { name: "confined_all_loopback_rewrites_in_place", code: 0, verdict: { ...confined, dcg_confined_loopback: "all" }, blocked: false, rewritten: true },
  { name: "confined_missing_scope", code: 0, verdict: { ...confined, dcg_approval_scope: undefined }, blocked: true },
  { name: "confined_invalid_scope", code: 0, verdict: { ...confined, dcg_approval_scope: "one_time" }, blocked: true },
  { name: "confined_missing_loopback", code: 0, verdict: { ...confined, dcg_confined_loopback: undefined }, blocked: true },
  { name: "confined_invalid_loopback", code: 0, verdict: { ...confined, dcg_confined_loopback: "owned" }, blocked: true },
  { name: "confined_nonstring_loopback", code: 0, verdict: { ...confined, dcg_confined_loopback: true }, blocked: true },
  { name: "confined_nested_metadata_only", code: 0, verdict: {
    dcg_verdict: "confined", hookSpecificOutput: { ...confined.hookSpecificOutput, approvalScope: "confined", confinedLoopback: "all" },
  }, blocked: true },
  { name: "confined_wrong_hook_event", code: 0, verdict: { ...confined,
    hookSpecificOutput: { ...confined.hookSpecificOutput, hookEventName: "PostToolUse" },
  }, blocked: true },
  { name: "confined_wrong_exit", code: 1, verdict: confined, blocked: true },
  { name: "confined_missing_update", code: 0, verdict: update(undefined), blocked: true },
  { name: "confined_null_update", code: 0, verdict: update(null), blocked: true },
  { name: "confined_missing_command", code: 0, verdict: update({ timeout: 1 }), blocked: true },
  { name: "confined_nonstring_command", code: 0, verdict: update({ command: 42 }), blocked: true },
  { name: "confined_empty_command", code: 0, verdict: update({ command: "" }), blocked: true },
  { name: "confined_blank_command", code: 0, verdict: update({ command: " \t " }), blocked: true },
  { name: "confined_ask_permission", code: 0, verdict: update({ command: confinedCommand }, "ask"), blocked: true },
  { name: "confined_immutable_input", code: 0, verdict: confined, blocked: true, immutable: true },
  { name: "json_deny_exit_zero", code: 0, verdict: deny, blocked: true },
  { name: "json_deny_exit_two", code: 2, verdict: deny, blocked: true },
  { name: "ask_is_not_allow", code: 0, verdict: { hookSpecificOutput: { permissionDecision: "ask" } }, blocked: true },
  { name: "wrong_exit_allow", code: 1, verdict: { dcg_verdict: "allow" }, blocked: true },
  { name: "empty_stdout", code: 0, raw: "", blocked: true },
  { name: "malformed_stdout", code: 0, raw: "not JSON", blocked: true },
  { name: "two_documents", code: 0, raw: '{"dcg_verdict":"allow"}\n{}', blocked: true },
  { name: "unknown_verdict", code: 0, verdict: { dcg_verdict: "maybe" }, blocked: true },
  { name: "oversized_stdout", code: 0, raw: "x".repeat(1024 * 1024 + 1), blocked: true },
  { name: "synchronous_spawn_failure", throws: true, blocked: true },
  { name: "missing_pipe", missingPipe: true, blocked: true },
  { name: "spawn_error_event", error: true, blocked: true },
];
const results = [];
for (const test of cases) {
  let handler;
  let received;
  let killed = false;
  const context = vm.createContext({ setTimeout, clearTimeout, JSON });
  const childProcesses = new vm.SyntheticModule(["spawn"], function() {
    this.setExport("spawn", (executable, args, options) => {
      assert.equal(executable, "/Users/tom/.local/bin/dcg");
      assert.deepEqual(Array.from(args), ["--desktop-review", "--no-color", "--agent", "pi"]);
      assert.equal(options.shell, false);
      assert.equal(options.cwd, "/test/work");
      if (test.throws) throw new Error("ENOENT fixture");
      const child = new EventEmitter();
      child.kill = () => { killed = true; };
      child.stdin = new EventEmitter();
      child.stdout = test.missingPipe ? undefined : new EventEmitter();
      child.stderr = new EventEmitter();
      child.stdin.end = (payload) => {
        received = JSON.parse(payload);
        queueMicrotask(() => {
          if (test.error) child.emit("error", new Error("EIO fixture"));
          child.stderr.emit("data", "test diagnostic");
          child.stdout?.emit("data", test.raw ?? JSON.stringify(test.verdict) ?? "");
          child.emit("close", test.code ?? 2);
        });
      };
      return child;
    });
  }, { context });
  const extension = new vm.SourceTextModule(source, { context });
  await extension.link((specifier) => {
    assert.equal(specifier, "node:child_process");
    return childProcesses;
  });
  await extension.evaluate();
  extension.namespace.default({ on(event, callback) {
    assert.equal(event, "tool_call"); handler = callback;
  } });
  const command = "printf '%s' '$(this-is-data)'";
  const input = { command, timeout: 45 };
  if (test.immutable) Object.freeze(input);
  const event = { toolName: "bash", input };
  const result = await handler(event, { cwd: "/test/work" });
  assert.equal(result?.block === true, test.blocked, test.name);
  assert.equal(event.input, input, `${test.name}: preserve input identity`);
  assert.equal(input.command, test.rewritten ? confinedCommand : command, `${test.name}: command`);
  assert.equal(input.timeout, 45, `${test.name}: preserve caller timeout`);
  if (!test.throws && !test.missingPipe) {
    assert.equal(received.tool_input.command, command);
    assert.equal(received.tool_input.timeout, 45);
    assert.equal(received.cwd, "/test/work");
    assert.equal(received.dcg_explicit_verdict, true);
    assert.equal(received.dcg_input_rewrite, true);
  }
  if (test.missingPipe || test.name === "oversized_stdout") assert.equal(killed, true);
  assert.equal(await handler({ toolName: "read", input: {} }, { cwd: "/test/work" }), undefined);
  assert.equal((await handler({ toolName: "bash", input: {} }, { cwd: "/test/work" })).block, true);
  results.push({ name: test.name, passed: true });
}
console.log(JSON.stringify(results, null, 2));
