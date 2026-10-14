// Fail-closed Pi bridge for sandbox trials and local macOS review.
// Candidate commands are JSON data; the bridge never executes them itself.
import { spawn } from "node:child_process";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const DCG_BIN = "/Users/tom/.local/bin/dcg";
const MAX_OUTPUT = 1024 * 1024;
// Default trial (600 s) plus setup/review margin (180 s). Increase this
// together with trial.timeout_secs before deploying a longer trial policy.
const GUARD_TIMEOUT_MS = 780_000;
const GUARD_FAILURE = {
  block: true,
  reason: "DCG konnte den Befehl nicht vollständig prüfen oder freigeben; Ausführung angehalten.",
};

type Verdict = { block: boolean; reason?: string; command?: string };

function checkCommand(input: Record<string, unknown>, cwd: string): Promise<Verdict> {
  return new Promise((resolve) => {
    let settled = false;
    let stdout = "";
    let stderr = "";
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (result: Verdict) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(result);
    };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(DCG_BIN, ["--desktop-review", "--no-color", "--agent", "pi"], {
        cwd,
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      finish(GUARD_FAILURE);
      return;
    }
    timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(GUARD_FAILURE);
    }, GUARD_TIMEOUT_MS);
    child.on("error", () => finish(GUARD_FAILURE));
    child.stdin?.on("error", () => finish(GUARD_FAILURE));
    child.stdout?.on("data", (chunk) => {
      stdout += chunk.toString();
      if (stdout.length > MAX_OUTPUT) {
        child.kill("SIGKILL");
        finish(GUARD_FAILURE);
      }
    });
    child.stderr?.on("data", (chunk) => {
      stderr = (stderr + chunk.toString()).slice(-8192);
    });
    child.on("close", (code) => {
      try {
        const result = JSON.parse(stdout);
        if (code === 0 && result.dcg_verdict === "confined"
            && result.dcg_approval_scope === "confined"
            && ["none", "all"].includes(result.dcg_confined_loopback)
            && result.hookSpecificOutput?.hookEventName === "PreToolUse"
            && result.hookSpecificOutput?.permissionDecision === "allow"
            && typeof result.hookSpecificOutput.updatedInput?.command === "string"
            && result.hookSpecificOutput.updatedInput.command.trim().length > 0) {
          finish({ block: false, command: result.hookSpecificOutput.updatedInput.command });
        } else if (code === 0 && result.dcg_verdict === "allow") {
          finish({ block: false });
        } else if (result.hookSpecificOutput?.permissionDecision === "deny") {
          finish({
            block: true,
            reason: `${result.hookSpecificOutput.permissionDecisionReason || "Blocked by DCG"}\n${stderr}`.trim(),
          });
        } else {
          finish(GUARD_FAILURE);
        }
      } catch {
        finish(GUARD_FAILURE);
      }
    });
    if (!child.stdin || !child.stdout) {
      child.kill("SIGKILL");
      finish(GUARD_FAILURE);
      return;
    }
    child.stdin.end(JSON.stringify({
      tool_name: "Bash",
      tool_input: input,
      cwd,
      dcg_explicit_verdict: true,
      dcg_input_rewrite: true,
    }));
  });
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return;
    const command = (event.input as { command?: unknown })?.command;
    if (typeof command !== "string") return GUARD_FAILURE;
    if (!command.trim()) return;
    const result = await checkCommand(event.input as Record<string, unknown>, ctx.cwd);
    if (result.block) return result;
    // Pi's tool_call contract explicitly permits in-place event.input mutation.
    // Never return an ordinary allow for a confined receipt without applying it.
    if (result.command !== undefined) {
      try {
        (event.input as { command: string }).command = result.command;
        if ((event.input as { command: string }).command !== result.command) return GUARD_FAILURE;
      } catch { return GUARD_FAILURE; }
    }
  });
}
