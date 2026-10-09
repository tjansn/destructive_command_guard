// Fail-closed Pi bridge for this fork's one-request macOS review.
// Candidate commands are JSON data; the bridge never executes them itself.
import { spawn } from "node:child_process";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const DCG_BIN = "/Users/tom/.local/bin/dcg";
const MAX_OUTPUT = 1024 * 1024;
const GUARD_FAILURE = {
  block: true,
  reason: "DCG konnte den Befehl nicht vollständig prüfen oder freigeben; Ausführung angehalten.",
};

function checkCommand(command: string, cwd: string): Promise<{ block: boolean; reason?: string }> {
  return new Promise((resolve) => {
    let settled = false;
    let stdout = "";
    let stderr = "";
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (result: { block: boolean; reason?: string }) => {
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
    }, 140_000);
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
        if (code === 0 && result.dcg_verdict === "allow") {
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
      tool_input: { command },
      cwd,
      dcg_explicit_verdict: true,
    }));
  });
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return;
    const command = (event.input as { command?: unknown })?.command;
    if (typeof command !== "string") return GUARD_FAILURE;
    if (!command.trim()) return;
    const result = await checkCommand(command, ctx.cwd);
    if (result.block) return result;
  });
}
