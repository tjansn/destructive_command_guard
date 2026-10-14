//! MCP server mode for direct agent integration.
//!
//! This exposes dcg as an MCP tool server over stdio, providing structured
//! checks without shell-hook overhead.

use crate::config::Config;
use crate::evaluator::{EvaluationDecision, evaluate_command_with_pack_order_at_path_in_dialect};
use crate::normalize::ShellDialect;
use crate::packs::REGISTRY;
use crate::scan::{
    ScanEvalContext, ScanFailOn, ScanFormat, ScanOptions, ScanRedactMode, ScanReport, scan_paths,
};
use async_trait::async_trait;
use rust_mcp_sdk::mcp_server::{
    McpServerOptions, ServerHandler, ToMcpServerHandler, server_runtime,
};
use rust_mcp_sdk::schema::schema_utils::CallToolError;
use rust_mcp_sdk::schema::{
    CallToolRequestParams, CallToolResult, Implementation, InitializeResult, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, RpcError, ServerCapabilities, ServerCapabilitiesTools,
    TextContent, Tool, ToolInputSchema,
};
use rust_mcp_sdk::{McpServer, StdioTransport, TransportOptions};
use serde::Serialize;
use serde_json::{Map, Value};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug)]
pub struct DcgMcpServer {
    server_info: InitializeResult,
    config: Arc<Config>,
    scan_ctx: Arc<ScanEvalContext>,
}

#[derive(Serialize)]
struct AllowlistInfo {
    layer: String,
    reason: String,
}

#[derive(Serialize)]
struct CheckCommandResponse {
    allowed: bool,
    decision: String,
    dialect: &'static str,
    mode: Option<String>,
    skipped_due_to_budget: bool,
    reason: Option<String>,
    rule_id: Option<String>,
    pack_id: Option<String>,
    pattern_name: Option<String>,
    severity: Option<String>,
    explanation: Option<String>,
    matched_text_preview: Option<String>,
    allowlist: Option<AllowlistInfo>,
}

#[derive(Serialize)]
struct ExplainPatternResponse {
    rule_id: String,
    pack_id: String,
    pattern_name: String,
    severity: String,
    reason: String,
    explanation: String,
}

fn mcp_decision_contract(
    decision: EvaluationDecision,
    mode: Option<crate::packs::DecisionMode>,
) -> (bool, &'static str) {
    match decision {
        EvaluationDecision::Allow => (true, "allow"),
        EvaluationDecision::Deny => match mode.unwrap_or(crate::packs::DecisionMode::Deny) {
            crate::packs::DecisionMode::Deny => (false, "deny"),
            crate::packs::DecisionMode::Ask => (false, "ask"),
            crate::packs::DecisionMode::Warn => (true, "warn"),
            crate::packs::DecisionMode::Log => (true, "log"),
        },
        EvaluationDecision::Indeterminate => (false, "indeterminate"),
    }
}

impl DcgMcpServer {
    #[must_use]
    pub fn new() -> Self {
        let config = Config::load();
        let scan_ctx = ScanEvalContext::from_config(&config);
        let server_info = InitializeResult {
            protocol_version: ProtocolVersion::V2025_11_25.into(),
            server_info: Implementation {
                description: Some(
                    "Destructive Command Guard MCP server for command safety checks.".to_string(),
                ),
                icons: Vec::new(),
                name: "dcg".to_string(),
                title: Some("Destructive Command Guard".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                website_url: None,
            },
            capabilities: ServerCapabilities {
                completions: None,
                experimental: None,
                logging: None,
                prompts: None,
                resources: None,
                tasks: None,
                tools: Some(ServerCapabilitiesTools {
                    list_changed: Some(false),
                }),
            },
            instructions: Some(
                "Destructive Command Guard MCP server. Tools: check_command, scan_file, explain_pattern."
                    .to_string(),
            ),
            meta: None,
        };

        Self {
            server_info,
            config: Arc::new(config),
            scan_ctx: Arc::new(scan_ctx),
        }
    }

    const fn default_scan_options() -> ScanOptions {
        ScanOptions {
            format: ScanFormat::Pretty,
            fail_on: ScanFailOn::Error,
            max_file_size_bytes: 1_048_576,
            max_findings: 100,
            redact: ScanRedactMode::None,
            truncate: 200,
        }
    }

    fn tool_input_schema(
        required: &[&str],
        props: Vec<(&str, Map<String, Value>)>,
    ) -> ToolInputSchema {
        let mut properties = std::collections::BTreeMap::new();
        for (name, schema) in props {
            properties.insert(name.to_string(), schema);
        }
        ToolInputSchema::new(
            required.iter().map(|s| (*s).to_string()).collect(),
            Some(properties),
            None,
        )
    }

    fn string_schema(description: &str) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("type".to_string(), Value::String("string".to_string()));
        map.insert(
            "description".to_string(),
            Value::String(description.to_string()),
        );
        map
    }

    fn check_command_schema() -> ToolInputSchema {
        let mut dialect = Self::string_schema(
            "Execution shell: posix, powershell, cmd, or unknown. Supply a known dialect only when the executing shell is known; omission retains conservative multi-shell analysis.",
        );
        dialect.insert(
            "enum".to_string(),
            serde_json::json!(["unknown", "posix", "powershell", "cmd"]),
        );
        dialect.insert("default".to_string(), serde_json::json!("unknown"));
        Self::tool_input_schema(
            &["command"],
            vec![
                (
                    "command",
                    Self::string_schema("Command to evaluate without executing it"),
                ),
                ("dialect", dialect),
            ],
        )
    }

    fn tool(name: &str, description: &str, schema: ToolInputSchema) -> Tool {
        Tool {
            name: name.to_string(),
            description: Some(description.to_string()),
            execution: None,
            icons: Vec::new(),
            input_schema: schema,
            title: None,
            annotations: None,
            meta: None,
            output_schema: None,
        }
    }

    fn tool_result_json<T: Serialize>(value: &T) -> Result<CallToolResult, CallToolError> {
        let json = serde_json::to_string_pretty(value).map_err(CallToolError::new)?;
        Ok(CallToolResult::text_content(vec![TextContent::from(json)]))
    }

    fn call_tool_error(message: impl Into<String>) -> CallToolError {
        CallToolError::new(std::io::Error::other(message.into()))
    }

    fn string_arg(args: Option<&Map<String, Value>>, key: &str) -> Result<String, CallToolError> {
        let args = args.ok_or_else(|| {
            Self::call_tool_error(format!("Missing arguments for tool (expected '{key}')"))
        })?;
        let value = args.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
            Self::call_tool_error(format!("Missing or invalid '{key}' parameter"))
        })?;
        Ok(value.to_string())
    }

    fn dialect_arg(args: Option<&Map<String, Value>>) -> Result<ShellDialect, CallToolError> {
        // An omitted dialect is not evidence of POSIX, including on Unix.
        // Conversely, reject an explicit unsupported value rather than
        // silently evaluating a different shell from the caller's request.
        match args.and_then(|args| args.get("dialect")) {
            None => Ok(ShellDialect::Unknown),
            Some(Value::String(value)) => match value.as_str() {
                "unknown" => Ok(ShellDialect::Unknown),
                "posix" => Ok(ShellDialect::Posix),
                "powershell" => Ok(ShellDialect::PowerShell),
                "cmd" => Ok(ShellDialect::Cmd),
                _ => Err(Self::call_tool_error(
                    "Invalid 'dialect': expected unknown, posix, powershell, or cmd",
                )),
            },
            Some(_) => Err(Self::call_tool_error(
                "Invalid 'dialect': expected a string",
            )),
        }
    }

    fn check_command_arguments(
        &self,
        args: Option<&Map<String, Value>>,
    ) -> Result<CheckCommandResponse, CallToolError> {
        let command = Self::string_arg(args, "command")?;
        let dialect = Self::dialect_arg(args)?;
        Ok(self.check_command(&command, dialect))
    }

    fn rule_id_from_match(pack_id: Option<&str>, pattern_name: Option<&str>) -> Option<String> {
        match (pack_id, pattern_name) {
            (Some(pack), Some(name)) => Some(format!("{pack}:{name}")),
            _ => None,
        }
    }

    fn check_command(&self, command: &str, dialect: ShellDialect) -> CheckCommandResponse {
        // Preserve the policy scope and configured extraction budget used by
        // evaluate_command; ScanEvalContext's larger scan-file timeout is not
        // the command-check timeout.
        let heredoc_settings = self.config.heredoc_settings();
        let _rule_target_scope = crate::config::RuleTargetExemptionScope::install(&self.config);
        let evaluate = |command: &str, allowlists: &crate::allowlist::LayeredAllowlist| {
            evaluate_command_with_pack_order_at_path_in_dialect(
                command,
                &self.scan_ctx.enabled_keywords,
                &self.scan_ctx.ordered_packs,
                self.scan_ctx.keyword_index.as_ref(),
                &self.scan_ctx.compiled_overrides,
                allowlists,
                &heredoc_settings,
                None,
                dialect,
            )
        };
        // A warn/log/ask first match must not hide a later deny (#498).
        let result = crate::evaluator::escalate_masked_findings(
            &self.config,
            command,
            &self.scan_ctx.allowlists,
            evaluate(command, &self.scan_ctx.allowlists),
            evaluate,
        );

        let effective_mode =
            crate::evaluator::resolve_effective_mode(&self.config, command, &result);
        let mode = effective_mode.map(|m| m.label().to_string());
        let (allowed, decision) = mcp_decision_contract(result.decision, effective_mode);

        let mut response = CheckCommandResponse {
            allowed,
            decision: decision.to_string(),
            dialect: match dialect {
                ShellDialect::Unknown => "unknown",
                ShellDialect::Posix => "posix",
                ShellDialect::PowerShell => "powershell",
                ShellDialect::Cmd => "cmd",
            },
            mode,
            skipped_due_to_budget: result.skipped_due_to_budget,
            reason: None,
            rule_id: None,
            pack_id: None,
            pattern_name: None,
            severity: None,
            explanation: None,
            matched_text_preview: None,
            allowlist: None,
        };

        if let Some(override_) = result.allowlist_override.as_ref() {
            response.allowlist = Some(AllowlistInfo {
                layer: override_.layer.label().to_string(),
                reason: override_.reason.clone(),
            });
        }

        let match_info = result
            .pattern_info
            .as_ref()
            .or_else(|| result.allowlist_override.as_ref().map(|o| &o.matched));

        if let Some(info) = match_info {
            response.reason = Some(info.reason.clone());
            response.rule_id =
                Self::rule_id_from_match(info.pack_id.as_deref(), info.pattern_name.as_deref());
            response.pack_id.clone_from(&info.pack_id);
            response.pattern_name.clone_from(&info.pattern_name);
            response.severity = info.severity.map(|s| s.label().to_string());
            response.explanation.clone_from(&info.explanation);
            response
                .matched_text_preview
                .clone_from(&info.matched_text_preview);
        }

        response
    }

    fn explain_pattern(rule_id: &str) -> Result<ExplainPatternResponse, CallToolError> {
        let (pack_id, pattern_name) = rule_id
            .split_once(':')
            .ok_or_else(|| Self::call_tool_error("rule_id must be in 'pack:pattern' format"))?;

        let pack = REGISTRY
            .get(pack_id)
            .ok_or_else(|| Self::call_tool_error(format!("Unknown pack '{pack_id}'")))?;

        let pattern = pack
            .destructive_patterns
            .iter()
            .find(|p| p.name == Some(pattern_name))
            .ok_or_else(|| {
                Self::call_tool_error(format!(
                    "Pattern '{pattern_name}' not found in pack '{pack_id}'"
                ))
            })?;

        let reason = pattern.reason.to_string();
        let explanation = pattern.explanation.unwrap_or(pattern.reason).to_string();

        Ok(ExplainPatternResponse {
            rule_id: rule_id.to_string(),
            pack_id: pack_id.to_string(),
            pattern_name: pattern_name.to_string(),
            severity: pattern.severity.label().to_string(),
            reason,
            explanation,
        })
    }

    async fn scan_file_report(&self, path: String) -> Result<ScanReport, CallToolError> {
        let config = Arc::clone(&self.config);
        let scan_ctx = Arc::clone(&self.scan_ctx);

        Self::run_blocking_scan(move || {
            let path_buf = PathBuf::from(path);
            let options = Self::default_scan_options();
            let include: Vec<String> = Vec::new();
            let exclude: Vec<String> = Vec::new();

            scan_paths(
                &[path_buf],
                &options,
                config.as_ref(),
                scan_ctx.as_ref(),
                &include,
                &exclude,
                None,
            )
        })
        .await
    }

    async fn scan_file_tool(&self, path: String) -> Result<CallToolResult, CallToolError> {
        let report = self.scan_file_report(path).await?;
        Self::tool_result_json(&report)
    }

    async fn run_blocking_scan<F>(scan: F) -> Result<ScanReport, CallToolError>
    where
        F: FnOnce() -> Result<ScanReport, String> + Send + 'static,
    {
        tokio::task::spawn_blocking(scan)
            .await
            .map_err(|err| Self::call_tool_error(format!("scan_file worker failed: {err}")))?
            .map_err(Self::call_tool_error)
    }
}

impl Default for DcgMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ServerHandler for DcgMcpServer {
    async fn handle_list_tools_request(
        &self,
        _params: Option<PaginatedRequestParams>,
        _runtime: Arc<dyn McpServer>,
    ) -> Result<ListToolsResult, RpcError> {
        let tools = vec![
            Self::tool(
                "check_command",
                "Evaluate a command using dcg policy",
                Self::check_command_schema(),
            ),
            Self::tool(
                "scan_file",
                "Scan a file or directory for destructive commands",
                Self::tool_input_schema(
                    &["path"],
                    vec![(
                        "path",
                        Self::string_schema("File or directory path to scan"),
                    )],
                ),
            ),
            Self::tool(
                "explain_pattern",
                "Explain a dcg rule by rule_id",
                Self::tool_input_schema(
                    &["rule_id"],
                    vec![(
                        "rule_id",
                        Self::string_schema("Rule id in the form 'pack:pattern'"),
                    )],
                ),
            ),
        ];

        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    async fn handle_call_tool_request(
        &self,
        params: CallToolRequestParams,
        _runtime: Arc<dyn McpServer>,
    ) -> Result<CallToolResult, CallToolError> {
        match params.name.as_str() {
            "check_command" => {
                let response = self.check_command_arguments(params.arguments.as_ref())?;
                Self::tool_result_json(&response)
            }
            "scan_file" => {
                let path = Self::string_arg(params.arguments.as_ref(), "path")?;
                self.scan_file_tool(path).await
            }
            "explain_pattern" => {
                let rule_id = Self::string_arg(params.arguments.as_ref(), "rule_id")?;
                let response = Self::explain_pattern(&rule_id)?;
                Self::tool_result_json(&response)
            }
            other => Err(Self::call_tool_error(format!("Unknown tool '{other}'"))),
        }
    }
}

/// # Errors
///
/// Returns an error when the MCP server fails to initialize or run.
pub async fn run_mcp_server_async() -> Result<(), Box<dyn std::error::Error>> {
    let handler = DcgMcpServer::new();
    let server_details = handler.server_info.clone();
    let transport = StdioTransport::new(TransportOptions::default())?;
    let server = server_runtime::create_server(McpServerOptions {
        transport,
        handler: handler.to_mcp_server_handler(),
        server_details,
        task_store: None,
        client_task_store: None,
        message_observer: None,
    });
    server.start().await?;
    Ok(())
}

/// # Errors
///
/// Returns an error when the async runtime or MCP server fails to start.
pub fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_mcp_server_async())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{SCAN_SCHEMA_VERSION, ScanDecisionCounts, ScanSeverityCounts, ScanSummary};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn empty_scan_report() -> ScanReport {
        ScanReport {
            schema_version: SCAN_SCHEMA_VERSION,
            summary: ScanSummary {
                files_scanned: 0,
                files_skipped: 0,
                skipped: Vec::new(),
                paths_skipped: Vec::new(),
                commands_extracted: 0,
                findings_total: 0,
                decisions: ScanDecisionCounts::default(),
                severities: ScanSeverityCounts::default(),
                max_findings_reached: false,
                elapsed_ms: Some(0),
            },
            findings: Vec::new(),
        }
    }

    #[test]
    fn indeterminate_mcp_decision_is_never_reported_as_allowed() {
        for mode in [
            None,
            Some(crate::packs::DecisionMode::Deny),
            Some(crate::packs::DecisionMode::Ask),
            Some(crate::packs::DecisionMode::Warn),
            Some(crate::packs::DecisionMode::Log),
        ] {
            assert_eq!(
                mcp_decision_contract(EvaluationDecision::Indeterminate, mode),
                (false, "indeterminate")
            );
        }
    }

    #[test]
    fn mcp_decision_contract_reports_every_policy_mode_consistently() {
        use crate::packs::DecisionMode;

        assert_eq!(
            mcp_decision_contract(EvaluationDecision::Allow, Some(DecisionMode::Deny)),
            (true, "allow")
        );
        assert_eq!(
            mcp_decision_contract(EvaluationDecision::Deny, Some(DecisionMode::Deny)),
            (false, "deny")
        );
        assert_eq!(
            mcp_decision_contract(EvaluationDecision::Deny, Some(DecisionMode::Ask)),
            (false, "ask")
        );
        assert_eq!(
            mcp_decision_contract(EvaluationDecision::Deny, Some(DecisionMode::Warn)),
            (true, "warn")
        );
        assert_eq!(
            mcp_decision_contract(EvaluationDecision::Deny, Some(DecisionMode::Log)),
            (true, "log")
        );
    }

    #[test]
    fn check_command_dialect_schema_and_parser_agree() {
        let schema = serde_json::to_value(DcgMcpServer::check_command_schema()).unwrap();
        assert_eq!(schema["required"], serde_json::json!(["command"]));
        assert_eq!(schema["properties"]["dialect"]["default"], "unknown");
        let spellings = schema["properties"]["dialect"]["enum"].as_array().unwrap();
        assert_eq!(spellings.len(), 4);
        for (name, expected) in [
            ("unknown", ShellDialect::Unknown),
            ("posix", ShellDialect::Posix),
            ("powershell", ShellDialect::PowerShell),
            ("cmd", ShellDialect::Cmd),
        ] {
            assert!(spellings.contains(&serde_json::json!(name)));
            let args = serde_json::json!({"command": "git status", "dialect": name});
            assert_eq!(
                DcgMcpServer::dialect_arg(args.as_object()).unwrap(),
                expected
            );
        }
        assert_eq!(
            DcgMcpServer::dialect_arg(None).unwrap(),
            ShellDialect::Unknown
        );
        assert_eq!(
            DcgMcpServer::dialect_arg(Some(&Map::new())).unwrap(),
            ShellDialect::Unknown
        );
    }

    #[test]
    fn check_command_rejects_explicit_invalid_dialects() {
        for value in [
            Value::Null,
            serde_json::json!(false),
            serde_json::json!(42),
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::json!(""),
            serde_json::json!("bash"),
            serde_json::json!("POSIX"),
            serde_json::json!("posix "),
            serde_json::json!("future-shell"),
        ] {
            let args = serde_json::json!({"command": "git status", "dialect": value});
            assert!(
                DcgMcpServer::dialect_arg(args.as_object()).is_err(),
                "an unsupported dialect must not silently select another shell: {args}"
            );
        }
    }

    #[test]
    fn check_command_arguments_preserve_shell_semantics_and_source() {
        let mut server = DcgMcpServer::new();
        let config = Config::default();
        let mut context = ScanEvalContext::from_config(&config);
        context.allowlists = crate::allowlist::LayeredAllowlist::default();
        server.config = Arc::new(config);
        server.scan_ctx = Arc::new(context);

        // All commands are classifier data. In POSIX, the escaped ampersand
        // remains echo's argument; cmd.exe still executes the git command.
        for (command, dialect, allowed) in [
            (r"echo ok \& git reset --hard", "posix", true),
            (r"echo ok \& git reset --hard", "cmd", false),
            (r"echo ok \& git reset --hard", "unknown", false),
            ("echo ok & git reset --hard", "posix", false),
            ("Write-Output ok; git reset --hard", "powershell", false),
            ("git reset --hard", "posix", false),
            ("git reset --hard", "cmd", false),
            ("git reset --hard", "powershell", false),
            ("git status", "posix", true),
            ("git status", "cmd", true),
            ("git status", "powershell", true),
            ("git status", "unknown", true),
        ] {
            let args = serde_json::json!({"command": command, "dialect": dialect});
            let original = args.clone();
            let response = server.check_command_arguments(args.as_object()).unwrap();
            assert_eq!(response.allowed, allowed, "{dialect}: {command}");
            assert_eq!(response.decision, if allowed { "allow" } else { "deny" });
            assert_eq!(response.dialect, dialect);
            assert_eq!(
                args, original,
                "the adapter must preserve the command bytes"
            );
            if !allowed {
                assert_eq!(response.rule_id.as_deref(), Some("core.git:reset-hard"));
            }
        }
        let omitted = serde_json::json!({"command": r"echo ok \& git reset --hard"});
        let response = server.check_command_arguments(omitted.as_object()).unwrap();
        assert!(
            !response.allowed,
            "an omitted dialect retains the conservative union"
        );
        assert_eq!(response.dialect, "unknown");
        assert!(server.check_command_arguments(None).is_err());
        assert!(server.check_command_arguments(Some(&Map::new())).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_scan_worker_does_not_starve_lightweight_checks() {
        let server = DcgMcpServer::new();
        let scan_started = Arc::new(AtomicBool::new(false));
        let scan_started_in_worker = Arc::clone(&scan_started);

        let scan_future = DcgMcpServer::run_blocking_scan(move || {
            scan_started_in_worker.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(2));
            Ok(empty_scan_report())
        });
        let quick_future = async {
            // If the blocking scan were starving the async runtime, this quick
            // check could not complete until the scan's multi-second sleep
            // finished. The timeout is generous (well under the scan's sleep, but
            // far above any realistic scheduling jitter) so it detects genuine
            // starvation without flaking when workers are merely busy under load.
            let quick_check = tokio::time::timeout(Duration::from_secs(1), async {
                while !scan_started.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
                server.check_command("git status", ShellDialect::Unknown)
            })
            .await
            .expect("blocking scan should not starve the async runtime");

            assert!(quick_check.allowed);
        };

        let (scan_result, ()) = tokio::join!(scan_future, quick_future);
        let report = scan_result.expect("blocking scan should succeed");
        assert_eq!(report.schema_version, SCAN_SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn scan_file_report_scans_path_on_blocking_worker() {
        let temp_dir = tempfile::tempdir().unwrap();
        let script = temp_dir.path().join("danger.sh");
        std::fs::write(&script, "#!/bin/sh\nrm -rf /\n").unwrap();

        let server = DcgMcpServer::new();
        let report = server
            .scan_file_report(script.to_string_lossy().into_owned())
            .await
            .unwrap();

        assert_eq!(report.summary.files_scanned, 1);
        assert!(report.summary.commands_extracted >= 1);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.extracted_command.contains("rm -rf /"))
        );
    }
}
