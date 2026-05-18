package com.compliance.platform.api;

import com.compliance.platform.orchestrator.ComplianceOrchestrator;
import com.compliance.platform.reporter.ComplianceReport;
import com.compliance.platform.reporter.ReporterAgent;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * REST API for compliance findings, scores, and scan history.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code GET /api/violations}              — filterable violations list</li>
 *   <li>{@code GET /api/violations/{id}}          — violation detail</li>
 *   <li>{@code GET /api/compliance-score}         — per-framework pass/fail scores</li>
 *   <li>{@code GET /api/scan-runs}                — scan run history</li>
 *   <li>{@code GET /api/compliance-reports}       — past compliance report history</li>
 *   <li>{@code POST /api/reports/generate}        — manually trigger a report run</li>
 *   <li>{@code GET /api/pipeline-runs}            — pipeline run history</li>
 *   <li>{@code POST /api/pipeline/trigger}        — manually trigger a full pipeline run</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
public class ComplianceController {

    private final JdbcTemplate jdbcTemplate;
    private final ReporterAgent reporterAgent;
    private final ComplianceOrchestrator orchestrator;

    public ComplianceController(JdbcTemplate jdbcTemplate,
                                ReporterAgent reporterAgent,
                                ComplianceOrchestrator orchestrator) {
        this.jdbcTemplate = jdbcTemplate;
        this.reporterAgent = reporterAgent;
        this.orchestrator = orchestrator;
    }

    // ── GET /api/violations ───────────────────────────────────────────────────

    /**
     * Returns a list of violations, newest first.
     * NEW violations (first occurrence in a run) are sorted to the top.
     *
     * @param framework optional filter — NIST-800-53 | CIS-AWS | SOC2
     * @param severity  optional filter — HIGH | MEDIUM | LOW
     * @param limit     max rows returned (default 100)
     */
    @GetMapping("/violations")
    public ResponseEntity<List<Map<String, Object>>> getViolations(
            @RequestParam(required = false) String framework,
            @RequestParam(required = false) String severity,
            @RequestParam(defaultValue = "100") int limit) {

        StringBuilder sql = new StringBuilder("""
                SELECT id, scan_run_id, resource_id, resource_type, control_id, framework,
                       severity, reasoning, cited_excerpt, first_seen_at, is_new
                FROM violations
                WHERE 1=1
                """);
        List<Object> params = new ArrayList<>();

        if (framework != null && !framework.isBlank()) {
            sql.append(" AND framework = ?");
            params.add(framework);
        }
        if (severity != null && !severity.isBlank()) {
            sql.append(" AND UPPER(severity) = UPPER(?)");
            params.add(severity);
        }
        sql.append(" ORDER BY is_new DESC, first_seen_at DESC LIMIT ?");
        params.add(limit);

        List<Map<String, Object>> rows = jdbcTemplate.query(
                sql.toString(), this::mapViolationRow, params.toArray());

        return ResponseEntity.ok(rows);
    }

    // ── GET /api/violations/{id} ──────────────────────────────────────────────

    /**
     * Returns a single violation by UUID, or 404 if not found.
     */
    @GetMapping("/violations/{id}")
    public ResponseEntity<Map<String, Object>> getViolation(@PathVariable String id) {
        List<Map<String, Object>> rows = jdbcTemplate.query(
                """
                SELECT id, scan_run_id, resource_id, resource_type, control_id, framework,
                       severity, reasoning, cited_excerpt, first_seen_at, is_new
                FROM violations
                WHERE id = ?::uuid
                """,
                this::mapViolationRow,
                id);

        if (rows.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(rows.get(0));
    }

    // ── GET /api/compliance-score ─────────────────────────────────────────────

    /**
     * Returns a per-framework compliance score.
     *
     * <p>Score = (total_distinct_controls_in_framework - violated_distinct_controls) /
     *             total_distinct_controls_in_framework * 100, rounded to one decimal.
     *
     * <p>Denominator comes from the {@code embeddings} table (the ingested framework
     * knowledge base), so the score reflects how many real controls are covered, not
     * an arbitrary constant. If no embeddings exist for a framework yet, score is 0.
     */
    @GetMapping("/compliance-score")
    public ResponseEntity<Map<String, Object>> getComplianceScore() {
        List<Map<String, Object>> frameworkScores = jdbcTemplate.query(
                """
                WITH framework_totals AS (
                    SELECT framework, COUNT(DISTINCT control_id) AS total_controls
                    FROM embeddings
                    GROUP BY framework
                ),
                violated AS (
                    SELECT framework, COUNT(DISTINCT control_id) AS violated_controls
                    FROM violations
                    GROUP BY framework
                )
                SELECT
                    ft.framework,
                    ft.total_controls,
                    COALESCE(v.violated_controls, 0)                        AS violated_controls,
                    ROUND(
                        CASE WHEN ft.total_controls = 0 THEN 0
                        ELSE (ft.total_controls - COALESCE(v.violated_controls, 0))::numeric
                             / ft.total_controls * 100
                        END, 1
                    )                                                        AS score
                FROM framework_totals ft
                LEFT JOIN violated v ON v.framework = ft.framework
                ORDER BY ft.framework
                """,
                (rs, row) -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("framework",        rs.getString("framework"));
                    m.put("totalControls",    rs.getLong("total_controls"));
                    m.put("violatedControls", rs.getLong("violated_controls"));
                    m.put("score",            rs.getDouble("score"));
                    return m;
                });

        double overall = frameworkScores.isEmpty() ? 0.0
                : frameworkScores.stream()
                        .mapToDouble(m -> (Double) m.get("score"))
                        .average()
                        .orElse(0.0);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("frameworks", frameworkScores);
        response.put("overallScore", Math.round(overall * 10.0) / 10.0);

        return ResponseEntity.ok(response);
    }

    // ── POST /api/violations/{id}/feedback ───────────────────────────────────

    /**
     * Records a false-positive flag on a violation.
     * Stored to {@code false_positive_feedback} and later injected as few-shot examples
     * into the Analyzer prompt (Phase 4) to reduce repeat false positives over time.
     */
    @PostMapping("/violations/{id}/feedback")
    public ResponseEntity<Void> submitFeedback(
            @PathVariable String id,
            @RequestBody Map<String, String> body) {

        String reason = body.getOrDefault("reason", "Marked as false positive");
        jdbcTemplate.update(
                "INSERT INTO false_positive_feedback (violation_id, reason) VALUES (?::uuid, ?)",
                id, reason);
        return ResponseEntity.ok().build();
    }

    // ── GET /api/violations/{id}/remediation ─────────────────────────────────

    /**
     * Returns the remediation plan for a given violation, or 404 if none exists yet.
     * The Remediator Agent generates plans lazily — this endpoint returning 404 simply
     * means the Orchestrator hasn't run a remediation pass for this violation yet.
     */
    @GetMapping("/violations/{id}/remediation")
    public ResponseEntity<Map<String, Object>> getRemediation(@PathVariable String id) {
        if (!isValidUuid(id)) return ResponseEntity.notFound().build();
        List<Map<String, Object>> rows = jdbcTemplate.query(
                """
                SELECT id, violation_id, steps, cli_commands, terraform_patch,
                       auto_remediable, approval_status, created_at, updated_at
                FROM remediation_plans
                WHERE violation_id = ?::uuid
                ORDER BY created_at DESC
                LIMIT 1
                """,
                this::mapRemediationRow,
                id);

        if (rows.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(rows.get(0));
    }

    // ── PATCH /api/remediations/{id}/status ──────────────────────────────────

    /**
     * Approves or rejects a remediation plan.
     *
     * <p>This endpoint records the human decision — it does NOT execute any AWS changes.
     * Execution is intentionally out of scope: the human-in-the-loop gate is an
     * architectural safety decision, not a missing feature.
     *
     * @param body must contain {@code "status"}: PENDING | APPROVED | REJECTED
     */
    @PatchMapping("/remediations/{id}/status")
    public ResponseEntity<Void> updateRemediationStatus(
            @PathVariable String id,
            @RequestBody Map<String, String> body) {

        if (!isValidUuid(id)) return ResponseEntity.notFound().build();
        String status = body.get("status");
        if (status == null || !List.of("PENDING", "APPROVED", "REJECTED").contains(status)) {
            return ResponseEntity.badRequest().build();
        }

        int updated = jdbcTemplate.update(
                """
                UPDATE remediation_plans
                SET approval_status = ?, updated_at = NOW()
                WHERE id = ?::uuid
                """,
                status, id);

        return updated > 0 ? ResponseEntity.ok().build() : ResponseEntity.notFound().build();
    }

    // ── GET /api/scan-runs ────────────────────────────────────────────────────

    /**
     * Returns recent scan run history, newest first.
     *
     * @param limit max rows returned (default 20)
     */
    @GetMapping("/scan-runs")
    public ResponseEntity<List<Map<String, Object>>> getScanRuns(
            @RequestParam(defaultValue = "20") int limit) {

        List<Map<String, Object>> rows = jdbcTemplate.query(
                """
                SELECT s.id,
                       s.created_at,
                       COUNT(v.id) AS violation_count
                FROM scan_runs s
                LEFT JOIN violations v ON v.scan_run_id = s.id
                GROUP BY s.id, s.created_at
                ORDER BY s.created_at DESC
                LIMIT ?
                """,
                this::mapScanRunRow,
                limit);

        return ResponseEntity.ok(rows);
    }

    // ── GET /api/compliance-reports ──────────────────────────────────────────

    /**
     * Returns recent compliance reports, newest first.
     *
     * @param limit max rows returned (default 20)
     */
    @GetMapping("/compliance-reports")
    public ResponseEntity<List<Map<String, Object>>> getComplianceReports(
            @RequestParam(defaultValue = "20") int limit) {

        List<Map<String, Object>> rows = jdbcTemplate.query(
                """
                SELECT id, nist_score, cis_score, soc2_score, total_violations, s3_key, created_at
                FROM compliance_reports
                ORDER BY created_at DESC
                LIMIT ?
                """,
                this::mapReportRow,
                limit);

        return ResponseEntity.ok(rows);
    }

    // ── POST /api/reports/generate ────────────────────────────────────────────

    /**
     * Manually triggers a compliance report run for today's date.
     *
     * <p>This is equivalent to the nightly Orchestrator-triggered report but invocable on demand.
     * The response contains the persisted report record including any S3 key if upload succeeded.
     */
    @PostMapping("/reports/generate")
    public ResponseEntity<Map<String, Object>> generateReport() {
        ComplianceReport report = reporterAgent.generateReport();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id",              report.id().toString());
        response.put("nistScore",       report.nistScore());
        response.put("cisScore",        report.cisScore());
        response.put("soc2Score",       report.soc2Score());
        response.put("totalViolations", report.totalViolations());
        response.put("s3Key",           report.s3Key());
        response.put("createdAt",       report.createdAt().toString());
        return ResponseEntity.ok(response);
    }

    // ── GET /api/pipeline-runs ────────────────────────────────────────────────

    /**
     * Returns recent pipeline run history, newest first.
     * Each row shows run status, timing, violation counts, and any error message.
     *
     * @param limit max rows returned (default 20)
     */
    @GetMapping("/pipeline-runs")
    public ResponseEntity<List<Map<String, Object>>> getPipelineRuns(
            @RequestParam(defaultValue = "20") int limit) {

        List<Map<String, Object>> rows = jdbcTemplate.query(
                """
                SELECT id, start_time, end_time, status,
                       violations_found, new_violations, error_message
                FROM pipeline_runs
                ORDER BY start_time DESC
                LIMIT ?
                """,
                this::mapPipelineRunRow,
                limit);

        return ResponseEntity.ok(rows);
    }

    // ── POST /api/pipeline/trigger ────────────────────────────────────────────

    /**
     * Manually triggers a full compliance pipeline run (Scanner → Analyzer →
     * Remediator → Reporter) in the background.
     *
     * <p>Returns immediately with the new pipeline run ID and {@code status = RUNNING}.
     * Poll {@code GET /api/pipeline-runs} to observe completion.
     */
    @PostMapping("/pipeline/trigger")
    public ResponseEntity<Map<String, Object>> triggerPipeline() {
        java.util.UUID runId = orchestrator.triggerAsync();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("pipelineRunId", runId.toString());
        response.put("status", "RUNNING");
        response.put("message", "Pipeline started — poll GET /api/pipeline-runs to track progress");
        return ResponseEntity.accepted().body(response);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean isValidUuid(String s) {
        try { UUID.fromString(s); return true; } catch (IllegalArgumentException e) { return false; }
    }

    // ── Row mappers ───────────────────────────────────────────────────────────

    private Map<String, Object> mapViolationRow(ResultSet rs, int row) throws SQLException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",           rs.getObject("id").toString());
        m.put("scanRunId",    rs.getObject("scan_run_id").toString());
        m.put("resourceId",   rs.getString("resource_id"));
        m.put("resourceType", rs.getString("resource_type"));
        m.put("controlId",    rs.getString("control_id"));
        m.put("framework",    rs.getString("framework"));
        m.put("severity",     rs.getString("severity"));
        m.put("reasoning",    rs.getString("reasoning"));
        m.put("citedExcerpt", rs.getString("cited_excerpt"));
        m.put("firstSeenAt",  rs.getTimestamp("first_seen_at").toInstant().toString());
        m.put("isNew",        rs.getBoolean("is_new"));
        return m;
    }

    private Map<String, Object> mapScanRunRow(ResultSet rs, int row) throws SQLException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",             rs.getObject("id").toString());
        m.put("createdAt",      rs.getTimestamp("created_at").toInstant().toString());
        m.put("violationCount", rs.getLong("violation_count"));
        return m;
    }

    private Map<String, Object> mapRemediationRow(ResultSet rs, int row) throws SQLException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",              rs.getObject("id").toString());
        m.put("violationId",     rs.getObject("violation_id").toString());
        m.put("steps",           rs.getString("steps"));
        m.put("cliCommands",     rs.getString("cli_commands"));
        m.put("terraformPatch",  rs.getString("terraform_patch"));
        m.put("autoRemediable",  rs.getBoolean("auto_remediable"));
        m.put("approvalStatus",  rs.getString("approval_status"));
        m.put("createdAt",       rs.getTimestamp("created_at").toInstant().toString());
        m.put("updatedAt",       rs.getTimestamp("updated_at").toInstant().toString());
        return m;
    }

    private Map<String, Object> mapReportRow(ResultSet rs, int row) throws SQLException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",              rs.getObject("id").toString());
        m.put("nistScore",       rs.getDouble("nist_score"));
        m.put("cisScore",        rs.getDouble("cis_score"));
        m.put("soc2Score",       rs.getDouble("soc2_score"));
        m.put("totalViolations", rs.getInt("total_violations"));
        m.put("s3Key",           rs.getString("s3_key"));
        m.put("createdAt",       rs.getTimestamp("created_at").toInstant().toString());
        return m;
    }

    private Map<String, Object> mapPipelineRunRow(ResultSet rs, int row) throws SQLException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",              rs.getObject("id").toString());
        m.put("startTime",       rs.getTimestamp("start_time").toInstant().toString());
        var endTs = rs.getTimestamp("end_time");
        m.put("endTime",         endTs != null ? endTs.toInstant().toString() : null);
        m.put("status",          rs.getString("status"));
        m.put("violationsFound", rs.getInt("violations_found"));
        m.put("newViolations",   rs.getInt("new_violations"));
        m.put("errorMessage",    rs.getString("error_message"));
        return m;
    }
}
