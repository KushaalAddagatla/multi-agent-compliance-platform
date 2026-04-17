package com.compliance.platform.api;

import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * REST API for compliance findings and scan history.
 *
 * <p>Phase 2E endpoints — consumed by the React dashboard in Week 3:
 * <ul>
 *   <li>{@code GET /api/violations} — filterable violations list</li>
 *   <li>{@code GET /api/scan-runs}  — scan run history</li>
 * </ul>
 *
 * <p>Additional endpoints ({@code /api/violations/{id}}, {@code /api/compliance-score},
 * {@code /api/violations/{id}/remediation}, {@code PATCH /api/remediations/{id}/status},
 * {@code POST /api/violations/{id}/feedback}) are added in Week 3 / Phase 4.
 */
@RestController
@RequestMapping("/api")
public class ComplianceController {

    private final JdbcTemplate jdbcTemplate;

    public ComplianceController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
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
}
