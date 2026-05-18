package com.compliance.platform.reporter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.*;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Aggregates violation data, generates a markdown compliance report, uploads it to S3,
 * sends a summary email via SES, and persists the report record to PostgreSQL.
 *
 * <p>Design decisions:
 * <ul>
 *   <li><b>Graceful degradation:</b> S3 upload and SES email both catch exceptions and log
 *       warnings rather than failing the whole report run. This means a report is always
 *       persisted to the DB even when LocalStack is not running or email is unconfigured.</li>
 *   <li><b>Score reuse:</b> Compliance scores are computed with the same SQL as
 *       {@code GET /api/compliance-score} — single source of truth, no duplication logic.</li>
 *   <li><b>Section-boundary fidelity:</b> The markdown report references real control IDs
 *       (e.g. AC-3, SC-8) sourced directly from the violations table — not hard-coded labels.</li>
 * </ul>
 */
@Service
public class ReporterAgent {

    private static final Logger log = LoggerFactory.getLogger(ReporterAgent.class);

    private final JdbcTemplate jdbcTemplate;
    private final S3Client s3Client;
    private final SesV2Client sesV2Client;

    @Value("${aws.s3.reports-bucket:compliance-reports}")
    private String reportsBucket;

    @Value("${aws.ses.from-email:}")
    private String fromEmail;

    @Value("${aws.ses.to-email:}")
    private String toEmail;

    public ReporterAgent(JdbcTemplate jdbcTemplate,
                         S3Client s3Client,
                         SesV2Client sesV2Client) {
        this.jdbcTemplate = jdbcTemplate;
        this.s3Client = s3Client;
        this.sesV2Client = sesV2Client;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Generates a compliance report for today's date.
     * Convenience overload called by the Orchestrator on its nightly schedule.
     */
    public ComplianceReport generateReport() {
        return generateReport(LocalDate.now());
    }

    /**
     * Generates a compliance report for a specific date.
     * Useful for backfilling or manual triggers via {@code POST /api/reports/generate}.
     *
     * <p>Steps:
     * <ol>
     *   <li>Aggregate violation counts by framework and severity</li>
     *   <li>Fetch top-5 critical violations for the report body</li>
     *   <li>Compute per-framework compliance scores</li>
     *   <li>Render a structured markdown report</li>
     *   <li>Upload to S3 at {@code reports/YYYY-MM-DD.md} (graceful on failure)</li>
     *   <li>Send summary HTML email via SES (skipped if SES env vars not set)</li>
     *   <li>Persist {@code ComplianceReport} record to {@code compliance_reports} table</li>
     * </ol>
     *
     * @param reportDate the date label for the report (typically today)
     * @return the persisted {@link ComplianceReport}
     */
    public ComplianceReport generateReport(LocalDate reportDate) {
        log.info("Reporter starting — generating compliance report for {}", reportDate);

        // 1. Aggregate
        Map<String, Long> byFramework   = countViolationsByFramework();
        Map<String, Long> bySeverity    = countViolationsBySeverity();
        List<Map<String, Object>> top5  = fetchTop5CriticalViolations();
        Map<String, Double> scores      = fetchFrameworkScores();
        long totalViolations            = byFramework.values().stream().mapToLong(Long::longValue).sum();

        // 2. Render markdown
        String markdown = buildMarkdownReport(reportDate, byFramework, bySeverity, top5, scores, totalViolations);

        // 3. Upload to S3 — graceful: failure does not abort the run
        String s3Key = null;
        try {
            s3Key = uploadToS3(markdown, reportDate);
            log.info("Report uploaded — s3://{}/{}", reportsBucket, s3Key);
        } catch (Exception e) {
            log.warn("S3 upload failed (LocalStack running? bucket created?) — skipping S3 link: {}", e.getMessage());
        }

        // 4. Send SES email — skipped when from/to addresses are not configured
        if (!fromEmail.isBlank() && !toEmail.isBlank()) {
            try {
                sendEmail(reportDate, scores, totalViolations, s3Key, markdown);
                log.info("Compliance summary email sent to {}", toEmail);
            } catch (Exception e) {
                log.warn("SES send failed — verify sender identity in SES console: {}", e.getMessage());
            }
        } else {
            log.info("SES email skipped — SES_FROM_EMAIL / SES_TO_EMAIL not configured");
        }

        // 5. Persist to DB (always succeeds if DB is up)
        ComplianceReport report = persistReport(scores, (int) totalViolations, s3Key);
        log.info("Reporter complete — report {} persisted (total violations: {})", report.id(), totalViolations);
        return report;
    }

    // ── Aggregation ───────────────────────────────────────────────────────────

    private Map<String, Long> countViolationsByFramework() {
        Map<String, Long> result = new LinkedHashMap<>();
        jdbcTemplate.query(
                "SELECT framework, COUNT(*) AS cnt FROM violations GROUP BY framework ORDER BY framework",
                (RowCallbackHandler) rs -> result.put(rs.getString("framework"), rs.getLong("cnt")));
        return result;
    }

    private Map<String, Long> countViolationsBySeverity() {
        Map<String, Long> result = new LinkedHashMap<>();
        jdbcTemplate.query(
                """
                SELECT severity, COUNT(*) AS cnt
                FROM violations
                GROUP BY severity
                ORDER BY CASE severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END
                """,
                (RowCallbackHandler) rs -> result.put(rs.getString("severity"), rs.getLong("cnt")));
        return result;
    }

    private List<Map<String, Object>> fetchTop5CriticalViolations() {
        return jdbcTemplate.query(
                """
                SELECT resource_id, resource_type, control_id, framework, severity, reasoning
                FROM violations
                ORDER BY CASE severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
                         first_seen_at DESC
                LIMIT 5
                """,
                (rs, row) -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("resourceId",   rs.getString("resource_id"));
                    m.put("resourceType", rs.getString("resource_type"));
                    m.put("controlId",    rs.getString("control_id"));
                    m.put("framework",    rs.getString("framework"));
                    m.put("severity",     rs.getString("severity"));
                    m.put("reasoning",    rs.getString("reasoning"));
                    return m;
                });
    }

    /**
     * Computes per-framework compliance scores using the same SQL as
     * {@code GET /api/compliance-score}: (total_controls - violated_controls) / total_controls * 100.
     * Denominator is the count of distinct control IDs in the embeddings table — not a constant —
     * so the score reflects actual framework coverage, not an arbitrary ceiling.
     */
    private Map<String, Double> fetchFrameworkScores() {
        Map<String, Double> scores = new LinkedHashMap<>();
        jdbcTemplate.query(
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
                    CASE WHEN ft.total_controls = 0 THEN 0
                    ELSE ROUND(
                        (ft.total_controls - COALESCE(v.violated_controls, 0))::numeric
                        / ft.total_controls * 100, 1)
                    END AS score
                FROM framework_totals ft
                LEFT JOIN violated v ON v.framework = ft.framework
                ORDER BY ft.framework
                """,
                (RowCallbackHandler) rs -> scores.put(rs.getString("framework"), rs.getDouble("score")));
        return scores;
    }

    // ── Markdown report ───────────────────────────────────────────────────────

    /**
     * Renders a structured markdown compliance report.
     *
     * <p>Sections:
     * <ul>
     *   <li>Framework Scores table — percentage pass rate per framework</li>
     *   <li>Violation Summary — total count, breakdown by framework and by severity</li>
     *   <li>Top 5 Critical Violations — real control IDs, resource IDs, and Claude reasoning</li>
     * </ul>
     */
    private String buildMarkdownReport(LocalDate date,
                                       Map<String, Long> byFramework,
                                       Map<String, Long> bySeverity,
                                       List<Map<String, Object>> top5,
                                       Map<String, Double> scores,
                                       long total) {
        var sb = new StringBuilder();
        sb.append("# AWS Compliance Report — ").append(date).append("\n\n");
        sb.append("> Generated by Multi-Agent Compliance Platform\n\n");
        sb.append("---\n\n");

        // Framework Scores
        sb.append("## Framework Scores\n\n");
        sb.append("| Framework | Compliance Score |\n");
        sb.append("|---|---|\n");
        if (scores.isEmpty()) {
            sb.append("| No frameworks ingested yet | — |\n");
        } else {
            scores.forEach((fw, sc) ->
                    sb.append("| ").append(fw).append(" | **").append(sc).append("%** |\n"));
        }
        sb.append("\n");

        // Violation Summary
        sb.append("## Violation Summary\n\n");
        sb.append("**Total violations detected:** ").append(total).append("\n\n");

        sb.append("### By Framework\n\n");
        sb.append("| Framework | Count |\n|---|---|\n");
        if (byFramework.isEmpty()) {
            sb.append("| — | 0 |\n");
        } else {
            byFramework.forEach((fw, cnt) ->
                    sb.append("| ").append(fw).append(" | ").append(cnt).append(" |\n"));
        }
        sb.append("\n");

        sb.append("### By Severity\n\n");
        sb.append("| Severity | Count |\n|---|---|\n");
        if (bySeverity.isEmpty()) {
            sb.append("| — | 0 |\n");
        } else {
            bySeverity.forEach((sev, cnt) ->
                    sb.append("| ").append(sev).append(" | ").append(cnt).append(" |\n"));
        }
        sb.append("\n");

        // Top 5 Critical
        sb.append("## Top 5 Critical Violations\n\n");
        if (top5.isEmpty()) {
            sb.append("_No violations detected. Environment is clean._\n\n");
        } else {
            for (int i = 0; i < top5.size(); i++) {
                var v = top5.get(i);
                sb.append(i + 1).append(". **[").append(v.get("framework")).append("] ")
                  .append(v.get("controlId")).append("** — `").append(v.get("severity")).append("`\n");
                sb.append("   - **Resource:** `").append(v.get("resourceId"))
                  .append("` (").append(v.get("resourceType")).append(")\n");
                sb.append("   - **Reasoning:** ").append(v.get("reasoning")).append("\n\n");
            }
        }

        sb.append("---\n_Report generated: ").append(date).append("_\n");
        return sb.toString();
    }

    // ── S3 upload ─────────────────────────────────────────────────────────────

    /**
     * Uploads the markdown report to S3 at key {@code reports/YYYY-MM-DD.md}.
     * The bucket must exist before this call — create it with:
     * {@code awslocal s3 mb s3://compliance-reports} (LocalStack) or via the AWS Console.
     *
     * @return the S3 object key (not a full URL — relative to the bucket)
     */
    private String uploadToS3(String markdown, LocalDate date) {
        String key = "reports/" + date.format(DateTimeFormatter.ISO_LOCAL_DATE) + ".md";
        s3Client.putObject(
                PutObjectRequest.builder()
                        .bucket(reportsBucket)
                        .key(key)
                        .contentType("text/markdown; charset=UTF-8")
                        .build(),
                RequestBody.fromString(markdown));
        return key;
    }

    // ── SES email ─────────────────────────────────────────────────────────────

    /**
     * Sends a compliance summary email via SES v2.
     *
     * <p>Both the HTML body (formatted summary) and a plain-text fallback (the full markdown)
     * are attached so email clients that do not render HTML still display useful content.
     *
     * <p>Prerequisite: the {@code fromEmail} address must be verified in AWS SES
     * (Console → SES → Verified identities) before this call will succeed in production.
     * In LocalStack the verification step is skipped automatically.
     */
    private void sendEmail(LocalDate date, Map<String, Double> scores,
                           long totalViolations, String s3Key, String markdownFallback) {
        String subject = "AWS Compliance Report — " + date + " (" + totalViolations + " violations)";

        // HTML body
        var html = new StringBuilder();
        html.append("<h2>AWS Compliance Report — ").append(date).append("</h2>");
        html.append("<p><strong>Total violations:</strong> ").append(totalViolations).append("</p>");
        html.append("<h3>Framework Scores</h3><table border='1' cellpadding='4'>");
        html.append("<tr><th>Framework</th><th>Score</th></tr>");
        scores.forEach((fw, sc) ->
                html.append("<tr><td>").append(fw).append("</td><td>").append(sc).append("%</td></tr>"));
        html.append("</table>");
        if (s3Key != null) {
            html.append("<p>Full report stored in S3: <code>s3://")
                .append(reportsBucket).append("/").append(s3Key).append("</code></p>");
        }
        html.append("<hr><small>Generated by Multi-Agent Compliance Platform</small>");

        sesV2Client.sendEmail(SendEmailRequest.builder()
                .fromEmailAddress(fromEmail)
                .destination(Destination.builder().toAddresses(toEmail).build())
                .content(EmailContent.builder()
                        .simple(Message.builder()
                                .subject(Content.builder().data(subject).charset("UTF-8").build())
                                .body(Body.builder()
                                        .html(Content.builder().data(html.toString()).charset("UTF-8").build())
                                        .text(Content.builder().data(markdownFallback).charset("UTF-8").build())
                                        .build())
                                .build())
                        .build())
                .build());
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    private ComplianceReport persistReport(Map<String, Double> scores,
                                           int totalViolations,
                                           String s3Key) {
        UUID id          = UUID.randomUUID();
        double nistScore = scores.getOrDefault("NIST-800-53", 0.0);
        double cisScore  = scores.getOrDefault("CIS-AWS",     0.0);
        double soc2Score = scores.getOrDefault("SOC2",         0.0);

        jdbcTemplate.update(
                """
                INSERT INTO compliance_reports
                    (id, nist_score, cis_score, soc2_score, total_violations, s3_key)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                id, nistScore, cisScore, soc2Score, totalViolations, s3Key);

        return new ComplianceReport(id, nistScore, cisScore, soc2Score, totalViolations, s3Key);
    }
}
