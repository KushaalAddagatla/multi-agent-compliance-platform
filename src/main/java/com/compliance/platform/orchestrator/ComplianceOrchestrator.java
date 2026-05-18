package com.compliance.platform.orchestrator;

import com.compliance.platform.analyzer.AnalyzerAgent;
import com.compliance.platform.analyzer.Violation;
import com.compliance.platform.remediator.RemediatorAgent;
import com.compliance.platform.reporter.ComplianceReport;
import com.compliance.platform.reporter.ReporterAgent;
import com.compliance.platform.scanner.EnvironmentSnapshot;
import com.compliance.platform.scanner.ScannerAgent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Nightly orchestrator that coordinates the full four-agent pipeline.
 *
 * <p><b>Scheduled run:</b> {@code @Scheduled(cron = "0 0 2 * * *")} — fires at 02:00 every night.
 * Spring's scheduler runs in a single thread by default; a long pipeline run will delay the
 * next trigger (fixedDelay semantics), which is the correct behavior for a nightly batch job.
 *
 * <p><b>Pipeline sequence:</b>
 * <ol>
 *   <li>Record a {@code pipeline_runs} row with {@code status = RUNNING}</li>
 *   <li>{@link ScannerAgent#scanOnly()} — collects AWS state, persists snapshot, does NOT publish
 *       to SQS (avoids duplicate analysis by the SqsAnalyzerPoller)</li>
 *   <li>{@link AnalyzerAgent#analyze(EnvironmentSnapshot)} — RAG + Claude reasoning, writes violations</li>
 *   <li>Delta detection — marks violations that existed in prior runs as {@code is_new = false}</li>
 *   <li>{@link RemediatorAgent#remediate(List)} — generates remediation plans per violation</li>
 *   <li>{@link ReporterAgent#generateReport()} — aggregates, uploads to S3, sends SES email</li>
 *   <li>CloudWatch metrics — publishes {@code ViolationsFound} and {@code NewViolations}</li>
 *   <li>Updates {@code pipeline_runs} row with {@code status = COMPLETED}</li>
 * </ol>
 *
 * <p><b>Error handling:</b> if any step throws, the pipeline halts for that run,
 * the {@code pipeline_runs} row is updated to {@code FAILED}, and the error message is recorded.
 * A Scanner failure does not leave orphan remediation plans; a Reporter failure does not
 * block future pipeline runs.
 *
 * <p><b>Delta detection:</b> the {@code is_new} column on violations defaults to {@code true}.
 * After the Analyzer writes violations for the new scan run, a single UPDATE flips
 * {@code is_new = false} for any violation whose {@code (resource_id, control_id)} pair
 * appeared in any prior run. This is done in pure SQL — no Java-side set comparison.
 *
 * <p><b>Manual trigger:</b> {@link #triggerAsync()} is called by {@code POST /api/pipeline/trigger}.
 * It starts the pipeline in a background thread and returns the new run ID immediately,
 * so the HTTP request does not time out during long-running Claude calls.
 */
@Component
public class ComplianceOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ComplianceOrchestrator.class);

    private final ScannerAgent scannerAgent;
    private final AnalyzerAgent analyzerAgent;
    private final RemediatorAgent remediatorAgent;
    private final ReporterAgent reporterAgent;
    private final CloudWatchService cloudWatchService;
    private final JdbcTemplate jdbcTemplate;

    public ComplianceOrchestrator(ScannerAgent scannerAgent,
                                  AnalyzerAgent analyzerAgent,
                                  RemediatorAgent remediatorAgent,
                                  ReporterAgent reporterAgent,
                                  CloudWatchService cloudWatchService,
                                  JdbcTemplate jdbcTemplate) {
        this.scannerAgent = scannerAgent;
        this.analyzerAgent = analyzerAgent;
        this.remediatorAgent = remediatorAgent;
        this.reporterAgent = reporterAgent;
        this.cloudWatchService = cloudWatchService;
        this.jdbcTemplate = jdbcTemplate;
    }

    // ── Scheduled entry point ─────────────────────────────────────────────────

    /**
     * Nightly compliance pipeline — runs at 02:00 every day.
     * Delegates to {@link #executePipeline(UUID)} synchronously (scheduled thread waits for completion).
     */
    @Scheduled(cron = "0 0 2 * * *")
    public void runNightly() {
        log.info("Nightly compliance pipeline triggered by scheduler");
        UUID runId = startPipelineRun();
        executePipeline(runId);
    }

    // ── Manual trigger (called from REST endpoint) ────────────────────────────

    /**
     * Starts the pipeline in a background thread and returns the run ID immediately.
     * The caller can poll {@code GET /api/pipeline-runs} to observe completion.
     */
    public UUID triggerAsync() {
        UUID runId = startPipelineRun();
        log.info("Manual pipeline trigger — runId={}", runId);
        CompletableFuture.runAsync(() -> executePipeline(runId));
        return runId;
    }

    // ── Core pipeline ─────────────────────────────────────────────────────────

    private void executePipeline(UUID runId) {
        log.info("Pipeline starting — runId={}", runId);

        try {
            // Ensure CloudWatch alarm exists (idempotent no-op if already created)
            cloudWatchService.ensureViolationAlarm();

            // Step 1: Scan — does NOT publish to SQS to avoid duplicate analysis
            EnvironmentSnapshot snapshot;
            try {
                snapshot = scannerAgent.scanOnly();
            } catch (Exception e) {
                log.error("Scanner failed — aborting pipeline run {}: {}", runId, e.getMessage());
                failPipelineRun(runId, "Scanner failed: " + e.getMessage());
                return;
            }

            // Step 2: Analyze
            List<Violation> violations;
            try {
                violations = analyzerAgent.analyze(snapshot);
            } catch (Exception e) {
                log.error("Analyzer failed — aborting pipeline run {}: {}", runId, e.getMessage());
                failPipelineRun(runId, "Analyzer failed: " + e.getMessage());
                return;
            }

            // Step 3: Delta detection — mark persistent (pre-existing) violations as is_new = false
            markPersistentViolations(snapshot.scanRunId());
            int newViolations = countNewViolations(snapshot.scanRunId());
            log.info("Delta detection complete — total={} new={} persistent={}",
                    violations.size(), newViolations, violations.size() - newViolations);

            // Step 4: Remediate (non-fatal — missing plans don't abort the run)
            try {
                remediatorAgent.remediate(violations);
            } catch (Exception e) {
                log.warn("Remediator encountered errors — continuing: {}", e.getMessage());
            }

            // Step 5: Report (non-fatal — report failure shouldn't prevent metric publishing)
            try {
                ComplianceReport report = reporterAgent.generateReport();
                log.info("Report generated — id={} s3Key={}", report.id(), report.s3Key());
            } catch (Exception e) {
                log.warn("Reporter failed — continuing: {}", e.getMessage());
            }

            // Step 6: CloudWatch metrics
            cloudWatchService.publishPipelineMetrics(violations.size(), newViolations);

            // Step 7: Complete
            completePipelineRun(runId, violations.size(), newViolations);
            log.info("Pipeline complete — runId={} violations={} new={}",
                    runId, violations.size(), newViolations);

        } catch (Exception e) {
            log.error("Unexpected pipeline failure — runId={}: {}", runId, e.getMessage(), e);
            failPipelineRun(runId, "Unexpected: " + e.getMessage());
        }
    }

    // ── Delta detection ───────────────────────────────────────────────────────

    /**
     * Marks violations in {@code newScanRunId} as {@code is_new = false} if the same
     * {@code (resource_id, control_id)} pair exists in any previous scan run.
     *
     * <p>Implemented as a single SQL UPDATE — no Java-side set comparison needed.
     * Violations that first appeared in this run remain {@code is_new = true} (the default).
     */
    private void markPersistentViolations(UUID newScanRunId) {
        int updated = jdbcTemplate.update("""
                UPDATE violations v
                SET is_new = false
                WHERE v.scan_run_id = ?
                  AND EXISTS (
                      SELECT 1
                      FROM   violations old
                      WHERE  old.resource_id  = v.resource_id
                        AND  old.control_id   = v.control_id
                        AND  old.scan_run_id <> v.scan_run_id
                  )
                """, newScanRunId);
        log.debug("Marked {} persistent violations as is_new=false for scan_run_id={}",
                updated, newScanRunId);
    }

    private int countNewViolations(UUID scanRunId) {
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM violations WHERE scan_run_id = ? AND is_new = true",
                Integer.class, scanRunId);
        return count != null ? count : 0;
    }

    // ── Pipeline run tracking ─────────────────────────────────────────────────

    /**
     * Inserts a {@code pipeline_runs} row with {@code status = RUNNING}.
     * Returns the new run UUID — used to correlate all subsequent updates.
     */
    private UUID startPipelineRun() {
        UUID id = UUID.randomUUID();
        jdbcTemplate.update(
                "INSERT INTO pipeline_runs (id, status) VALUES (?, 'RUNNING')",
                id);
        return id;
    }

    private void completePipelineRun(UUID id, int violationsFound, int newViolations) {
        jdbcTemplate.update("""
                UPDATE pipeline_runs
                SET status = 'COMPLETED', end_time = ?, violations_found = ?, new_violations = ?
                WHERE id = ?
                """,
                Instant.now(), violationsFound, newViolations, id);
    }

    private void failPipelineRun(UUID id, String errorMessage) {
        jdbcTemplate.update("""
                UPDATE pipeline_runs
                SET status = 'FAILED', end_time = ?, error_message = ?
                WHERE id = ?
                """,
                Instant.now(), errorMessage, id);
    }
}
