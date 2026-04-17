package com.compliance.platform.analyzer;

import com.compliance.platform.scanner.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test for Phase 2C — Analyzer Agent checkpoint.
 *
 * <p><b>Prerequisites to run:</b>
 * <ol>
 *   <li>PostgreSQL running (docker-compose up -d)</li>
 *   <li>ANTHROPIC_API_KEY set to a real key</li>
 *   <li>OPENAI_API_KEY set to a real key</li>
 *   <li>Embeddings table populated (POST /api/ingestion/ingest)</li>
 * </ol>
 *
 * <p>Tests auto-skip when prerequisites are not met.
 */
@SpringBootTest
@ActiveProfiles({"test", "local"})
class AnalyzerAgentTest {

    private static final Logger log = LoggerFactory.getLogger(AnalyzerAgentTest.class);

    @Autowired
    private AnalyzerAgent analyzerAgent;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void skipUnlessFullyConfigured() {
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
        } catch (Exception e) {
            assumeTrue(false, "Skipping — PostgreSQL not reachable. Run: docker-compose up -d");
        }

        String anthropicKey = System.getenv("ANTHROPIC_API_KEY");
        assumeTrue(anthropicKey != null && !anthropicKey.isBlank() && !anthropicKey.startsWith("test"),
                "Skipping — ANTHROPIC_API_KEY not set to a real key.");

        String openaiKey = System.getenv("OPENAI_API_KEY");
        assumeTrue(openaiKey != null && !openaiKey.isBlank() && !openaiKey.startsWith("test"),
                "Skipping — OPENAI_API_KEY not set (needed for RAG embedding).");

        Integer embeddingCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM embeddings", Integer.class);
        assumeTrue(embeddingCount != null && embeddingCount > 0,
                "Skipping — embeddings table is empty. Run POST /api/ingestion/ingest first.");

        log.info("Prerequisites satisfied — embeddings={}", embeddingCount);
    }

    /**
     * Phase 2C checkpoint: Analyzer produces violations with non-null citedExcerpt
     * when given a snapshot containing resources with known compliance issues.
     *
     * <p>The snapshot uses synthetic resources designed to trigger violations:
     * an IAM user with a 120-day-old key (>90 day threshold) and
     * a publicly accessible S3 bucket.
     */
    @Test
    void analyzeSnapshotProducesViolationsWithCitations() {
        UUID scanRunId = insertTestScanRun();

        // IAM user with a 120-day-old active key — should trigger IA-5 / key rotation violation
        IamUserInfo oldKeyUser = new IamUserInfo(
                "test-user-old-key",
                "arn:aws:iam::123456789:user/test-user-old-key",
                List.of(new AccessKeyInfo("AKIATEST123", "Active", 120, true)));

        // S3 bucket with AllUsers ACL grant — should trigger public exposure violation
        S3BucketInfo publicBucket = new S3BucketInfo(
                "test-public-bucket",
                true,
                List.of("http://acs.amazonaws.com/groups/global/AllUsers"));

        EnvironmentSnapshot snapshot = new EnvironmentSnapshot(
                scanRunId,
                List.of(),          // no EC2 instances
                List.of(oldKeyUser),
                List.of(publicBucket),
                List.of(),          // no ECS tasks
                Instant.now());

        int violationsBefore = countViolations(scanRunId);

        List<Violation> violations = analyzerAgent.analyze(snapshot);

        // Checkpoint 1: violations were returned
        assertThat(violations).isNotEmpty();

        // Checkpoint 2: every violation has a non-null citedExcerpt
        assertThat(violations).allSatisfy(v -> {
            assertThat(v.citedExcerpt())
                    .as("citedExcerpt must not be null for violation on %s", v.resourceId())
                    .isNotNull()
                    .isNotBlank();
            assertThat(v.reasoning()).isNotNull().isNotBlank();
            assertThat(v.controlId()).isNotNull().isNotBlank();
            assertThat(v.framework()).isIn("NIST-800-53", "CIS-AWS", "SOC2");
            assertThat(v.severity()).isIn("HIGH", "MEDIUM", "LOW");
        });

        // Checkpoint 3: violations were persisted to DB
        assertThat(countViolations(scanRunId)).isGreaterThan(violationsBefore);

        logViolations(violations);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** Insert a synthetic scan_run row so the violation FK constraint is satisfied. */
    private UUID insertTestScanRun() {
        UUID id = UUID.randomUUID();
        jdbcTemplate.update(
                "INSERT INTO scan_runs (id, snapshot_json) VALUES (?, CAST(? AS jsonb))",
                id, "{\"test\":true}");
        return id;
    }

    private int countViolations(UUID scanRunId) {
        Integer n = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM violations WHERE scan_run_id = ?",
                Integer.class, scanRunId);
        return n == null ? 0 : n;
    }

    private void logViolations(List<Violation> violations) {
        log.info("\n══════════════════════════════════════════════════════════════");
        log.info("Violations found: {}", violations.size());
        log.info("══════════════════════════════════════════════════════════════");
        for (Violation v : violations) {
            log.info("[{}] {} | {} | {} | {}", v.severity(), v.resourceId(), v.framework(), v.controlId(), v.resourceType());
            log.info("  Reasoning:    {}", v.reasoning());
            log.info("  CitedExcerpt: {}", v.citedExcerpt());
        }
    }
}
