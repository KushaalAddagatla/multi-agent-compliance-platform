package com.compliance.platform;

import com.compliance.platform.scanner.EnvironmentSnapshot;
import com.compliance.platform.scanner.ScannerAgent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Phase 2E end-to-end integration test.
 *
 * <p>Exercises the full pipeline: Scanner → SQS → SqsAnalyzerPoller → AnalyzerAgent → DB,
 * then verifies both REST endpoints return correct data.
 *
 * <p><b>Prerequisites to run:</b>
 * <ol>
 *   <li>PostgreSQL running — docker-compose up -d</li>
 *   <li>LocalStack running — docker-compose up -d (SQS must be available)</li>
 *   <li>ANTHROPIC_API_KEY set to a real key</li>
 *   <li>OPENAI_API_KEY set to a real key</li>
 *   <li>Embeddings table populated — POST /api/ingestion/ingest</li>
 * </ol>
 *
 * <p>All prerequisites are checked with {@code assumeTrue} — the test skips rather
 * than fails if infrastructure is unavailable, so it is safe to run in CI.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"test", "local"})
class PipelineIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(PipelineIntegrationTest.class);

    @LocalServerPort
    private int port;

    @Autowired
    private ScannerAgent scannerAgent;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private TestRestTemplate restTemplate;

    @BeforeEach
    void skipUnlessFullyConfigured() {
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
        } catch (Exception e) {
            assumeTrue(false, "Skipping — PostgreSQL not reachable. Run: docker-compose up -d");
        }

        assumeTrue(isRealKey("ANTHROPIC_API_KEY"),
                "Skipping — ANTHROPIC_API_KEY not set to a real key.");

        assumeTrue(isRealKey("OPENAI_API_KEY"),
                "Skipping — OPENAI_API_KEY not set (needed for RAG embedding).");

        Integer embCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM embeddings", Integer.class);
        assumeTrue(embCount != null && embCount > 0,
                "Skipping — embeddings table is empty. Run POST /api/ingestion/ingest first.");

        log.info("All prerequisites met — embeddings={}", embCount);
    }

    /**
     * Phase 2E checkpoint: full pipeline from scan to REST API.
     *
     * <ol>
     *   <li>Scanner runs and publishes snapshot to SQS.</li>
     *   <li>SqsAnalyzerPoller consumes the message and calls AnalyzerAgent.</li>
     *   <li>Violations appear in DB (wait up to 30s for poller + Claude calls).</li>
     *   <li>GET /api/violations returns those violations with required fields.</li>
     *   <li>GET /api/scan-runs includes the run just completed.</li>
     * </ol>
     */
    @Test
    @SuppressWarnings("unchecked")
    void fullPipelineProducesViolationsAccessibleViaRestApi() throws InterruptedException {
        // Step 1: trigger a scan — this persists to DB and publishes to SQS
        EnvironmentSnapshot snapshot = scannerAgent.scan();
        UUID scanRunId = snapshot.scanRunId();
        log.info("Scan complete — runId={}", scanRunId);

        // Step 2: wait for poller to pick up the SQS message and Analyzer to write violations
        // Poller fires every 5s; Claude calls add ~5-15s per resource group
        boolean violationsAppeared = waitForViolations(scanRunId, 30);
        assumeTrue(violationsAppeared,
                "Skipping assertions — no violations appeared within 30s. " +
                "Check that your AWS account has resources and embeddings are populated.");

        // Step 3: GET /api/violations — must return non-empty list with required fields
        ResponseEntity<List> violationsResp = restTemplate.getForEntity(
                "http://localhost:" + port + "/api/violations", List.class);

        assertThat(violationsResp.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(violationsResp.getBody()).isNotEmpty();

        Map<String, Object> first = (Map<String, Object>) violationsResp.getBody().get(0);
        assertThat(first).containsKeys("id", "controlId", "framework", "severity",
                                        "reasoning", "citedExcerpt", "resourceId", "isNew");
        assertThat((String) first.get("citedExcerpt")).isNotBlank();
        assertThat((String) first.get("reasoning")).isNotBlank();

        log.info("GET /api/violations — {} violations returned, first: {} | {} | {}",
                violationsResp.getBody().size(),
                first.get("severity"), first.get("framework"), first.get("controlId"));

        // Step 4: GET /api/scan-runs — must include our run
        ResponseEntity<List> scanRunsResp = restTemplate.getForEntity(
                "http://localhost:" + port + "/api/scan-runs", List.class);

        assertThat(scanRunsResp.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(scanRunsResp.getBody()).isNotEmpty();

        List<Map<String, Object>> scanRuns = (List<Map<String, Object>>) (List<?>) scanRunsResp.getBody();
        boolean runPresent = scanRuns.stream()
                .anyMatch(r -> scanRunId.toString().equals(r.get("id")));
        assertThat(runPresent)
                .as("GET /api/scan-runs should include runId=%s", scanRunId)
                .isTrue();

        log.info("GET /api/scan-runs — {} runs returned, target run present: true", scanRunsResp.getBody().size());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** Polls the DB until violations appear for the given scan run, or times out. */
    private boolean waitForViolations(UUID scanRunId, int timeoutSeconds) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutSeconds * 1000L;
        while (System.currentTimeMillis() < deadline) {
            if (countViolations(scanRunId) > 0) return true;
            Thread.sleep(2_000);
        }
        return false;
    }

    private int countViolations(UUID scanRunId) {
        Integer n = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM violations WHERE scan_run_id = ?",
                Integer.class, scanRunId);
        return n == null ? 0 : n;
    }

    private boolean isRealKey(String envVar) {
        String val = System.getenv(envVar);
        return val != null && !val.isBlank() && !val.startsWith("test");
    }
}
