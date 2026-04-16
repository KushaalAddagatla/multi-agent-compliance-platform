package com.compliance.platform.retrieval;

import com.compliance.platform.model.RetrievedChunk;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test for the RAG retrieval path.
 *
 * <p><b>Prerequisites to run:</b>
 * <ol>
 *   <li>PostgreSQL running (docker-compose up -d)</li>
 *   <li>OPENAI_API_KEY set to a real key</li>
 *   <li>Embeddings table populated: {@code POST /api/ingestion/ingest}</li>
 * </ol>
 *
 * <p>Tests auto-skip (not fail) when prerequisites are not met, so they are safe to run in CI.
 */
@SpringBootTest
@ActiveProfiles("test")
class RetrievalServiceTest {

    private static final Logger log = LoggerFactory.getLogger(RetrievalServiceTest.class);

    @Autowired
    private RetrievalService retrievalService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void skipUnlessFullyConfigured() {
        // Skip if OPENAI_API_KEY is a placeholder — real embeddings API call required
        String apiKey = System.getenv("OPENAI_API_KEY");
        assumeTrue(apiKey != null && !apiKey.isBlank() && !apiKey.startsWith("test"),
                "Skipping — OPENAI_API_KEY not set to a real key. " +
                "Export the variable and re-run this test.");

        // Skip if embeddings table is empty — no data to retrieve
        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM embeddings", Integer.class);
        assumeTrue(count != null && count > 0,
                "Skipping — embeddings table is empty. " +
                "Run POST /api/ingestion/ingest first, then re-run this test.");

        log.info("Embeddings table has {} rows — proceeding with retrieval tests", count);
    }

    /**
     * Phase 1E checkpoint #1: AC-3 should surface for an access enforcement question.
     * This validates that the section-boundary chunking produced semantically coherent chunks
     * that embed correctly and are retrieved precisely.
     */
    @Test
    void accessEnforcementQuestionReturnsAccessControlChunks() {
        String question = "What does AC-3 require for access enforcement?";
        List<RetrievedChunk> results = retrievalService.search(question, 3);

        log.info("\n══════════════════════════════════════════════════════════════");
        log.info("Query: \"{}\"", question);
        log.info("══════════════════════════════════════════════════════════════");
        printChunks(results);

        assertThat(results).isNotEmpty();
        // Top result should be from the AC (Access Control) family
        assertThat(results.get(0).controlId())
                .as("Top result for an AC-3 question should be an AC-family control")
                .startsWith("AC");
    }

    /**
     * Phase 1E checkpoint #2: SI-2 should surface for a patch management question.
     * SI-2 (Flaw Remediation) is the NIST patch management control.
     */
    @Test
    void patchManagementQuestionReturnsSI2() {
        String question = "What are the requirements for patch management and flaw remediation?";
        List<RetrievedChunk> results = retrievalService.search(question, 3);

        log.info("\n══════════════════════════════════════════════════════════════");
        log.info("Query: \"{}\"", question);
        log.info("══════════════════════════════════════════════════════════════");
        printChunks(results);

        assertThat(results).isNotEmpty();
        // SI-2 (Flaw Remediation) is the canonical patch management control in NIST 800-53
        boolean siControlFound = results.stream().anyMatch(r -> r.controlId().startsWith("SI"));
        assertThat(siControlFound)
                .as("Expected SI-family control (patch management) in top 3 results")
                .isTrue();
    }

    /**
     * Sanity check: framework-scoped search returns only rows from that framework.
     */
    @Test
    void frameworkScopeFilterIsRespected() {
        boolean nistExists = Boolean.TRUE.equals(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) > 0 FROM embeddings WHERE framework = 'NIST-800-53'", Boolean.class));
        assumeTrue(nistExists, "Skipping — no NIST-800-53 rows in embeddings table");

        List<RetrievedChunk> results = retrievalService.search("access control policy", 5, "NIST-800-53");

        assertThat(results).isNotEmpty();
        assertThat(results).allMatch(r -> "NIST-800-53".equals(r.framework()),
                "All results should be NIST-800-53 when framework filter is applied");

        log.info("Framework-scoped search returned {} NIST-800-53 results", results.size());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private void printChunks(List<RetrievedChunk> chunks) {
        for (int i = 0; i < chunks.size(); i++) {
            RetrievedChunk c = chunks.get(i);
            int previewLen = Math.min(300, c.content().length());
            log.info("\n[{}/{}] {} | {} | {} | similarity={}",
                    i + 1, chunks.size(),
                    c.controlId(), c.framework(), c.severity(),
                    String.format("%.4f", c.similarity()));
            log.info("{}", c.content().substring(0, previewLen));
            if (c.content().length() > 300) {
                log.info("... ({} chars total)", c.content().length());
            }
        }
    }
}
