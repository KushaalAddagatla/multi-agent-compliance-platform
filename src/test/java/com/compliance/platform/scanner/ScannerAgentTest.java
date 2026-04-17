package com.compliance.platform.scanner;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test for Phase 2B — Scanner Agent checkpoint.
 *
 * <p><b>Prerequisites to run:</b>
 * <ol>
 *   <li>PostgreSQL running (docker-compose up -d)</li>
 *   <li>LocalStack running (docker-compose up -d)</li>
 * </ol>
 *
 * <p>Tests auto-skip (not fail) when prerequisites are not met, so they are
 * safe to run in CI without real infrastructure.
 */
@SpringBootTest
@ActiveProfiles({"test", "local"})
class ScannerAgentTest {

    private static final Logger log = LoggerFactory.getLogger(ScannerAgentTest.class);

    @Autowired
    private ScannerAgent scannerAgent;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void skipUnlessInfrastructureAvailable() {
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
        } catch (Exception e) {
            assumeTrue(false, "Skipping — PostgreSQL not reachable. Run: docker-compose up -d");
        }
    }

    /**
     * Phase 2B checkpoint: scan() returns a populated EnvironmentSnapshot
     * and inserts a row into scan_runs with valid JSON.
     *
     * <p>Running against LocalStack means EC2/IAM/S3/ECS return empty lists —
     * that is expected and correct. The test verifies the scan completes without
     * error and persists the snapshot, not that there are resources to find.
     */
    @Test
    void scanReturnSnapshotAndPersistsToDatabase() {
        int rowsBefore = countScanRuns();

        EnvironmentSnapshot snapshot = scannerAgent.scan();

        // Snapshot must be returned with a runId
        assertThat(snapshot).isNotNull();
        assertThat(snapshot.scanRunId()).isNotNull();
        assertThat(snapshot.scannedAt()).isNotNull();

        // All lists must be non-null (empty is fine against LocalStack, but never null)
        assertThat(snapshot.ec2Instances()).isNotNull();
        assertThat(snapshot.iamUsers()).isNotNull();
        assertThat(snapshot.s3Buckets()).isNotNull();
        assertThat(snapshot.ecsTasks()).isNotNull();

        // One new row must appear in scan_runs
        assertThat(countScanRuns()).isEqualTo(rowsBefore + 1);

        // The DB row must contain the scanRunId and valid JSON
        Map<String, Object> row = jdbcTemplate.queryForMap(
                "SELECT id::text, snapshot_json::text FROM scan_runs WHERE id = ?",
                snapshot.scanRunId());

        assertThat(row.get("id")).asString().isEqualTo(snapshot.scanRunId().toString());
        assertThat(row.get("snapshot_json")).asString()
                .contains("scanRunId")
                .contains("ec2Instances")
                .contains("iamUsers")
                .contains("s3Buckets")
                .contains("ecsTasks");

        log.info("Snapshot runId={} ec2={} iam={} s3={} ecs={}",
                snapshot.scanRunId(),
                snapshot.ec2Instances().size(),
                snapshot.iamUsers().size(),
                snapshot.s3Buckets().size(),
                snapshot.ecsTasks().size());
    }

    private int countScanRuns() {
        Integer n = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM scan_runs", Integer.class);
        return n == null ? 0 : n;
    }
}
