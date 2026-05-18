package com.compliance.platform.reporter;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable record representing a completed compliance report run.
 *
 * <p>Stored in the {@code compliance_reports} table. The {@code s3Key} field will be null
 * when S3 upload was skipped (e.g. LocalStack not running in local dev) — callers should
 * treat a null s3Key as "no remote copy available" rather than an error.
 */
public record ComplianceReport(
        UUID id,
        double nistScore,
        double cisScore,
        double soc2Score,
        int totalViolations,
        String s3Key,          // null if S3 upload was skipped
        Instant createdAt
) {
    /** Constructor used by ReporterAgent before DB insert (createdAt filled in post-insert). */
    public ComplianceReport(UUID id, double nistScore, double cisScore, double soc2Score,
                            int totalViolations, String s3Key) {
        this(id, nistScore, cisScore, soc2Score, totalViolations, s3Key, Instant.now());
    }
}
