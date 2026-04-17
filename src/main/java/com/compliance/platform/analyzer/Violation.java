package com.compliance.platform.analyzer;

import java.util.UUID;

/**
 * A compliance violation detected by the Analyzer Agent.
 * Persisted to the violations table and returned from the REST API.
 */
public record Violation(
        UUID id,
        UUID scanRunId,
        String resourceId,
        String resourceType,    // EC2_INSTANCE | IAM_USER | S3_BUCKET | ECS_TASK_DEF
        String controlId,       // AC-3, SC-7, 1.2, etc.
        String framework,       // NIST-800-53 | CIS-AWS | SOC2
        String severity,        // HIGH | MEDIUM | LOW
        String reasoning,       // Claude's 1-2 sentence explanation
        String citedExcerpt     // verbatim quote from the retrieved control text
) {}
