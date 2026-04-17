package com.compliance.platform.scanner;

/** IAM access key metadata extracted per user. */
public record AccessKeyInfo(
        String keyId,
        String status,    // Active | Inactive
        long ageDays,
        boolean old       // true when ageDays > 90
) {}
