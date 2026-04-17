package com.compliance.platform.scanner;

import java.util.List;

/** S3 bucket ACL state extracted by the Scanner Agent. */
public record S3BucketInfo(
        String bucketName,
        boolean publiclyAccessible,   // true if any ACL grant targets AllUsers or AuthenticatedUsers
        List<String> publicGrantUris  // which grant URIs are public, for violation context
) {}
