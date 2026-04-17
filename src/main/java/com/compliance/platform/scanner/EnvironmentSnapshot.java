package com.compliance.platform.scanner;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Immutable snapshot of the AWS environment captured by the Scanner Agent.
 * Serialized to JSON and stored in scan_runs.snapshot_json.
 * Passed to the Analyzer Agent for RAG-grounded violation detection.
 */
public record EnvironmentSnapshot(
        UUID scanRunId,
        List<Ec2InstanceInfo> ec2Instances,
        List<IamUserInfo> iamUsers,
        List<S3BucketInfo> s3Buckets,
        List<EcsTaskInfo> ecsTasks,
        Instant scannedAt
) {}
