package com.compliance.platform.scanner;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ecs.EcsClient;
import software.amazon.awssdk.services.ecs.model.ListTaskDefinitionsRequest;
import software.amazon.awssdk.services.ecs.model.TaskDefinitionStatus;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.s3.S3Client;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Scans the AWS environment across EC2, IAM, S3, and ECS, then persists
 * the result as a structured {@link EnvironmentSnapshot} in the scan_runs table.
 *
 * <p>Each scan method is independent — a failure in one service does not abort
 * the others. Callers receive a partial snapshot rather than no data.
 *
 * <p>The snapshot is the sole input to the Analyzer Agent. It deliberately
 * contains only the fields needed for compliance reasoning — nothing more.
 */
@Service
public class ScannerAgent {

    private static final Logger log = LoggerFactory.getLogger(ScannerAgent.class);

    private final Ec2Client ec2Client;
    private final IamClient iamClient;
    private final S3Client s3Client;
    private final EcsClient ecsClient;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public ScannerAgent(Ec2Client ec2Client,
                        IamClient iamClient,
                        S3Client s3Client,
                        EcsClient ecsClient,
                        JdbcTemplate jdbcTemplate,
                        ObjectMapper objectMapper) {
        this.ec2Client = ec2Client;
        this.iamClient = iamClient;
        this.s3Client = s3Client;
        this.ecsClient = ecsClient;
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Runs a full environment scan, stores the snapshot to PostgreSQL, and returns it.
     * The returned snapshot's {@code scanRunId} matches the row inserted in scan_runs.
     */
    public EnvironmentSnapshot scan() {
        UUID runId = UUID.randomUUID();
        log.info("Scanner starting — runId={}", runId);

        List<Ec2InstanceInfo> ec2 = scanEc2();
        List<IamUserInfo> iam = scanIam();
        List<S3BucketInfo> s3 = scanS3();
        List<EcsTaskInfo> ecs = scanEcs();

        EnvironmentSnapshot snapshot = new EnvironmentSnapshot(runId, ec2, iam, s3, ecs, Instant.now());
        persistSnapshot(runId, snapshot);

        log.info("Scanner complete — ec2={} iam={} s3={} ecs={} runId={}",
                ec2.size(), iam.size(), s3.size(), ecs.size(), runId);
        return snapshot;
    }

    // ── EC2 ───────────────────────────────────────────────────────────────────

    private List<Ec2InstanceInfo> scanEc2() {
        try {
            return ec2Client.describeInstances()
                    .reservations().stream()
                    .flatMap(r -> r.instances().stream())
                    .map(i -> new Ec2InstanceInfo(
                            i.instanceId(),
                            i.state().nameAsString(),
                            i.publicIpAddress(),
                            i.securityGroups().stream().map(sg -> sg.groupId()).toList(),
                            i.securityGroups().stream().map(sg -> sg.groupName()).toList()))
                    .toList();
        } catch (Exception e) {
            log.error("EC2 scan failed — {}", e.getMessage());
            return List.of();
        }
    }

    // ── IAM ───────────────────────────────────────────────────────────────────

    private List<IamUserInfo> scanIam() {
        try {
            return iamClient.listUsers().users().stream()
                    .map(user -> {
                        List<AccessKeyInfo> keys = iamClient
                                .listAccessKeys(r -> r.userName(user.userName()))
                                .accessKeyMetadata().stream()
                                .map(key -> {
                                    long days = ChronoUnit.DAYS.between(key.createDate(), Instant.now());
                                    return new AccessKeyInfo(
                                            key.accessKeyId(),
                                            key.statusAsString(),
                                            days,
                                            days > 90);
                                })
                                .toList();
                        return new IamUserInfo(user.userName(), user.arn(), keys);
                    })
                    .toList();
        } catch (Exception e) {
            log.error("IAM scan failed — {}", e.getMessage());
            return List.of();
        }
    }

    // ── S3 ────────────────────────────────────────────────────────────────────

    private List<S3BucketInfo> scanS3() {
        try {
            return s3Client.listBuckets().buckets().stream()
                    .map(bucket -> {
                        try {
                            List<String> publicUris = s3Client
                                    .getBucketAcl(r -> r.bucket(bucket.name()))
                                    .grants().stream()
                                    .filter(g -> g.grantee() != null && g.grantee().uri() != null)
                                    .filter(g -> g.grantee().uri().contains("AllUsers")
                                              || g.grantee().uri().contains("AuthenticatedUsers"))
                                    .map(g -> g.grantee().uri())
                                    .distinct()
                                    .toList();
                            return new S3BucketInfo(bucket.name(), !publicUris.isEmpty(), publicUris);
                        } catch (Exception e) {
                            log.warn("Could not read ACL for bucket {} — {}", bucket.name(), e.getMessage());
                            return new S3BucketInfo(bucket.name(), false, List.of());
                        }
                    })
                    .toList();
        } catch (Exception e) {
            log.error("S3 scan failed — {}", e.getMessage());
            return List.of();
        }
    }

    // ── ECS ───────────────────────────────────────────────────────────────────

    private List<EcsTaskInfo> scanEcs() {
        try {
            List<String> clusterArns = ecsClient.listClusters().clusterArns();
            log.debug("ECS clusters found: {}", clusterArns.size());

            List<EcsTaskInfo> results = new ArrayList<>();
            String nextToken = null;
            int fetched = 0;

            // Cap at 50 task definitions — enough for compliance scanning without runaway calls
            do {
                var req = ListTaskDefinitionsRequest.builder()
                        .status(TaskDefinitionStatus.ACTIVE)
                        .nextToken(nextToken)
                        .maxResults(50)
                        .build();
                var resp = ecsClient.listTaskDefinitions(req);

                for (String arn : resp.taskDefinitionArns()) {
                    if (fetched >= 50) break;
                    try {
                        var taskDef = ecsClient
                                .describeTaskDefinition(r -> r.taskDefinition(arn))
                                .taskDefinition();

                        List<EcsContainerInfo> containers = taskDef.containerDefinitions().stream()
                                .map(c -> {
                                    boolean rootUser = c.user() == null
                                            || c.user().isBlank()
                                            || c.user().equals("root")
                                            || c.user().equals("0");
                                    return new EcsContainerInfo(
                                            c.name(),
                                            Boolean.TRUE.equals(c.privileged()),
                                            rootUser);
                                })
                                .toList();

                        results.add(new EcsTaskInfo(arn, taskDef.family(), taskDef.revision(), containers));
                        fetched++;
                    } catch (Exception e) {
                        log.warn("Could not describe task definition {} — {}", arn, e.getMessage());
                    }
                }

                nextToken = resp.nextToken();
            } while (nextToken != null && fetched < 50);

            return results;
        } catch (Exception e) {
            log.error("ECS scan failed — {}", e.getMessage());
            return List.of();
        }
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    private void persistSnapshot(UUID runId, EnvironmentSnapshot snapshot) {
        try {
            String json = objectMapper.writeValueAsString(snapshot);
            jdbcTemplate.update(
                    "INSERT INTO scan_runs (id, snapshot_json) VALUES (?, CAST(? AS jsonb))",
                    runId, json);
            log.debug("Snapshot persisted — runId={}", runId);
        } catch (Exception e) {
            log.error("Failed to persist snapshot runId={} — {}", runId, e.getMessage());
        }
    }
}
