package com.compliance.platform.analyzer;

import com.compliance.platform.model.RetrievedChunk;
import com.compliance.platform.retrieval.RetrievalService;
import com.compliance.platform.scanner.*;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Analyzes an {@link EnvironmentSnapshot} to detect compliance violations.
 *
 * <p>For each resource, the Analyzer:
 * <ol>
 *   <li>Builds a context-aware query and retrieves the top-3 matching control chunks from pgvector.</li>
 *   <li>Assembles a structured prompt containing the resource state and retrieved framework text.</li>
 *   <li>Calls Claude to reason over the evidence and return violations as a JSON array.</li>
 *   <li>Retries once with a stricter format instruction if the response is not valid JSON.</li>
 *   <li>Persists all violations to the violations table.</li>
 * </ol>
 *
 * <p>The Analyzer never hardcodes compliance rules — every finding is grounded in actual
 * framework text retrieved at query time. This is the key interview talking point.
 */
@Service
public class AnalyzerAgent {

    private static final Logger log = LoggerFactory.getLogger(AnalyzerAgent.class);

    private static final String SYSTEM_PROMPT = """
            You are a cloud security compliance analyst. You will be given the state of an AWS \
            resource and relevant sections from security frameworks (NIST 800-53, CIS AWS Benchmark, SOC2).

            Identify compliance violations based ONLY on the provided framework text. \
            Do not reference controls that are not in the provided sections.

            Respond ONLY with a valid JSON array. Each element must have exactly these fields:
            - "resourceId": the AWS resource identifier from the resource state
            - "controlId": the control ID from the framework text (e.g. AC-3, SC-7, 1.2)
            - "framework": one of NIST-800-53, CIS-AWS, SOC2
            - "severity": one of HIGH, MEDIUM, LOW
            - "reasoning": 1-2 sentences explaining the specific violation
            - "citedExcerpt": a verbatim quote of 10-30 words from the control text that applies

            If there are no violations, return [].
            Do not include any text, explanation, or markdown fences outside the JSON array.
            """;

    private static final String RETRY_SUFFIX =
            "\n\nCRITICAL: Your entire response must be a valid JSON array only. " +
            "No markdown, no code fences, no text before or after the array.";

    private final RetrievalService retrievalService;
    private final ChatClient chatClient;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public AnalyzerAgent(RetrievalService retrievalService,
                         ChatClient.Builder chatClientBuilder,
                         JdbcTemplate jdbcTemplate,
                         ObjectMapper objectMapper) {
        this.retrievalService = retrievalService;
        this.chatClient = chatClientBuilder.build();
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Analyzes every resource in the snapshot and returns all detected violations.
     * Violations are also persisted to the violations table before returning.
     */
    public List<Violation> analyze(EnvironmentSnapshot snapshot) {
        UUID scanRunId = snapshot.scanRunId();
        log.info("Analyzer starting — scanRunId={} ec2={} iam={} s3={} ecs={}",
                scanRunId,
                snapshot.ec2Instances().size(),
                snapshot.iamUsers().size(),
                snapshot.s3Buckets().size(),
                snapshot.ecsTasks().size());

        List<Violation> all = new ArrayList<>();

        for (Ec2InstanceInfo r : snapshot.ec2Instances()) {
            all.addAll(analyzeResource(scanRunId, "EC2_INSTANCE", r.instanceId(), r,
                    ragQuery(r)));
        }
        for (IamUserInfo r : snapshot.iamUsers()) {
            all.addAll(analyzeResource(scanRunId, "IAM_USER", r.username(), r,
                    ragQuery(r)));
        }
        for (S3BucketInfo r : snapshot.s3Buckets()) {
            all.addAll(analyzeResource(scanRunId, "S3_BUCKET", r.bucketName(), r,
                    ragQuery(r)));
        }
        for (EcsTaskInfo r : snapshot.ecsTasks()) {
            all.addAll(analyzeResource(scanRunId, "ECS_TASK_DEF", r.taskDefinitionArn(), r,
                    ragQuery(r)));
        }

        if (!all.isEmpty()) {
            persistViolations(all);
        }

        log.info("Analyzer complete — {} violations found for scanRunId={}", all.size(), scanRunId);
        return all;
    }

    // ── Per-resource analysis ─────────────────────────────────────────────────

    private List<Violation> analyzeResource(UUID scanRunId, String resourceType,
                                             String resourceId, Object resource,
                                             String ragQuery) {
        List<RetrievedChunk> chunks = retrievalService.search(ragQuery, 3);
        if (chunks.isEmpty()) {
            log.warn("No RAG chunks for {} {} — skipping (embeddings table empty?)",
                    resourceType, resourceId);
            return List.of();
        }

        try {
            String resourceJson = objectMapper.writeValueAsString(resource);
            List<ViolationDto> dtos = callClaude(resourceType, resourceId, resourceJson, chunks);

            return dtos.stream()
                    .map(dto -> new Violation(
                            UUID.randomUUID(), scanRunId,
                            dto.resourceId(), resourceType,
                            dto.controlId(), dto.framework(),
                            dto.severity(), dto.reasoning(), dto.citedExcerpt()))
                    .toList();

        } catch (Exception e) {
            log.error("Analysis failed for {} {} — {}", resourceType, resourceId, e.getMessage());
            return List.of();
        }
    }

    // ── Claude interaction ────────────────────────────────────────────────────

    private List<ViolationDto> callClaude(String resourceType, String resourceId,
                                           String resourceJson, List<RetrievedChunk> chunks) throws Exception {
        String userPrompt = buildUserPrompt(resourceType, resourceJson, chunks);

        String response = chatClient.prompt()
                .system(SYSTEM_PROMPT)
                .user(userPrompt)
                .call()
                .content();

        try {
            return parseViolations(response);
        } catch (Exception e) {
            log.warn("Malformed JSON from Claude for {} {} — retrying", resourceType, resourceId);
            String retryResponse = chatClient.prompt()
                    .system(SYSTEM_PROMPT + RETRY_SUFFIX)
                    .user(userPrompt)
                    .call()
                    .content();
            return parseViolations(retryResponse);
        }
    }

    private List<ViolationDto> parseViolations(String response) throws Exception {
        // Strip markdown code fences if Claude wrapped the output
        String cleaned = response.replaceAll("(?s)```json\\s*|```\\s*", "").trim();

        // Find the JSON array bounds — ignore any stray preamble text
        int start = cleaned.indexOf('[');
        int end = cleaned.lastIndexOf(']');
        if (start == -1 || end == -1 || end < start) {
            throw new IllegalArgumentException("Response contains no JSON array: " + cleaned);
        }
        cleaned = cleaned.substring(start, end + 1);

        ViolationDto[] dtos = objectMapper.readValue(cleaned, ViolationDto[].class);
        return List.of(dtos);
    }

    private String buildUserPrompt(String resourceType, String resourceJson,
                                    List<RetrievedChunk> chunks) {
        StringBuilder sb = new StringBuilder();
        sb.append("RESOURCE TYPE: ").append(resourceType).append("\n");
        sb.append("RESOURCE STATE:\n").append(resourceJson).append("\n\n");
        sb.append("RELEVANT COMPLIANCE CONTROLS:\n\n");

        for (int i = 0; i < chunks.size(); i++) {
            RetrievedChunk c = chunks.get(i);
            sb.append("[").append(i + 1).append("] ")
              .append(c.framework()).append(" | ")
              .append(c.controlId()).append(" | ")
              .append(c.severity() != null ? c.severity() : "MEDIUM").append("\n");
            // Cap content to avoid overfilling the context window
            String content = c.content().length() > 1500
                    ? c.content().substring(0, 1500) + "..."
                    : c.content();
            sb.append(content).append("\n\n");
        }

        return sb.toString();
    }

    // ── Context-aware RAG queries ─────────────────────────────────────────────

    private String ragQuery(Ec2InstanceInfo r) {
        return "EC2 instance security group network access control" +
               (r.publicIp() != null ? " public IP exposure boundary protection" : "");
    }

    private String ragQuery(IamUserInfo r) {
        boolean hasOldKey = r.accessKeys().stream().anyMatch(AccessKeyInfo::old);
        return "IAM user access key credential management" +
               (hasOldKey ? " rotation 90 days stale inactive" : "");
    }

    private String ragQuery(S3BucketInfo r) {
        return "S3 bucket access control" +
               (r.publiclyAccessible() ? " public exposure AllUsers data confidentiality" : " private ACL");
    }

    private String ragQuery(EcsTaskInfo r) {
        boolean privileged = r.containers().stream().anyMatch(EcsContainerInfo::privileged);
        boolean root = r.containers().stream().anyMatch(EcsContainerInfo::runAsRoot);
        return "ECS container task definition security" +
               (privileged ? " privileged mode escalation" : "") +
               (root ? " root user least privilege" : "");
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    private void persistViolations(List<Violation> violations) {
        jdbcTemplate.batchUpdate(
                """
                INSERT INTO violations
                    (id, scan_run_id, resource_id, resource_type,
                     control_id, framework, severity, reasoning, cited_excerpt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                violations,
                violations.size(),
                (ps, v) -> {
                    ps.setObject(1, v.id());
                    ps.setObject(2, v.scanRunId());
                    ps.setString(3, v.resourceId());
                    ps.setString(4, v.resourceType());
                    ps.setString(5, v.controlId());
                    ps.setString(6, v.framework());
                    ps.setString(7, v.severity());
                    ps.setString(8, v.reasoning());
                    ps.setString(9, v.citedExcerpt());
                });
        log.debug("Persisted {} violations", violations.size());
    }

    // ── Inner DTO for parsing Claude's JSON response ──────────────────────────

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record ViolationDto(
            String resourceId,
            String controlId,
            String framework,
            String severity,
            String reasoning,
            String citedExcerpt
    ) {}
}
