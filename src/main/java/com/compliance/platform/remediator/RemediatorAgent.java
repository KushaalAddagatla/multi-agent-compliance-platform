package com.compliance.platform.remediator;

import com.compliance.platform.analyzer.Violation;
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
 * Generates step-by-step remediation plans for compliance violations.
 *
 * <p>For each violation, the Remediator:
 * <ol>
 *   <li>Assembles a prompt containing the full violation context (resource, framework, reasoning).</li>
 *   <li>Calls Claude to produce a JSON remediation plan with steps, CLI commands, and a
 *       Terraform patch where applicable.</li>
 *   <li>Sets {@code autoRemediable} based on whether the fix is a deterministic, safe API call.</li>
 *   <li>Retries once with a stricter format instruction if the response is not valid JSON.</li>
 *   <li>Persists the plan to {@code remediation_plans} with {@code approval_status = PENDING}.</li>
 * </ol>
 *
 * <p><b>Human-in-the-loop is intentional.</b> The agent generates but never executes.
 * {@code autoRemediable} is a signal to the UI — it unlocks an Approve button,
 * but execution only happens if a human clicks it (and even then, only in a future phase).
 * This is a deliberate architectural safety gate, not a limitation.
 */
@Service
public class RemediatorAgent {

    private static final Logger log = LoggerFactory.getLogger(RemediatorAgent.class);

    private static final String SYSTEM_PROMPT = """
            You are a cloud security remediation engineer specialising in AWS compliance.
            You will be given a compliance violation detected in an AWS environment.

            Produce a remediation plan as a JSON object with exactly these fields:
            - "steps": numbered, human-readable remediation steps as plain text (newline-separated)
            - "cliCommands": AWS CLI commands that implement the fix, one per line \
              (null if not applicable)
            - "terraformPatch": a corrected Terraform resource block showing the desired \
              configuration (null if not applicable or if the resource is not Terraform-manageable)
            - "autoRemediable": true or false

            autoRemediable is TRUE only when ALL of the following hold:
            - The fix is a single deterministic AWS CLI command or API call
            - No human architectural judgment is needed
            - No risk of data loss or service disruption
            Examples that qualify: rotate an IAM access key, disable a public S3 bucket ACL, \
            enable default encryption on an S3 bucket, enable MFA delete.

            autoRemediable is FALSE for: network topology changes, IAM policy redesign, \
            security group restructuring, application-level code changes.

            Respond ONLY with valid JSON. No markdown fences, no explanatory text outside the object.
            """;

    private static final String RETRY_SUFFIX =
            "\n\nCRITICAL: Respond with a valid JSON object only. " +
            "No markdown, no code fences, no text before or after the object.";

    private final ChatClient chatClient;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public RemediatorAgent(ChatClient.Builder chatClientBuilder,
                           JdbcTemplate jdbcTemplate,
                           ObjectMapper objectMapper) {
        this.chatClient = chatClientBuilder.build();
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Generates and persists remediation plans for all supplied violations.
     * Skips any violation that already has a plan in the DB to avoid duplicates
     * when the Orchestrator re-runs.
     */
    public List<RemediationPlan> remediate(List<Violation> violations) {
        log.info("Remediator starting — {} violations to process", violations.size());
        List<RemediationPlan> plans = new ArrayList<>();

        for (Violation v : violations) {
            if (planExists(v.id())) {
                log.debug("Plan already exists for violation {} — skipping", v.id());
                continue;
            }
            try {
                RemediationPlan plan = remediateOne(v);
                persistPlan(plan);
                plans.add(plan);
            } catch (Exception e) {
                log.error("Remediation failed for violation {} — {}", v.id(), e.getMessage());
            }
        }

        log.info("Remediator complete — {} plans generated", plans.size());
        return plans;
    }

    // ── Per-violation remediation ─────────────────────────────────────────────

    private RemediationPlan remediateOne(Violation v) throws Exception {
        String userPrompt = buildPrompt(v);

        String response = chatClient.prompt()
                .system(SYSTEM_PROMPT)
                .user(userPrompt)
                .call()
                .content();

        PlanDto dto;
        try {
            dto = parseResponse(response);
        } catch (Exception e) {
            log.warn("Malformed JSON from Claude for violation {} — retrying", v.id());
            String retry = chatClient.prompt()
                    .system(SYSTEM_PROMPT + RETRY_SUFFIX)
                    .user(userPrompt)
                    .call()
                    .content();
            dto = parseResponse(retry);
        }

        return new RemediationPlan(
                UUID.randomUUID(),
                v.id(),
                dto.steps(),
                dto.cliCommands(),
                dto.terraformPatch(),
                dto.autoRemediable(),
                "PENDING");
    }

    private String buildPrompt(Violation v) {
        return """
                VIOLATION DETAILS:
                Resource ID:   %s
                Resource Type: %s
                Framework:     %s
                Control ID:    %s
                Severity:      %s
                Reasoning:     %s
                Cited excerpt: %s

                Generate a concrete remediation plan for this specific violation.
                """.formatted(
                v.resourceId(), v.resourceType(),
                v.framework(), v.controlId(),
                v.severity(), v.reasoning(),
                v.citedExcerpt() != null ? v.citedExcerpt() : "N/A");
    }

    private PlanDto parseResponse(String response) throws Exception {
        String cleaned = response.replaceAll("(?s)```json\\s*|```\\s*", "").trim();
        int start = cleaned.indexOf('{');
        int end   = cleaned.lastIndexOf('}');
        if (start == -1 || end == -1 || end < start) {
            throw new IllegalArgumentException("No JSON object found in response: " + cleaned);
        }
        return objectMapper.readValue(cleaned.substring(start, end + 1), PlanDto.class);
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    private void persistPlan(RemediationPlan plan) {
        jdbcTemplate.update("""
                INSERT INTO remediation_plans
                    (id, violation_id, steps, cli_commands, terraform_patch,
                     auto_remediable, approval_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                plan.id(), plan.violationId(),
                plan.steps(), plan.cliCommands(), plan.terraformPatch(),
                plan.autoRemediable(), plan.approvalStatus());
        log.debug("Persisted plan {} for violation {} (autoRemediable={})",
                plan.id(), plan.violationId(), plan.autoRemediable());
    }

    private boolean planExists(UUID violationId) {
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM remediation_plans WHERE violation_id = ?",
                Integer.class, violationId);
        return count != null && count > 0;
    }

    // ── Inner DTO ─────────────────────────────────────────────────────────────

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record PlanDto(
            String steps,
            String cliCommands,
            String terraformPatch,
            boolean autoRemediable
    ) {}
}
