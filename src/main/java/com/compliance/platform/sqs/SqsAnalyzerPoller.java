package com.compliance.platform.sqs;

import com.compliance.platform.analyzer.AnalyzerAgent;
import com.compliance.platform.analyzer.Violation;
import com.compliance.platform.scanner.EnvironmentSnapshot;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.sqs.model.Message;

import java.util.List;

/**
 * Polls the SQS scan queue and dispatches each message to the Analyzer Agent.
 *
 * <p><b>Why polling instead of push?</b> AWS SQS is pull-based — there is no server-push
 * mechanism without additional infrastructure (SNS, EventBridge). The poller simulates
 * event-driven behavior with a short poll interval at negligible cost.
 *
 * <p><b>Serial processing:</b> One message is consumed per poll cycle intentionally.
 * The Analyzer makes multiple Claude API calls per resource; processing snapshots in
 * parallel would saturate the Anthropic rate limit. Single-message consumption gives
 * natural backpressure.
 *
 * <p><b>Failure handling:</b> If analysis throws, the message is NOT deleted. SQS will
 * make it visible again after the visibility timeout — a built-in retry. After the
 * queue's maxReceiveCount, the message is moved to a dead-letter queue (configurable).
 */
@Component
public class SqsAnalyzerPoller {

    private static final Logger log = LoggerFactory.getLogger(SqsAnalyzerPoller.class);

    private final SqsService sqsService;
    private final AnalyzerAgent analyzerAgent;
    private final ObjectMapper objectMapper;

    public SqsAnalyzerPoller(SqsService sqsService,
                              AnalyzerAgent analyzerAgent,
                              ObjectMapper objectMapper) {
        this.sqsService = sqsService;
        this.analyzerAgent = analyzerAgent;
        this.objectMapper = objectMapper;
    }

    /**
     * Polls once per 5 seconds (measured from completion of the previous poll).
     * fixedDelay — not fixedRate — prevents overlapping executions if analysis is slow.
     */
    @Scheduled(fixedDelay = 5_000)
    public void poll() {
        List<Message> messages;
        try {
            messages = sqsService.receive(1);
        } catch (Exception e) {
            // SQS not available — log at DEBUG to avoid spamming logs in dev without LocalStack
            log.debug("SQS poll skipped — {}", e.getMessage());
            return;
        }

        for (Message message : messages) {
            String messageId = message.messageId();
            log.info("SQS message received — id={}", messageId);
            try {
                EnvironmentSnapshot snapshot = objectMapper.readValue(
                        message.body(), EnvironmentSnapshot.class);

                List<Violation> violations = analyzerAgent.analyze(snapshot);
                log.info("Analysis complete — {} violations, scanRunId={}",
                        violations.size(), snapshot.scanRunId());

                // Delete only after successful analysis — failed messages retry via visibility timeout
                sqsService.delete(message.receiptHandle());
                log.debug("SQS message deleted — id={}", messageId);

            } catch (Exception e) {
                log.error("Failed to process SQS message id={} — message will retry: {}",
                        messageId, e.getMessage());
            }
        }
    }
}
