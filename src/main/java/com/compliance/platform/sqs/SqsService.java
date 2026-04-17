package com.compliance.platform.sqs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.Message;

import java.util.List;

/**
 * Low-level SQS operations: queue resolution, message publishing, and message consumption.
 *
 * <p><b>Queue URL strategy:</b> if {@code aws.sqs.scan-queue-url} is configured (production),
 * it is used directly. Otherwise the queue is created on first use via {@code createQueue} —
 * which is idempotent and returns the existing URL if the queue already exists. This means
 * no manual setup step is required for local dev or a fresh deployment.
 *
 * <p><b>Why SQS here at all?</b> Without the queue, the Scanner calls the Analyzer directly
 * in the same thread. If the Analyzer takes 30s (many Claude calls), the Scanner is blocked
 * and cannot handle a second trigger. SQS decouples them: the Scanner finishes and returns
 * in milliseconds; the Analyzer consumes the message at its own pace.
 */
@Service
public class SqsService {

    private static final Logger log = LoggerFactory.getLogger(SqsService.class);
    private static final String QUEUE_NAME = "compliance-scan-queue";

    private final SqsClient sqsClient;
    private final String configuredQueueUrl;

    /** Lazily resolved — set on first call to {@link #queueUrl()}. */
    private volatile String resolvedQueueUrl;

    public SqsService(SqsClient sqsClient,
                      @Value("${aws.sqs.scan-queue-url:}") String configuredQueueUrl) {
        this.sqsClient = sqsClient;
        this.configuredQueueUrl = configuredQueueUrl;
    }

    /**
     * Returns the queue URL, creating the queue if necessary.
     * Thread-safe via double-checked locking.
     */
    public String queueUrl() {
        if (resolvedQueueUrl != null) return resolvedQueueUrl;
        synchronized (this) {
            if (resolvedQueueUrl != null) return resolvedQueueUrl;
            if (!configuredQueueUrl.isBlank()) {
                resolvedQueueUrl = configuredQueueUrl;
            } else {
                // createQueue is idempotent — returns existing URL if queue already exists
                resolvedQueueUrl = sqsClient
                        .createQueue(b -> b.queueName(QUEUE_NAME))
                        .queueUrl();
                log.info("SQS queue ready: {}", resolvedQueueUrl);
            }
        }
        return resolvedQueueUrl;
    }

    /**
     * Publishes a message body to the scan queue.
     */
    public void publish(String messageBody) {
        sqsClient.sendMessage(b -> b.queueUrl(queueUrl()).messageBody(messageBody));
    }

    /**
     * Receives up to {@code maxMessages} messages.
     * Uses a 1-second long-poll to avoid tight-looping against the queue.
     */
    public List<Message> receive(int maxMessages) {
        return sqsClient.receiveMessage(b -> b
                .queueUrl(queueUrl())
                .maxNumberOfMessages(maxMessages)
                .waitTimeSeconds(1))
                .messages();
    }

    /**
     * Deletes a message after successful processing.
     * Not deleting leaves the message invisible for the visibility timeout,
     * after which it becomes available again — a natural retry mechanism.
     */
    public void delete(String receiptHandle) {
        sqsClient.deleteMessage(b -> b.queueUrl(queueUrl()).receiptHandle(receiptHandle));
    }
}
