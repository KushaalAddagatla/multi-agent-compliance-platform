package com.compliance.platform.orchestrator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.*;

import java.time.Instant;
import java.util.List;

/**
 * Publishes pipeline metrics to CloudWatch and maintains a violations alarm.
 *
 * <p>Metrics published per run:
 * <ul>
 *   <li>{@code ViolationsFound} — total violations detected in this run</li>
 *   <li>{@code NewViolations} — violations not seen in any prior run (delta)</li>
 * </ul>
 *
 * <p>Alarm: if {@code ViolationsFound > 50} for one consecutive period, the alarm
 * transitions to ALARM state and fires an SNS notification. Only created when
 * {@code aws.sns.alert-topic-arn} is configured — skipped otherwise.
 *
 * <p>All operations are graceful: a CloudWatch or SNS failure never aborts the
 * pipeline run. Metrics are nice-to-have observability, not critical path.
 */
@Service
public class CloudWatchService {

    private static final Logger log = LoggerFactory.getLogger(CloudWatchService.class);
    private static final String ALARM_NAME = "CompliancePlatform-HighViolationCount";

    private final CloudWatchClient cloudWatchClient;

    @Value("${aws.cloudwatch.namespace:CompliancePlatform}")
    private String namespace;

    @Value("${aws.sns.alert-topic-arn:}")
    private String alertTopicArn;

    public CloudWatchService(CloudWatchClient cloudWatchClient) {
        this.cloudWatchClient = cloudWatchClient;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Publishes {@code ViolationsFound} and {@code NewViolations} metrics for the
     * completed pipeline run. Both metrics use unit COUNT and are timestamped now.
     */
    public void publishPipelineMetrics(int violationsFound, int newViolations) {
        try {
            Instant now = Instant.now();
            cloudWatchClient.putMetricData(PutMetricDataRequest.builder()
                    .namespace(namespace)
                    .metricData(List.of(
                            metric("ViolationsFound", violationsFound, now),
                            metric("NewViolations", newViolations, now)))
                    .build());
            log.info("CloudWatch metrics published — ViolationsFound={} NewViolations={}",
                    violationsFound, newViolations);
        } catch (Exception e) {
            log.warn("CloudWatch metric publish failed (LocalStack running? Correct region?) — {}",
                    e.getMessage());
        }
    }

    /**
     * Creates or updates the high-violation-count CloudWatch alarm.
     * Idempotent — safe to call on every run; CloudWatch upserts existing alarms.
     * No-op when {@code aws.sns.alert-topic-arn} is not configured.
     *
     * <p>Alarm configuration: threshold = 50, period = 300s (5 min),
     * evaluation periods = 1, statistic = Sum, comparison = GREATER_THAN_THRESHOLD.
     */
    public void ensureViolationAlarm() {
        if (alertTopicArn.isBlank()) {
            log.debug("SNS_ALERT_TOPIC_ARN not configured — skipping alarm setup");
            return;
        }
        try {
            cloudWatchClient.putMetricAlarm(PutMetricAlarmRequest.builder()
                    .alarmName(ALARM_NAME)
                    .alarmDescription("Fires when a compliance run finds more than 50 violations")
                    .namespace(namespace)
                    .metricName("ViolationsFound")
                    .statistic(Statistic.SUM)
                    .period(300)
                    .evaluationPeriods(1)
                    .threshold(50.0)
                    .comparisonOperator(ComparisonOperator.GREATER_THAN_THRESHOLD)
                    .treatMissingData("notBreaching")
                    .alarmActions(alertTopicArn)
                    .build());
            log.info("CloudWatch alarm '{}' configured — fires if ViolationsFound > 50", ALARM_NAME);
        } catch (Exception e) {
            log.warn("CloudWatch alarm setup failed — {}", e.getMessage());
        }
    }

    // ── Builder helper ────────────────────────────────────────────────────────

    private MetricDatum metric(String name, double value, Instant timestamp) {
        return MetricDatum.builder()
                .metricName(name)
                .value(value)
                .unit(StandardUnit.COUNT)
                .timestamp(timestamp)
                .build();
    }
}
