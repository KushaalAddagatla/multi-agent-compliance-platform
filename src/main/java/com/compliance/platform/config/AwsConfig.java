package com.compliance.platform.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ecs.EcsClient;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sqs.SqsClient;

import java.net.URI;

/**
 * Creates AWS SDK v2 client beans.
 * When aws.endpoint-override is set (local profile), all clients point to LocalStack.
 * In production, the default credentials chain (IAM role / env vars) is used.
 */
@Configuration
public class AwsConfig {

    @Value("${aws.region:us-east-1}")
    private String region;

    /** Empty string when not set — indicates production (no override). */
    @Value("${aws.endpoint-override:}")
    private String endpointOverride;

    /** Static credentials for LocalStack; empty in production. */
    @Value("${aws.access-key-id:}")
    private String accessKeyId;

    @Value("${aws.secret-access-key:}")
    private String secretAccessKey;

    private AwsCredentialsProvider credentialsProvider() {
        if (!accessKeyId.isBlank()) {
            return StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(accessKeyId, secretAccessKey));
        }
        return DefaultCredentialsProvider.create();
    }

    private <B extends software.amazon.awssdk.awscore.client.builder.AwsClientBuilder<B, C>,
             C> B applyCommon(B builder) {
        builder.region(Region.of(region)).credentialsProvider(credentialsProvider());
        if (!endpointOverride.isBlank()) {
            builder.endpointOverride(URI.create(endpointOverride));
        }
        return builder;
    }

    @Bean
    public Ec2Client ec2Client() {
        return applyCommon(Ec2Client.builder()).build();
    }

    @Bean
    public IamClient iamClient() {
        // IAM is a global service; SDK requires us-east-1 when using a custom endpoint.
        var builder = IamClient.builder()
                .credentialsProvider(credentialsProvider());
        if (!endpointOverride.isBlank()) {
            builder.region(Region.US_EAST_1)
                   .endpointOverride(URI.create(endpointOverride));
        } else {
            builder.region(Region.AWS_GLOBAL);
        }
        return builder.build();
    }

    @Bean
    public S3Client s3Client() {
        return applyCommon(S3Client.builder()).build();
    }

    @Bean
    public EcsClient ecsClient() {
        return applyCommon(EcsClient.builder()).build();
    }

    @Bean
    public SqsClient sqsClient() {
        return applyCommon(SqsClient.builder()).build();
    }

    @Bean
    public SesV2Client sesV2Client() {
        return applyCommon(SesV2Client.builder()).build();
    }

    @Bean
    public SecretsManagerClient secretsManagerClient() {
        return applyCommon(SecretsManagerClient.builder()).build();
    }
}
