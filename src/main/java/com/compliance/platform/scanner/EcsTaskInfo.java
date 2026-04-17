package com.compliance.platform.scanner;

import java.util.List;

/** ECS task definition with container security posture extracted by the Scanner Agent. */
public record EcsTaskInfo(
        String taskDefinitionArn,
        String family,
        int revision,
        List<EcsContainerInfo> containers
) {}
