package com.compliance.platform.scanner;

import java.util.List;

/** EC2 instance state extracted by the Scanner Agent. */
public record Ec2InstanceInfo(
        String instanceId,
        String state,                  // pending | running | stopped | terminated | ...
        String publicIp,               // null if instance has no public IP
        List<String> securityGroupIds,
        List<String> securityGroupNames
) {}
