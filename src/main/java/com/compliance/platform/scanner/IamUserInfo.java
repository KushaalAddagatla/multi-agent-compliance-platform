package com.compliance.platform.scanner;

import java.util.List;

/** IAM user and their access key summary extracted by the Scanner Agent. */
public record IamUserInfo(
        String username,
        String arn,
        List<AccessKeyInfo> accessKeys
) {}
