package com.compliance.platform.scanner;

/** Single container definition extracted from an ECS task definition. */
public record EcsContainerInfo(
        String name,
        boolean privileged,    // container has privileged: true
        boolean runAsRoot      // user field is null/blank/"root"/"0" — defaults to root
) {}
