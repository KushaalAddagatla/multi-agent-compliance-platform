package com.compliance.platform;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class CompliancePlatformApplication {

    public static void main(String[] args) {
        SpringApplication.run(CompliancePlatformApplication.class, args);
    }
}
