package com.scascanner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Dependency Vulnerability Correlation and Remediation Service.
 *
 * See README.md for the API, the architecture, and how to run it. Short version:
 *   mvn spring-boot:run
 *   curl -X POST localhost:8080/api/v1/scans -H "Content-Type: application/json" \
 *        -d '{"project":"demo","dependencies":[{"ecosystem":"maven","group":"org.apache.logging.log4j","name":"log4j-core","version":"2.14.1"}]}'
 */
@SpringBootApplication
public class ScaScannerApplication {
    public static void main(String[] args) {
        SpringApplication.run(ScaScannerApplication.class, args);
    }
}
