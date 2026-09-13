package com.scascanner.model;

import java.time.Instant;
import java.util.List;

public record ScanResult(
        String scanId,
        String project,
        Instant scannedAt,
        List<Finding> findings,
        List<RemediationPlan> remediations,
        List<ScanError> errors
) {
}
