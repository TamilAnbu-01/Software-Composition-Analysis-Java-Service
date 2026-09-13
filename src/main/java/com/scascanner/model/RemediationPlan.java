package com.scascanner.model;

import java.util.Map;

/**
 * The remediation recommendation for one dependency: the smallest version that resolves the
 * largest number of its findings, plus the before/after picture.
 *
 * recommendedVersion is null when none of the findings for this dependency name a fixed
 * version at all - there is nothing for the service to safely recommend.
 */
public record RemediationPlan(
        NormalizedDependency dependency,
        String currentVersion,
        String recommendedVersion,
        int findingsBefore,
        int findingsAfter,
        int resolved,
        int remaining,
        Map<Severity, Integer> severityResolved,
        Map<Severity, Integer> severityRemaining
) {
}
