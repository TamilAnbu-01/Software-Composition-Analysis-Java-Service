package com.scascanner.remediate;

import com.scascanner.model.RemediationPlan;
import com.scascanner.model.Severity;

import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * Optional bonus (assignment section 11, "remediation optimization"): given remediation plans
 * for several dependencies, ranks which upgrade is highest priority to do first.
 *
 * The score weights resolved findings by severity, so "resolves 2 CRITICALs" outranks "resolves
 * 5 LOWs" even though the raw finding count is smaller - matching how a security team would
 * actually triage a backlog of upgrades.
 */
public class RemediationPriorityRanker {

    private static final Map<Severity, Integer> WEIGHTS = Map.of(
            Severity.CRITICAL, 10,
            Severity.HIGH, 5,
            Severity.MEDIUM, 2,
            Severity.LOW, 1,
            Severity.UNKNOWN, 1
    );

    public List<RemediationPlan> rank(List<RemediationPlan> plans) {
        return plans.stream()
                .sorted(Comparator.comparingInt(this::score).reversed())
                .toList();
    }

    private int score(RemediationPlan plan) {
        int score = 0;
        for (Map.Entry<Severity, Integer> entry : plan.severityResolved().entrySet()) {
            score += WEIGHTS.get(entry.getKey()) * entry.getValue();
        }
        return score;
    }
}
