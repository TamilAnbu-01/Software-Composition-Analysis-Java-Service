package com.scascanner.remediate;

import com.scascanner.model.*;
import com.scascanner.version.VersionComparator;
import com.scascanner.version.VersionComparators;

import java.util.*;

/**
 * Computes the remediation recommendation for one dependency's (deduplicated) findings: the
 * smallest version that resolves the largest number of them.
 *
 * The key insight (see README for the worked example) is that "findings resolved by upgrading
 * to version V" is monotonically non-decreasing as V increases, because a finding is resolved
 * by any version at or above its own known fix version. That means the maximum number of
 * findings resolvable by any single upgrade is always achieved by the largest known fix version
 * among the findings - the only real question is whether a *smaller* candidate already reaches
 * that same maximum, which is the "minimum safe version" the assignment asks for. So: score
 * every distinct known fix version, take the global best score, and recommend the smallest
 * candidate that reaches it.
 *
 * Findings with no known fixed version can never be resolved by any recommendation - there is
 * nothing to upgrade to - so they always land in "remaining", no matter which candidate wins.
 */
public class RemediationEngine {

    public RemediationPlan plan(NormalizedDependency dependency, List<Finding> findings) {
        VersionComparator cmp = VersionComparators.forEcosystem(dependency.ecosystem());
        int total = findings.size();

        List<String> candidates = distinctSortedFixVersions(findings, cmp);

        String recommended = null;
        int resolvedCount = 0;

        if (!candidates.isEmpty()) {
            Map<String, Integer> resolvedCountByCandidate = new LinkedHashMap<>();
            int globalMax = 0;
            for (String candidate : candidates) {
                int count = countResolvedBy(candidate, findings, cmp);
                resolvedCountByCandidate.put(candidate, count);
                globalMax = Math.max(globalMax, count);
            }
            for (String candidate : candidates) { // ascending order -> first to hit globalMax is minimal
                if (resolvedCountByCandidate.get(candidate) == globalMax) {
                    recommended = candidate;
                    resolvedCount = globalMax;
                    break;
                }
            }
        }

        int remaining = total - resolvedCount;
        Map<Severity, Integer> severityResolved = zeroedSeverityMap();
        Map<Severity, Integer> severityRemaining = zeroedSeverityMap();

        for (Finding f : findings) {
            boolean resolved = recommended != null
                    && f.fixedVersion() != null
                    && cmp.greaterThanOrEqual(recommended, f.fixedVersion());
            Severity sev = f.vulnerability().severity();
            (resolved ? severityResolved : severityRemaining).merge(sev, 1, Integer::sum);
        }

        return new RemediationPlan(dependency, dependency.version(), recommended,
                total, remaining, resolvedCount, remaining, severityResolved, severityRemaining);
    }

    private List<String> distinctSortedFixVersions(List<Finding> findings, VersionComparator cmp) {
        List<String> versions = new ArrayList<>();
        for (Finding f : findings) {
            if (f.fixedVersion() != null && !containsVersion(versions, f.fixedVersion(), cmp)) {
                versions.add(f.fixedVersion());
            }
        }
        versions.sort(cmp::compare);
        return versions;
    }

    private boolean containsVersion(List<String> versions, String v, VersionComparator cmp) {
        for (String existing : versions) {
            if (cmp.compare(existing, v) == 0) return true;
        }
        return false;
    }

    private int countResolvedBy(String candidate, List<Finding> findings, VersionComparator cmp) {
        int count = 0;
        for (Finding f : findings) {
            if (f.fixedVersion() != null && cmp.greaterThanOrEqual(candidate, f.fixedVersion())) {
                count++;
            }
        }
        return count;
    }

    private Map<Severity, Integer> zeroedSeverityMap() {
        Map<Severity, Integer> map = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            map.put(s, 0);
        }
        return map;
    }
}
