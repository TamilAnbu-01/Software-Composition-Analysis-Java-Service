package com.scascanner.remediate;

import com.scascanner.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class RemediationEngineTest {

    private final RemediationEngine engine = new RemediationEngine();

    private NormalizedDependency dep(String version) {
        return NormalizedDependency.of(Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", version);
    }

    private Finding finding(NormalizedDependency d, String id, Severity sev, String fixedVersion) {
        VulnerabilityRecord v = new VulnerabilityRecord(id, Set.of(), "desc", sev, Ecosystem.MAVEN,
                d.packageKey(), List.of(), "TEST");
        return new Finding(d, v, fixedVersion);
    }

    @Test
    void log4jExampleFromBrief_recommendsTheVersionThatClearsAllFour() {
        // CRITICAL fixed in 2.15.0, HIGH fixed in 2.16.0, MEDIUM+LOW fixed in 2.17.0.
        // The only candidate that resolves all 4 is 2.17.0, and it's also the minimal one
        // that reaches that maximum, so it must be the recommendation.
        NormalizedDependency d = dep("2.14.1");
        List<Finding> findings = List.of(
                finding(d, "CVE-CRIT", Severity.CRITICAL, "2.15.0"),
                finding(d, "CVE-HIGH", Severity.HIGH, "2.16.0"),
                finding(d, "CVE-MED", Severity.MEDIUM, "2.17.0"),
                finding(d, "CVE-LOW", Severity.LOW, "2.17.0")
        );

        RemediationPlan plan = engine.plan(d, findings);

        assertEquals("2.17.0", plan.recommendedVersion());
        assertEquals(4, plan.findingsBefore());
        assertEquals(0, plan.findingsAfter());
        assertEquals(4, plan.resolved());
        assertEquals(0, plan.remaining());
    }

    @Test
    void recommendsTheSmallestVersionThatReachesTheMaximum_notJustTheLargestFix() {
        // 1.1 resolves 1 finding, 1.2 resolves 2, 2.0 resolves all 3 but so would anything
        // >= 2.0 - 2.0 is both the max AND the minimal version reaching it.
        NormalizedDependency d = dep("1.0");
        List<Finding> findings = List.of(
                finding(d, "CVE-A", Severity.LOW, "1.1"),
                finding(d, "CVE-B", Severity.MEDIUM, "1.2"),
                finding(d, "CVE-C", Severity.HIGH, "2.0")
        );

        RemediationPlan plan = engine.plan(d, findings);
        assertEquals("2.0", plan.recommendedVersion());
        assertEquals(3, plan.resolved());
    }

    @Test
    void smallerVersionPreferredWhenItAlreadyReachesTheSameMaximumAsALargerOne() {
        // Two CVEs both fixed by 1.5; a third, unrelated-looking "1.6" candidate appears only
        // because of a duplicate fix pointer and resolves nothing extra. 1.5 must win, not 1.6.
        NormalizedDependency d = dep("1.0");
        List<Finding> findings = List.of(
                finding(d, "CVE-A", Severity.HIGH, "1.5"),
                finding(d, "CVE-B", Severity.HIGH, "1.5"),
                finding(d, "CVE-C-ALREADY-FIXED", Severity.LOW, "1.0") // already resolved at current version
        );

        RemediationPlan plan = engine.plan(d, findings);
        assertEquals("1.5", plan.recommendedVersion());
        assertEquals(3, plan.resolved()); // 1.5 >= 1.0 too, so the already-fixed one counts as resolved
    }

    @Test
    void findingsWithNoKnownFixVersion_neverCountAsResolved() {
        NormalizedDependency d = dep("1.0");
        List<Finding> findings = List.of(
                finding(d, "CVE-FIXABLE", Severity.HIGH, "2.0"),
                finding(d, "CVE-NO-FIX-YET", Severity.CRITICAL, null)
        );

        RemediationPlan plan = engine.plan(d, findings);
        assertEquals("2.0", plan.recommendedVersion());
        assertEquals(1, plan.resolved());
        assertEquals(1, plan.remaining());
        assertEquals(1, plan.severityRemaining().get(Severity.CRITICAL));
    }

    @Test
    void noFindingsHaveAKnownFix_recommendsNothing() {
        NormalizedDependency d = dep("1.0");
        List<Finding> findings = List.of(finding(d, "CVE-X", Severity.HIGH, null));

        RemediationPlan plan = engine.plan(d, findings);
        assertNull(plan.recommendedVersion());
        assertEquals(0, plan.resolved());
        assertEquals(1, plan.remaining());
    }

    @Test
    void emptyFindingsList_isAlreadyClean() {
        NormalizedDependency d = dep("2.17.0");
        RemediationPlan plan = engine.plan(d, List.of());

        assertNull(plan.recommendedVersion());
        assertEquals(0, plan.findingsBefore());
        assertEquals(0, plan.remaining());
    }

    @Test
    void severityBreakdownAddsUpToTotals() {
        NormalizedDependency d = dep("1.0");
        List<Finding> findings = List.of(
                finding(d, "CVE-A", Severity.CRITICAL, "3.0"),
                finding(d, "CVE-B", Severity.HIGH, "2.0"),
                finding(d, "CVE-C", Severity.LOW, null)
        );

        RemediationPlan plan = engine.plan(d, findings);
        assertEquals("3.0", plan.recommendedVersion());
        int resolvedSum = plan.severityResolved().values().stream().mapToInt(Integer::intValue).sum();
        int remainingSum = plan.severityRemaining().values().stream().mapToInt(Integer::intValue).sum();
        assertEquals(plan.resolved(), resolvedSum);
        assertEquals(plan.remaining(), remainingSum);
        assertEquals(plan.findingsBefore(), resolvedSum + remainingSum);
    }
}
