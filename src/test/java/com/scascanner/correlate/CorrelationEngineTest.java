package com.scascanner.correlate;

import com.scascanner.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CorrelationEngineTest {

    private final CorrelationEngine engine = new CorrelationEngine();

    private VulnerabilityRecord vuln(String id, Severity sev, VersionRange range) {
        return new VulnerabilityRecord(id, Set.of(), "test vuln " + id, sev,
                Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", List.of(range), "TEST");
    }

    @Test
    void log4jShellExampleFromBrief_identifiesBothVulnerabilities() {
        NormalizedDependency dep = NormalizedDependency.of(
                Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.14.1");

        VulnerabilityRecord critical = vuln("CVE-2021-44228", Severity.CRITICAL,
                new VersionRange(null, "2.15.0", null));
        VulnerabilityRecord high = vuln("CVE-2021-45046", Severity.HIGH,
                new VersionRange(null, "2.16.0", null));

        List<Finding> findings = engine.correlate(dep, List.of(critical, high));

        assertEquals(2, findings.size());
        assertTrue(findings.stream().anyMatch(f -> f.vulnerability().id().equals("CVE-2021-44228")));
        assertTrue(findings.stream().anyMatch(f -> f.vulnerability().id().equals("CVE-2021-45046")));
    }

    @Test
    void installedAtOrAboveFixedVersion_isNotVulnerable() {
        NormalizedDependency dep = NormalizedDependency.of(
                Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.15.0");
        VulnerabilityRecord v = vuln("CVE-X", Severity.CRITICAL, new VersionRange(null, "2.15.0", null));

        assertTrue(engine.correlate(dep, List.of(v)).isEmpty(),
                "fixedExclusive is exclusive: installed == fixed version means not vulnerable");
    }

    @Test
    void installedBelowIntroduced_isNotVulnerable() {
        NormalizedDependency dep = NormalizedDependency.of(
                Ecosystem.MAVEN, "com.example:lib", "0.9.0");
        VulnerabilityRecord v = vuln("CVE-Y", Severity.MEDIUM, new VersionRange("1.0.0", "1.5.0", null));

        assertTrue(engine.correlate(dep, List.of(v)).isEmpty());
    }

    @Test
    void lastAffectedInclusive_installedAtBoundary_isVulnerable() {
        NormalizedDependency dep = NormalizedDependency.of(Ecosystem.MAVEN, "com.example:lib", "1.5.0");
        VulnerabilityRecord v = vuln("CVE-Z", Severity.LOW, new VersionRange(null, null, "1.5.0"));

        List<Finding> findings = engine.correlate(dep, List.of(v));
        assertEquals(1, findings.size());
        assertNull(findings.get(0).fixedVersion(), "a last-affected-only range has no known fix version");
    }

    @Test
    void openEndedRangeWithNoUpperBound_isAlwaysVulnerableFromIntroduced() {
        NormalizedDependency dep = NormalizedDependency.of(Ecosystem.MAVEN, "com.example:lib", "99.0.0");
        VulnerabilityRecord v = vuln("CVE-OPEN", Severity.HIGH, new VersionRange("1.0.0", null, null));

        assertEquals(1, engine.correlate(dep, List.of(v)).size());
    }

    @Test
    void dependencyAffectedByMultipleVulnerabilities_producesOneFindingEach() {
        NormalizedDependency dep = NormalizedDependency.of(
                Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.14.1");
        VulnerabilityRecord critical = vuln("CVE-2021-44228", Severity.CRITICAL, new VersionRange(null, "2.15.0", null));
        VulnerabilityRecord high = vuln("CVE-2021-45046", Severity.HIGH, new VersionRange(null, "2.16.0", null));
        VulnerabilityRecord medium = vuln("CVE-2021-45105", Severity.MEDIUM, new VersionRange(null, "2.17.0", null));

        List<Finding> findings = engine.correlate(dep, List.of(critical, high, medium));
        assertEquals(3, findings.size());
    }

    @Test
    void nearestFixIsTheClosestOneAboveInstalled_whenARecordHasMultipleRanges() {
        // A single advisory covering two disjoint vulnerable intervals, e.g. an old 2.x line
        // and a 3.x pre-release line - only the range that actually matches should set the fix.
        NormalizedDependency dep = NormalizedDependency.of(Ecosystem.MAVEN, "com.example:lib", "2.1.0");
        VulnerabilityRecord v = new VulnerabilityRecord("GHSA-1", Set.of(), "multi-range", Severity.HIGH,
                Ecosystem.MAVEN, "com.example:lib",
                List.of(new VersionRange("2.0.0", "2.2.0", null),
                        new VersionRange("3.0.0-beta1", "3.0.0-beta4", null)),
                "GHSA");

        List<Finding> findings = engine.correlate(dep, List.of(v));
        assertEquals(1, findings.size());
        assertEquals("2.2.0", findings.get(0).fixedVersion());
    }
}
