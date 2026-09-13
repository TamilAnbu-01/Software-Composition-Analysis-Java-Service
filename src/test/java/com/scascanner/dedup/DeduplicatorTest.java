package com.scascanner.dedup;

import com.scascanner.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class DeduplicatorTest {

    private final Deduplicator dedup = new Deduplicator();

    private NormalizedDependency dep() {
        return NormalizedDependency.of(Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.14.1");
    }

    private VulnerabilityRecord record(String id, Set<String> aliases, Severity sev, String fixed, String source) {
        return new VulnerabilityRecord(id, aliases, "desc", sev, Ecosystem.MAVEN,
                "org.apache.logging.log4j:log4j-core",
                List.of(new VersionRange(null, fixed, null)), source);
    }

    @Test
    void exactDuplicateIdsCollapseToOneFinding() {
        VulnerabilityRecord v1 = record("CVE-2021-44228", Set.of(), Severity.CRITICAL, "2.15.0", "SRC_A");
        VulnerabilityRecord v2 = record("CVE-2021-44228", Set.of(), Severity.CRITICAL, "2.15.0", "SRC_B");
        VulnerabilityRecord v3 = record("CVE-2021-44228", Set.of(), Severity.CRITICAL, "2.15.0", "SRC_C");

        List<Finding> input = List.of(
                new Finding(dep(), v1, "2.15.0"),
                new Finding(dep(), v2, "2.15.0"),
                new Finding(dep(), v3, "2.15.0"));

        List<Finding> result = dedup.deduplicate(input);
        assertEquals(1, result.size(), "three identical CVE records must not produce three findings");
    }

    @Test
    void crossReferencedAliasesMergeAcrossSources() {
        // GHSA advisory that lists the CVE as an alias, and a second source that only knows
        // the vendor advisory id but cross-references the same GHSA.
        VulnerabilityRecord ghsa = record("GHSA-jfh8-c2jp-5v3q", Set.of("CVE-2021-44228"),
                Severity.CRITICAL, "2.15.0", "GHSA");
        VulnerabilityRecord vendor = record("VENDOR-LOG4J-001", Set.of("GHSA-jfh8-c2jp-5v3q"),
                Severity.HIGH, "2.15.0", "VENDOR");

        List<Finding> result = dedup.deduplicate(List.of(
                new Finding(dep(), ghsa, "2.15.0"),
                new Finding(dep(), vendor, "2.15.0")));

        assertEquals(1, result.size());
        VulnerabilityRecord merged = result.get(0).vulnerability();
        assertTrue(merged.allIdentifiers().containsAll(
                Set.of("GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "VENDOR-LOG4J-001")));
    }

    @Test
    void mergingPrefersCveIdAsTheDisplayId() {
        VulnerabilityRecord ghsa = record("GHSA-xxxx", Set.of("CVE-2021-44228"), Severity.CRITICAL, "2.15.0", "GHSA");
        VulnerabilityRecord dupGhsa = record("GHSA-xxxx", Set.of(), Severity.CRITICAL, "2.15.0", "GHSA");

        // force a merge by giving the CVE its own record too
        VulnerabilityRecord cveRecord = record("CVE-2021-44228", Set.of("GHSA-xxxx"), Severity.CRITICAL, "2.15.0", "NVD");

        List<Finding> result = dedup.deduplicate(List.of(
                new Finding(dep(), ghsa, "2.15.0"),
                new Finding(dep(), cveRecord, "2.15.0")));

        assertEquals(1, result.size());
        assertEquals("CVE-2021-44228", result.get(0).vulnerability().id());
    }

    @Test
    void unrelatedVulnerabilitiesAreNotMerged() {
        VulnerabilityRecord a = record("CVE-2021-44228", Set.of(), Severity.CRITICAL, "2.15.0", "SRC");
        VulnerabilityRecord b = record("CVE-2021-45105", Set.of(), Severity.MEDIUM, "2.17.0", "SRC");

        List<Finding> result = dedup.deduplicate(List.of(new Finding(dep(), a, "2.15.0"), new Finding(dep(), b, "2.17.0")));
        assertEquals(2, result.size());
    }

    @Test
    void mergingKeepsTheMoreConservativeHigherSeverity() {
        VulnerabilityRecord low = record("CVE-1", Set.of("GHSA-1"), Severity.MEDIUM, "1.1", "SRC_A");
        VulnerabilityRecord high = record("GHSA-1", Set.of(), Severity.CRITICAL, "1.1", "SRC_B");

        List<Finding> result = dedup.deduplicate(List.of(new Finding(dep(), low, "1.1"), new Finding(dep(), high, "1.1")));
        assertEquals(1, result.size());
        assertEquals(Severity.CRITICAL, result.get(0).vulnerability().severity());
    }
}
