package com.scascanner.service;

import com.scascanner.correlate.CorrelationEngine;
import com.scascanner.dedup.Deduplicator;
import com.scascanner.exception.VulnerabilitySourceException;
import com.scascanner.intel.VulnerabilitySource;
import com.scascanner.model.*;
import com.scascanner.normalize.DependencyNormalizer;
import com.scascanner.remediate.RemediationEngine;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ScanServiceTest {

    /** A fake source: returns one CRITICAL vulnerability for log4j-core, nothing for anything
     *  else, and throws for a package name containing "unreachable" to exercise the
     *  source-failure error path without any real network call. */
    private static class FakeSource implements VulnerabilitySource {
        @Override
        public String name() {
            return "FAKE";
        }

        @Override
        public List<VulnerabilityRecord> findVulnerabilities(NormalizedDependency dependency) {
            if (dependency.packageKey().contains("unreachable")) {
                throw new VulnerabilitySourceException("simulated outage");
            }
            if (dependency.packageKey().equals("org.apache.logging.log4j:log4j-core")) {
                return List.of(new VulnerabilityRecord("CVE-2021-44228", Set.of(), "Log4Shell",
                        Severity.CRITICAL, Ecosystem.MAVEN, dependency.packageKey(),
                        List.of(new VersionRange(null, "2.15.0", null)), "FAKE"));
            }
            return List.of();
        }
    }

    private ScanService newService() {
        return new ScanService(new DependencyNormalizer(), new FakeSource(),
                new CorrelationEngine(), new Deduplicator(), new RemediationEngine(), new ScanStore());
    }

    @Test
    void scanWithOneVulnerableDependency_producesFindingAndRemediation() {
        ScanRequest request = new ScanRequest("payment-service", List.of(
                new DependencyInput("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1")));

        ScanResult result = newService().scan(request);

        assertEquals(1, result.findings().size());
        assertEquals(1, result.remediations().size());
        assertEquals("2.15.0", result.remediations().get(0).recommendedVersion());
        assertTrue(result.errors().isEmpty());
    }

    @Test
    void invalidDependencyEntry_isReportedAsErrorAndDoesNotStopTheRest() {
        ScanRequest request = new ScanRequest("payment-service", List.of(
                new DependencyInput("maven", null, "log4j-core", "2.14.1"), // missing group id -> invalid
                new DependencyInput("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"))); // valid

        ScanResult result = newService().scan(request);

        assertEquals(1, result.errors().size());
        assertEquals(1, result.findings().size(), "the valid entry should still be scanned");
    }

    @Test
    void sourceFailureForOneDependency_isReportedAsErrorAndDoesNotStopTheRest() {
        ScanRequest request = new ScanRequest("payment-service", List.of(
                new DependencyInput("maven", "com.example", "unreachable-lib", "1.0.0"),
                new DependencyInput("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1")));

        ScanResult result = newService().scan(request);

        assertEquals(1, result.errors().size());
        assertTrue(result.errors().get(0).reason().contains("simulated outage"));
        assertEquals(1, result.findings().size());
    }

    @Test
    void emptyDependencyList_isAValidCleanScan() {
        ScanResult result = newService().scan(new ScanRequest("empty-project", List.of()));
        assertTrue(result.findings().isEmpty());
        assertTrue(result.remediations().isEmpty());
        assertTrue(result.errors().isEmpty());
    }

    @Test
    void scanResultIsRetrievableByScanId() {
        ScanService service = newService();
        ScanResult result = service.scan(new ScanRequest("proj", List.of()));

        ScanResult retrieved = service.getScan(result.scanId());
        assertNotNull(retrieved);
        assertEquals(result.scanId(), retrieved.scanId());
    }

    @Test
    void unknownScanId_returnsNull() {
        assertNull(newService().getScan("does-not-exist"));
    }
}
