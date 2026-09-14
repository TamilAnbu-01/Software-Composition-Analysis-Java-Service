package com.scascanner.service;

import com.scascanner.correlate.CorrelationEngine;
import com.scascanner.dedup.Deduplicator;
import com.scascanner.exception.InvalidDependencyException;
import com.scascanner.exception.VulnerabilitySourceException;
import com.scascanner.intel.VulnerabilitySource;
import com.scascanner.model.*;
import com.scascanner.normalize.DependencyNormalizer;
import com.scascanner.remediate.RemediationEngine;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Orchestrates one scan request end to end: normalize -> fetch candidate vulnerabilities ->
 * correlate -> deduplicate -> recommend remediation, for every dependency in the request.
 *
 * Deliberately framework-free (no Spring types anywhere in this class or its dependencies) so
 * the whole pipeline can be unit tested without standing up a web server.
 *
 * A problem with one dependency - bad input, or the vulnerability source failing for that one
 * package - is recorded as a ScanError and the rest of the request still completes.
 */
public class ScanService {

    private final DependencyNormalizer normalizer;
    private final VulnerabilitySource vulnerabilitySource;
    private final CorrelationEngine correlationEngine;
    private final Deduplicator deduplicator;
    private final RemediationEngine remediationEngine;
    private final ScanStore store;
    private final VulnerabilityStore vulnerabilityStore;

    public ScanService(
            DependencyNormalizer normalizer,
            VulnerabilitySource vulnerabilitySource,
            CorrelationEngine correlationEngine,
            Deduplicator deduplicator,
            RemediationEngine remediationEngine,
            ScanStore store,
            VulnerabilityStore vulnerabilityStore) {

        this.normalizer = normalizer;
        this.vulnerabilitySource = vulnerabilitySource;
        this.correlationEngine = correlationEngine;
        this.deduplicator = deduplicator;
        this.remediationEngine = remediationEngine;
        this.store = store;
        this.vulnerabilityStore = vulnerabilityStore;
    }

    public ScanResult scan(ScanRequest request) {
        List<Finding> allFindings = new ArrayList<>();
        List<RemediationPlan> allPlans = new ArrayList<>();
        List<ScanError> errors = new ArrayList<>();

        for (DependencyInput input : request.dependencies()) {

            NormalizedDependency dependency;

            try {
                dependency = normalizer.normalize(input);
            } catch (InvalidDependencyException e) {
                errors.add(new ScanError(describe(input), e.getMessage()));
                continue;
            }

            List<VulnerabilityRecord> candidates;

            try {
                candidates = vulnerabilitySource.findVulnerabilities(dependency);

                // Keep vulnerability records available for
                // GET /vulnerabilities/{id}.
                vulnerabilityStore.saveAll(candidates);

            } catch (VulnerabilitySourceException e) {
                errors.add(new ScanError(
                        dependency.canonicalKey(),
                        "could not query vulnerability source: " + e.getMessage()
                ));
                continue;
            }

            List<Finding> rawFindings =
                    correlationEngine.correlate(dependency, candidates);

            List<Finding> dedupedFindings =
                    deduplicator.deduplicate(rawFindings);

            allFindings.addAll(dedupedFindings);

            allPlans.add(
                    remediationEngine.plan(dependency, dedupedFindings)
            );
        }

        ScanResult result = new ScanResult(
                UUID.randomUUID().toString(),
                request.project(),
                Instant.now(),
                allFindings,
                allPlans,
                errors
        );

        store.save(result);

        return result;
    }

    public ScanResult getScan(String scanId) {
        return store.get(scanId);
    }

    public VulnerabilityRecord getVulnerability(String id) {
        return vulnerabilityStore.get(id);
    }

    private String describe(DependencyInput input) {
        if (input == null) {
            return "(null entry)";
        }

        String name = input.name() != null
                ? input.name()
                : "(missing name)";

        String version = input.version() != null
                ? input.version()
                : "(missing version)";

        return name + "@" + version;
    }
}