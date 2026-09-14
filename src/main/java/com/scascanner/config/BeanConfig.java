package com.scascanner.config;

import com.scascanner.correlate.CorrelationEngine;
import com.scascanner.dedup.Deduplicator;
import com.scascanner.intel.GitHubAdvisorySource;
import com.scascanner.intel.VulnerabilitySource;
import com.scascanner.normalize.DependencyNormalizer;
import com.scascanner.remediate.RemediationEngine;
import com.scascanner.remediate.RemediationPriorityRanker;
import com.scascanner.service.ScanService;
import com.scascanner.service.ScanStore;
import com.scascanner.service.VulnerabilityStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the framework-free core (normalize/intel/correlate/dedup/remediate/service)
 * as Spring beans.
 *
 * Deliberately kept separate from the domain classes themselves - none of them
 * import Spring, so they stay usable outside a Spring context.
 */
@Configuration
public class BeanConfig {

    @Bean
    public DependencyNormalizer dependencyNormalizer() {
        return new DependencyNormalizer();
    }

    @Bean
    public VulnerabilitySource vulnerabilitySource() {
        return new GitHubAdvisorySource();
    }

    @Bean
    public CorrelationEngine correlationEngine() {
        return new CorrelationEngine();
    }

    @Bean
    public Deduplicator deduplicator() {
        return new Deduplicator();
    }

    @Bean
    public RemediationEngine remediationEngine() {
        return new RemediationEngine();
    }

    @Bean
    public RemediationPriorityRanker remediationPriorityRanker() {
        return new RemediationPriorityRanker();
    }

    @Bean
    public ScanStore scanStore() {
        return new ScanStore();
    }

    @Bean
    public VulnerabilityStore vulnerabilityStore() {
        return new VulnerabilityStore();
    }

    @Bean
    public ScanService scanService(
            DependencyNormalizer normalizer,
            VulnerabilitySource vulnerabilitySource,
            CorrelationEngine correlationEngine,
            Deduplicator deduplicator,
            RemediationEngine remediationEngine,
            ScanStore scanStore,
            VulnerabilityStore vulnerabilityStore) {

        return new ScanService(
                normalizer,
                vulnerabilitySource,
                correlationEngine,
                deduplicator,
                remediationEngine,
                scanStore,
                vulnerabilityStore
        );
    }
}