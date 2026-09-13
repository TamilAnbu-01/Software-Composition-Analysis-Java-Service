package com.scascanner.correlate;

import com.scascanner.model.Finding;
import com.scascanner.model.NormalizedDependency;
import com.scascanner.model.VersionRange;
import com.scascanner.model.VulnerabilityRecord;
import com.scascanner.version.VersionComparator;
import com.scascanner.version.VersionComparators;

import java.util.ArrayList;
import java.util.List;

/**
 * Decides, for one dependency, which of its candidate vulnerabilities actually apply at the
 * installed version - the "Package identity matching -&gt; affected-version evaluation -&gt;
 * vulnerable/not vulnerable" pipeline from the assignment brief.
 *
 * Callers are expected to have already narrowed {@code candidates} to vulnerabilities that
 * target this dependency's package (the intelligence source does that); this class only
 * evaluates version ranges, it does not re-check package identity.
 */
public class CorrelationEngine {

    public List<Finding> correlate(NormalizedDependency dependency, List<VulnerabilityRecord> candidates) {
        VersionComparator cmp = VersionComparators.forEcosystem(dependency.ecosystem());
        String installed = dependency.version();

        List<Finding> findings = new ArrayList<>();
        for (VulnerabilityRecord vulnerability : candidates) {
            String nearestFix = null;
            boolean vulnerable = false;

            for (VersionRange range : vulnerability.ranges()) {
                if (!isAffected(cmp, installed, range)) {
                    continue;
                }
                vulnerable = true;
                String candidateFix = range.candidateFixVersion();
                if (candidateFix != null && (nearestFix == null || cmp.lessThan(candidateFix, nearestFix))) {
                    nearestFix = candidateFix;
                }
            }

            if (vulnerable) {
                findings.add(new Finding(dependency, vulnerability, nearestFix));
            }
        }
        return findings;
    }

    private boolean isAffected(VersionComparator cmp, String installed, VersionRange range) {
        if (range.introducedInclusive() != null && cmp.lessThan(installed, range.introducedInclusive())) {
            return false; // installed predates the range entirely
        }
        if (range.fixedExclusive() != null) {
            return cmp.lessThan(installed, range.fixedExclusive());
        }
        if (range.lastAffectedInclusive() != null) {
            return cmp.lessThanOrEqual(installed, range.lastAffectedInclusive());
        }
        // No upper bound at all in the source data: still vulnerable at every version from
        // introducedInclusive onward, as far as we know.
        return true;
    }
}
