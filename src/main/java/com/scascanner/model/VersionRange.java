package com.scascanner.model;

/**
 * One affected-version interval for a vulnerability, e.g. "&gt;= 2.21.0, &lt; 2.25.4".
 *
 * introducedInclusive: lower bound, inclusive. Null means "since the beginning of time" (0).
 * fixedExclusive: upper bound, exclusive - the version where the fix landed. Null if unknown.
 * lastAffectedInclusive: alternative upper bound, inclusive, used when the source states the
 *   last known-bad version rather than a clean fixed version. At most one of fixedExclusive /
 *   lastAffectedInclusive is normally set; if both are absent the range is open-ended (still
 *   vulnerable at every version at or above introducedInclusive, per available data).
 */
public record VersionRange(String introducedInclusive, String fixedExclusive, String lastAffectedInclusive) {

    /** The version to recommend upgrading to for this specific range, if the data gives one.
     *  A lastAffectedInclusive-only range has no known-good version to name, so this is null -
     *  remediation must not assume "latest" from a range like this. */
    public String candidateFixVersion() {
        return fixedExclusive;
    }
}
