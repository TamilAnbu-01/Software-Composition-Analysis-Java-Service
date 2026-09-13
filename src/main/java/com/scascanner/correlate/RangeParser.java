package com.scascanner.correlate;

import com.scascanner.model.VersionRange;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses the constraint-string form vulnerability sources use for an affected range, e.g.:
 *   "&gt;= 2.21.0, &lt; 2.25.4"
 *   "&lt; 2.15.0"
 *   "= 1.2.3"
 * into a {@link VersionRange}. Comma-separated constraints within one string are AND'ed
 * together (they describe one interval); if a package has several disjoint vulnerable
 * intervals, the source represents that as several separate range strings, each parsed
 * independently and OR'ed together at the {@link VulnerabilityRecord} level.
 *
 * This never throws: a constraint segment it doesn't recognize is skipped rather than failing
 * the whole advisory, per the "invalid vulnerability data" case in the error-handling
 * requirements. If nothing in the string is parseable, the result is a fully-open range
 * (matches everything) - safer to over-report a finding than to silently drop it because of a
 * formatting quirk in the source data.
 */
public class RangeParser {

    private static final Pattern CONSTRAINT =
            Pattern.compile("(>=|<=|>|<|==|=)\\s*([0-9A-Za-z.\\-+_]+)");

    public VersionRange parse(String constraintString, String fixedVersionHint) {
        String introduced = null;
        String fixedExclusive = null;
        String lastAffectedInclusive = null;

        if (constraintString != null && !constraintString.isBlank()) {
            Matcher m = CONSTRAINT.matcher(constraintString);
            while (m.find()) {
                String op = m.group(1);
                String version = m.group(2);
                switch (op) {
                    case ">=" -> introduced = version;
                    case ">" -> introduced = version; // treated as inclusive-from-next-version; see class javadoc on simplifications
                    case "<" -> fixedExclusive = version;
                    case "<=" -> lastAffectedInclusive = version;
                    case "=", "==" -> {
                        introduced = version;
                        lastAffectedInclusive = version;
                    }
                    default -> { /* unrecognized operator - ignore this segment */ }
                }
            }
        }

        // A source-provided "first patched version" is authoritative when present, even if the
        // free-text constraint string didn't contain a clean "<" bound.
        if (fixedVersionHint != null && !fixedVersionHint.isBlank()) {
            fixedExclusive = fixedVersionHint;
        }

        return new VersionRange(introduced, fixedExclusive, lastAffectedInclusive);
    }

    /** Splits a source's top-level range list on commas that separate whole constraints,
     *  used when a source gives one comma-separated string per disjoint interval rather than
     *  pre-split ranges. Not needed for the GitHub Advisory client (it already gives one
     *  string per interval) but kept here for sources that don't. */
    public List<String> splitDisjointRanges(String raw) {
        List<String> result = new ArrayList<>();
        if (raw == null || raw.isBlank()) return result;
        for (String part : raw.split(";")) {
            if (!part.isBlank()) result.add(part.trim());
        }
        return result;
    }
}
