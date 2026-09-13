package com.scascanner.normalize;

import com.scascanner.exception.InvalidDependencyException;
import com.scascanner.model.DependencyInput;
import com.scascanner.model.Ecosystem;
import com.scascanner.model.NormalizedDependency;
import com.scascanner.version.VersionComparators;

/**
 * Turns raw wire input into a {@link NormalizedDependency}, or rejects it with a message
 * precise enough to put straight into a {@link com.scascanner.model.ScanError}.
 *
 * This is intentionally the only place that knows how each ecosystem's coordinates are
 * assembled into a canonical package key - everything downstream (correlation, dedup,
 * remediation) works off the resulting packageKey and never re-derives it.
 */
public class DependencyNormalizer {

    public NormalizedDependency normalize(DependencyInput input) {
        if (input == null) {
            throw new InvalidDependencyException("dependency entry is null");
        }

        Ecosystem ecosystem = Ecosystem.fromString(input.ecosystem());
        if (ecosystem == Ecosystem.UNKNOWN) {
            throw new InvalidDependencyException(
                    "unrecognized ecosystem '" + input.ecosystem() + "'");
        }
        if (!VersionComparators.isSupported(ecosystem)) {
            throw new InvalidDependencyException(
                    "ecosystem '" + ecosystem + "' is not yet supported (no version comparator registered)");
        }

        String name = blankToNull(input.name());
        if (name == null) {
            throw new InvalidDependencyException("dependency name is missing");
        }

        String version = blankToNull(input.version());
        if (version == null) {
            throw new InvalidDependencyException("dependency '" + name + "' has no version");
        }

        String group = blankToNull(input.group());
        String packageKey = buildPackageKey(ecosystem, group, name);

        return NormalizedDependency.of(ecosystem, packageKey, version.trim());
    }

    private String buildPackageKey(Ecosystem ecosystem, String group, String name) {
        return switch (ecosystem) {
            case MAVEN -> {
                if (group == null) {
                    throw new InvalidDependencyException(
                            "Maven dependency '" + name + "' is missing its group id");
                }
                yield group.trim() + ":" + name.trim();
            }
            case NPM, GO -> group == null ? name.trim() : group.trim() + "/" + name.trim();
            case PYPI -> name.trim();
            case UNKNOWN -> throw new IllegalStateException("unreachable: UNKNOWN filtered out above");
        };
    }

    private String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
