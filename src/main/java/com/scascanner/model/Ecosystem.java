package com.scascanner.model;

/**
 * Package ecosystems the scanner understands. Adding a new ecosystem means:
 *   1. adding a case here,
 *   2. teaching {@link com.scascanner.normalize.DependencyNormalizer} how to build its canonical key,
 *   3. registering a {@link com.scascanner.version.VersionComparator} for it in
 *      {@link com.scascanner.version.VersionComparators}.
 * No other class needs to change - correlation, dedup and remediation are ecosystem-agnostic.
 */
public enum Ecosystem {
    MAVEN,
    NPM,
    PYPI,
    GO,
    UNKNOWN;

    /** Case-insensitive parse. Never throws - unrecognized input becomes UNKNOWN so a single
     *  bad dependency entry degrades gracefully instead of failing the whole scan request. */
    public static Ecosystem fromString(String raw) {
        if (raw == null || raw.isBlank()) {
            return UNKNOWN;
        }
        try {
            return Ecosystem.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }

    /** The ecosystem name as the GitHub Advisory Database's REST API expects it. */
    public String githubEcosystemName() {
        return switch (this) {
            case MAVEN -> "maven";
            case NPM -> "npm";
            case PYPI -> "pip";
            case GO -> "go";
            case UNKNOWN -> throw new IllegalStateException("UNKNOWN ecosystem has no advisory-source mapping");
        };
    }
}
