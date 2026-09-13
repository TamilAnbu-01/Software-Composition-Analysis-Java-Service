package com.scascanner.version;

/**
 * Ecosystem-specific version ordering. Implementations must NOT fall back to lexical string
 * comparison - "1.9" vs "1.10" is the canonical case that breaks under lexical comparison
 * (lexically "1.10" < "1.9") and every implementation here is tested against it.
 */
public interface VersionComparator {

    /** Standard compareTo contract: negative if a &lt; b, zero if equal, positive if a &gt; b. */
    int compare(String a, String b);

    default boolean lessThan(String a, String b) {
        return compare(a, b) < 0;
    }

    default boolean lessThanOrEqual(String a, String b) {
        return compare(a, b) <= 0;
    }

    default boolean greaterThanOrEqual(String a, String b) {
        return compare(a, b) >= 0;
    }
}
