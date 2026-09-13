package com.scascanner.model;

import java.util.Locale;

/**
 * Ordered worst-to-best so {@code CRITICAL.compareTo(LOW) < 0}, which lets callers
 * sort findings by severity using the enum's natural ordering.
 */
public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    UNKNOWN;

    /** Case-insensitive parse. An unrecognized or missing severity string becomes UNKNOWN
     *  rather than being thrown away or defaulted to something falsely reassuring like LOW -
     *  the finding itself is still real and still reported. */
    public static Severity fromString(String raw) {
        if (raw == null || raw.isBlank()) {
            return UNKNOWN;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "critical" -> CRITICAL;
            case "high" -> HIGH;
            case "medium", "moderate" -> MEDIUM;
            case "low" -> LOW;
            default -> UNKNOWN;
        };
    }

    /** True if this severity is at least as bad as {@code other}. UNKNOWN is treated as the
     *  least severe so it never silently outranks a known severity when merging duplicates. */
    public boolean atLeastAsSevereAs(Severity other) {
        return this.rank() <= other.rank();
    }

    private int rank() {
        return this == UNKNOWN ? Integer.MAX_VALUE : this.ordinal();
    }
}
