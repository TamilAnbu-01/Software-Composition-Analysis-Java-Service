package com.scascanner.model;

/**
 * One correlated result: this dependency, at this version, is affected by this vulnerability.
 * fixedVersion is the nearest known version that clears the specific range that matched -
 * null if the data doesn't name one (e.g. a "last affected" range with no clean fix yet).
 */
public record Finding(NormalizedDependency dependency, VulnerabilityRecord vulnerability, String fixedVersion) {
}
