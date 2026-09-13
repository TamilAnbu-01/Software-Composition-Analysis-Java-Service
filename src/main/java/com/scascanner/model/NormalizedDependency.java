package com.scascanner.model;

/**
 * A dependency after normalization: ecosystem resolved to an enum, group+name collapsed into
 * one package key, and a single canonical string identity used for logging/dedup/display.
 *
 * packageKey is what the ecosystem calls the package - "group:artifact" for Maven,
 * just the package name for npm/PyPI/Go.
 */
public record NormalizedDependency(Ecosystem ecosystem, String packageKey, String version, String canonicalKey) {

    public static NormalizedDependency of(Ecosystem ecosystem, String packageKey, String version) {
        String canonical = ecosystem.name() + ":" + packageKey + ":" + version;
        return new NormalizedDependency(ecosystem, packageKey, version, canonical);
    }
}
