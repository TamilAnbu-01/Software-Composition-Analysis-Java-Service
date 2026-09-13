package com.scascanner.version;

import com.scascanner.model.Ecosystem;

import java.util.EnumMap;
import java.util.Map;

/** Registry mapping each supported ecosystem to its version comparator. */
public final class VersionComparators {

    private static final Map<Ecosystem, VersionComparator> REGISTRY = new EnumMap<>(Ecosystem.class);

    static {
        REGISTRY.put(Ecosystem.MAVEN, new MavenVersionComparator());
        REGISTRY.put(Ecosystem.NPM, new SemverLikeComparator());
        REGISTRY.put(Ecosystem.PYPI, new SemverLikeComparator());
    }

    private VersionComparators() {
    }

    public static VersionComparator forEcosystem(Ecosystem ecosystem) {
        VersionComparator c = REGISTRY.get(ecosystem);
        if (c == null) {
            throw new UnsupportedOperationException(
                    "No version comparator registered for ecosystem " + ecosystem
                            + ". Supported: " + REGISTRY.keySet());
        }
        return c;
    }

    public static boolean isSupported(Ecosystem ecosystem) {
        return REGISTRY.containsKey(ecosystem);
    }
}
