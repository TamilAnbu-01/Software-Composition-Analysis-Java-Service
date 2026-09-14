package com.scascanner.normalize;

import com.scascanner.exception.InvalidDependencyException;
import com.scascanner.model.DependencyInput;
import com.scascanner.model.Ecosystem;
import com.scascanner.model.NormalizedDependency;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DependencyNormalizerTest {

    private final DependencyNormalizer normalizer = new DependencyNormalizer();

    @Test
    void mavenDependency_buildsGroupColonArtifactKey() {
        NormalizedDependency n = normalizer.normalize(
                new DependencyInput("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"));

        assertEquals(Ecosystem.MAVEN, n.ecosystem());
        assertEquals("org.apache.logging.log4j:log4j-core", n.packageKey());
        assertEquals("2.14.1", n.version());
        assertEquals("MAVEN:org.apache.logging.log4j:log4j-core:2.14.1", n.canonicalKey());
    }

    @Test
    void ecosystemIsCaseInsensitive() {
        NormalizedDependency n = normalizer.normalize(
                new DependencyInput("MAVEN", "com.example", "lib", "1.0"));
        assertEquals(Ecosystem.MAVEN, n.ecosystem());
    }

    @Test
    void npmDependencyWithoutGroup_usesNameAlone() {
        NormalizedDependency n = normalizer.normalize(new DependencyInput("npm", null, "lodash", "4.17.21"));
        assertEquals("lodash", n.packageKey());
    }

    @Test
    void npmScopedPackage_combinesGroupAndName() {
        NormalizedDependency n = normalizer.normalize(new DependencyInput("npm", "@babel", "core", "7.20.0"));
        assertEquals("@babel/core", n.packageKey());
    }

    @Test
    void mavenWithoutGroup_isRejected() {
        InvalidDependencyException ex = assertThrows(InvalidDependencyException.class, () ->
                normalizer.normalize(new DependencyInput("maven", null, "log4j-core", "2.14.1")));
        assertTrue(ex.getMessage().contains("group"));
    }

    @Test
    void missingVersion_isRejected() {
        assertThrows(InvalidDependencyException.class, () ->
                normalizer.normalize(new DependencyInput("maven", "com.example", "lib", null)));
    }

    @Test
    void missingName_isRejected() {
        assertThrows(InvalidDependencyException.class, () ->
                normalizer.normalize(new DependencyInput("maven", "com.example", " ", "1.0")));
    }

    @Test
    void unrecognizedEcosystem_isRejectedNotDefaulted() {
        InvalidDependencyException ex = assertThrows(InvalidDependencyException.class, () ->
                normalizer.normalize(new DependencyInput("cargo", null, "serde", "1.0")));
        assertTrue(ex.getMessage().toLowerCase().contains("ecosystem"));
    }

    @Test
    void nullInput_isRejected() {
        assertThrows(InvalidDependencyException.class, () -> normalizer.normalize(null));
    }
}
