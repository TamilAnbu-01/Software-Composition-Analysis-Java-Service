package com.scascanner.version;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MavenVersionComparatorTest {

    private final VersionComparator cmp = new MavenVersionComparator();

    @Test
    void ordersNumericSegmentsNumericallyNotLexically() {
        // The canonical trap: lexically "1.10" < "1.9", numerically it must not be.
        assertTrue(cmp.lessThan("1.9", "1.10"), "1.9 should be less than 1.10");
        assertTrue(cmp.lessThan("1.10", "2.0"));
        assertTrue(cmp.lessThan("2.0", "2.0.1"));
        assertTrue(cmp.lessThan("2.0.1", "2.10.0"));
    }

    @Test
    void assignmentBriefExamples() {
        assertTrue(cmp.lessThan("2.14.1", "2.15.0"));
        assertEquals(0, cmp.compare("2.15.0", "2.15.0"));
        assertTrue(cmp.compare("2.16.0", "2.15.0") > 0);
        assertTrue(cmp.compare("2.10.0", "2.9.0") > 0);
    }

    @Test
    void log4jFullChain() {
        assertTrue(cmp.lessThan("2.14.1", "2.15.0"));
        assertTrue(cmp.lessThan("2.15.0", "2.16.0"));
        assertTrue(cmp.lessThan("2.16.0", "2.17.0"));
    }

    @Test
    void missingTrailingZerosAreEqual() {
        assertEquals(0, cmp.compare("1.0", "1.0.0"));
        assertEquals(0, cmp.compare("1.0.0", "1.0.0.0"));
    }

    @Test
    void finalReleaseQualifiersAreEquivalentToNoQualifier() {
        assertEquals(0, cmp.compare("1.0.0", "1.0.0.RELEASE"));
        assertEquals(0, cmp.compare("1.0.0", "1.0.0-GA"));
        assertEquals(0, cmp.compare("1.0.0-final", "1.0.0"));
    }

    @Test
    void preReleaseQualifiersRankBelowFinal() {
        assertTrue(cmp.lessThan("1.0.0-alpha", "1.0.0-beta"));
        assertTrue(cmp.lessThan("1.0.0-beta", "1.0.0-milestone1"));
        assertTrue(cmp.lessThan("1.0.0-milestone1", "1.0.0-rc1"));
        assertTrue(cmp.lessThan("1.0.0-rc1", "1.0.0"));
        assertTrue(cmp.lessThan("1.0.0-alpha", "1.0.0"));
    }

    @Test
    void spQualifierRanksAboveFinal() {
        assertTrue(cmp.compare("1.0.0-sp1", "1.0.0") > 0);
    }

    @Test
    void numberBeatsQualifierAtSamePosition() {
        assertTrue(cmp.compare("1.0.5", "1.0-beta") > 0);
    }

    @Test
    void snapshotRanksBelowFinalButAboveRc() {
        assertTrue(cmp.lessThan("1.0-rc1", "1.0-SNAPSHOT"));
        assertTrue(cmp.lessThan("1.0-SNAPSHOT", "1.0"));
    }

    @Test
    void comparisonIsCaseInsensitiveForQualifiers() {
        assertEquals(0, cmp.compare("1.0.0-Alpha", "1.0.0-ALPHA"));
    }

    @Test
    void handlesNullAndBlankAsZero() {
        assertEquals(0, cmp.compare(null, "0"));
        assertEquals(0, cmp.compare("", "0.0.0"));
    }
}
