package com.scascanner.version;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Semantic Versioning 2.0.0 precedence, used as the ecosystem comparator for npm and (as an
 * approximation - see below) PyPI.
 *
 * Build metadata (anything after "+") is ignored for comparison. A pre-release version has
 * lower precedence than the same core version without one ("1.0.0-alpha" &lt; "1.0.0"), and two
 * pre-release versions are compared identifier-by-identifier: purely numeric identifiers
 * compare numerically, anything else compares as an ASCII string, and numeric identifiers
 * always have lower precedence than non-numeric ones at the same position.
 *
 * Known limitation: PyPI packages follow PEP 440, not SemVer - they mostly overlap (numeric
 * dotted releases, "a"/"b"/"rc" pre-release markers) but PEP 440's epoch segment and ".postN" /
 * ".devN" segments are not modeled here. This comparator handles the common case; a
 * PEP-440-accurate comparator would be a follow-up if PyPI support needed to be exact.
 */
public class SemverLikeComparator implements VersionComparator {

    @Override
    public int compare(String rawA, String rawB) {
        String a = stripBuildMetadata(rawA);
        String b = stripBuildMetadata(rawB);

        String[] coreAndPreA = splitCoreAndPreRelease(a);
        String[] coreAndPreB = splitCoreAndPreRelease(b);

        int coreCmp = compareCore(coreAndPreA[0], coreAndPreB[0]);
        if (coreCmp != 0) return coreCmp;

        String preA = coreAndPreA[1];
        String preB = coreAndPreB[1];
        if (preA == null && preB == null) return 0;
        if (preA == null) return 1;   // no pre-release beats any pre-release
        if (preB == null) return -1;
        return comparePreRelease(preA, preB);
    }

    private String stripBuildMetadata(String v) {
        if (v == null) return "0";
        int plus = v.indexOf('+');
        return plus >= 0 ? v.substring(0, plus) : v;
    }

    /** returns [core, preReleaseOrNull] */
    private String[] splitCoreAndPreRelease(String v) {
        int dash = v.indexOf('-');
        if (dash < 0) return new String[]{v, null};
        return new String[]{v.substring(0, dash), v.substring(dash + 1)};
    }

    private int compareCore(String a, String b) {
        List<BigInteger> pa = coreParts(a);
        List<BigInteger> pb = coreParts(b);
        int max = Math.max(pa.size(), pb.size());
        for (int i = 0; i < max; i++) {
            BigInteger x = i < pa.size() ? pa.get(i) : BigInteger.ZERO;
            BigInteger y = i < pb.size() ? pb.get(i) : BigInteger.ZERO;
            int c = x.compareTo(y);
            if (c != 0) return c;
        }
        return 0;
    }

    private List<BigInteger> coreParts(String core) {
        List<BigInteger> parts = new ArrayList<>();
        for (String piece : core.split("\\.")) {
            if (piece.isEmpty()) continue;
            StringBuilder digits = new StringBuilder();
            for (int i = 0; i < piece.length() && Character.isDigit(piece.charAt(i)); i++) {
                digits.append(piece.charAt(i));
            }
            parts.add(digits.length() == 0 ? BigInteger.ZERO : new BigInteger(digits.toString()));
        }
        if (parts.isEmpty()) parts.add(BigInteger.ZERO);
        return parts;
    }

    private int comparePreRelease(String a, String b) {
        String[] ia = a.split("\\.");
        String[] ib = b.split("\\.");
        int max = Math.max(ia.length, ib.length);
        for (int i = 0; i < max; i++) {
            if (i >= ia.length) return -1; // a ran out first -> fewer pre-release fields -> lower precedence
            if (i >= ib.length) return 1;
            int c = compareIdentifier(ia[i], ib[i]);
            if (c != 0) return c;
        }
        return 0;
    }

    private int compareIdentifier(String x, String y) {
        boolean xNum = isNumeric(x);
        boolean yNum = isNumeric(y);
        if (xNum && yNum) {
            return new BigInteger(x).compareTo(new BigInteger(y));
        }
        if (xNum) return -1;   // numeric identifiers have lower precedence than non-numeric
        if (yNum) return 1;
        return x.compareTo(y);
    }

    private boolean isNumeric(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) return false;
        }
        return true;
    }
}
