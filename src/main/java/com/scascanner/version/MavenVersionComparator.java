package com.scascanner.version;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Version comparison for the Maven ecosystem, written from scratch (no
 * org.apache.maven:maven-artifact / ComparableVersion dependency).
 *
 * A version is tokenized into an alternating sequence of numeric and qualifier tokens - "." "-"
 * "_" and "+" are all treated as equivalent separators, and a boundary between a digit run and
 * a letter run is itself a separator (so "2.15.0-beta1" and "3a" both split the way you'd expect:
 * [2, 15, 0, beta, 1] and [3, a]).
 *
 * Comparison rules, evaluated position by position:
 *  - number vs number:      compared numerically (BigInteger, so no overflow and no "1.9" &gt; "1.10"
 *                            lexical-string bug).
 *  - qualifier vs qualifier: compared by release-cycle rank: alpha &lt; beta &lt; milestone &lt; rc &lt;
 *                            snapshot &lt; (final/ga/release) &lt; sp. An unrecognized qualifier is
 *                            treated as ranking just above "final" (like a vendor patch suffix),
 *                            and two unrecognized qualifiers at the same rank fall back to a
 *                            case-insensitive string comparison so the ordering stays total and
 *                            deterministic even though it isn't meaningful.
 *  - number vs qualifier at the same position: the number wins (Maven's own rule - "1.0.5" &gt;
 *                            "1.0-beta").
 *  - one version runs out of tokens before the other: the shorter version is padded with an
 *    implicit "0" if the longer side's next token is numeric (so "1.0" == "1.0.0", "1.0" &lt;
 *    "1.0.1"), or with an implicit "final release" marker if the longer side's next token is a
 *    qualifier (so "1.0" &gt; "1.0-beta" but "1.0" &lt; "1.0-sp1", and "1.0.0.RELEASE" == "1.0.0").
 *
 * Known limitation: this does not reproduce every corner of Maven's actual ComparableVersion
 * algorithm (e.g. its exact list-nesting rules for mixed "." / "-" separators). It is correct
 * for the overwhelming majority of real-world Maven versions, including every case in the
 * assignment brief; see MavenVersionComparatorTest for the cases it's verified against.
 */
public class MavenVersionComparator implements VersionComparator {

    private static final Pattern ATOM = Pattern.compile("\\d+|[^\\d]+");

    @Override
    public int compare(String a, String b) {
        List<Token> ta = tokenize(a);
        List<Token> tb = tokenize(b);

        int max = Math.max(ta.size(), tb.size());
        for (int i = 0; i < max; i++) {
            Token x = i < ta.size() ? ta.get(i) : null;
            Token y = i < tb.size() ? tb.get(i) : null;

            if (x != null && y != null) {
                int c = compareToken(x, y);
                if (c != 0) return c;
                continue;
            }

            // One side has run out of tokens. The remaining token on the longer side decides
            // the outcome (or, for an explicit "final" marker, is equivalent and we move on -
            // this only matters for contrived versions like "1.0.0.RELEASE.RELEASE").
            Token longerSideToken = x != null ? x : y;
            boolean bIsLonger = (x == null);
            int trailing = trailingSignal(longerSideToken);
            if (trailing == 0) {
                continue;
            }
            return bIsLonger ? -trailing : trailing;
        }
        return 0;
    }

    private int compareToken(Token x, Token y) {
        if (x instanceof NumTok nx && y instanceof NumTok ny) {
            return nx.value.compareTo(ny.value);
        }
        if (x instanceof NumTok) {
            return 1; // number beats qualifier at the same position
        }
        if (y instanceof NumTok) {
            return -1;
        }
        QualTok qx = (QualTok) x;
        QualTok qy = (QualTok) y;
        if (qx.rank != qy.rank) {
            return Integer.compare(qx.rank, qy.rank);
        }
        if (qx.finalMarker && qy.finalMarker) {
            return 0;
        }
        if (qx.finalMarker != qy.finalMarker) {
            // same rank (5), one is a canonical final/ga/release/empty marker, the other an
            // unrecognized qualifier - unrecognized sorts above the canonical marker.
            return qx.finalMarker ? -1 : 1;
        }
        return qx.raw.compareToIgnoreCase(qy.raw);
    }

    /** For a token that has no counterpart on the other side: does its presence make this
     *  version greater than the shorter one (1), equivalent to it (0), or lesser (-1)? */
    private int trailingSignal(Token t) {
        if (t instanceof NumTok n) {
            return n.value.signum() == 0 ? 0 : 1;
        }
        QualTok q = (QualTok) t;
        if (q.rank < 5) return -1;      // alpha/beta/milestone/rc/snapshot: pre-release, so smaller
        if (q.rank == 5) return q.finalMarker ? 0 : 1;
        return 1;                        // sp (rank 6): post-release, so bigger
    }

    private static List<Token> tokenize(String version) {
        String v = version == null ? "" : version.trim();
        if (v.isEmpty()) {
            v = "0";
        }
        String[] chunks = v.split("[.\\-_+]");
        List<Token> tokens = new ArrayList<>();
        for (String chunk : chunks) {
            if (chunk.isEmpty()) continue;
            Matcher m = ATOM.matcher(chunk);
            while (m.find()) {
                String piece = m.group();
                if (isAllDigits(piece)) {
                    tokens.add(new NumTok(new BigInteger(piece)));
                } else {
                    tokens.add(QualTok.of(piece));
                }
            }
        }
        if (tokens.isEmpty()) {
            tokens.add(new NumTok(BigInteger.ZERO));
        }
        return tokens;
    }

    private static boolean isAllDigits(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) return false;
        }
        return !s.isEmpty();
    }

    private sealed interface Token permits NumTok, QualTok {}

    private record NumTok(BigInteger value) implements Token {}

    private static final class QualTok implements Token {
        final String raw;
        final int rank;
        final boolean finalMarker;

        private QualTok(String raw, int rank, boolean finalMarker) {
            this.raw = raw;
            this.rank = rank;
            this.finalMarker = finalMarker;
        }

        static QualTok of(String raw) {
            String norm = raw.toLowerCase(Locale.ROOT);
            int rank = switch (norm) {
                case "alpha", "a" -> 0;
                case "beta", "b" -> 1;
                case "milestone", "m" -> 2;
                case "rc", "cr" -> 3;
                case "snapshot" -> 4;
                case "", "ga", "final", "release" -> 5;
                case "sp" -> 6;
                default -> 5;
            };
            boolean finalMarker = switch (norm) {
                case "", "ga", "final", "release" -> true;
                default -> false;
            };
            return new QualTok(norm, rank, finalMarker);
        }
    }
}
