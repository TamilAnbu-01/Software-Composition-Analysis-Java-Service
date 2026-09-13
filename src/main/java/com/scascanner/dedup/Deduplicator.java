package com.scascanner.dedup;

import com.scascanner.model.Finding;
import com.scascanner.model.Severity;
import com.scascanner.model.VersionRange;
import com.scascanner.model.VulnerabilityRecord;
import com.scascanner.version.VersionComparator;
import com.scascanner.version.VersionComparators;

import java.util.*;

/**
 * Collapses findings that refer to the same underlying vulnerability into one.
 *
 * Two vulnerability records are the same vulnerability if their identifier sets (primary id
 * plus aliases) overlap at all - a CVE id and a GHSA id that cross-reference each other merge,
 * as do three literally-identical records. This is a union-find over identifiers: it also
 * correctly chains A-B-C together when A shares an id only with B and B shares a (different)
 * id only with C, even though A and C share nothing directly.
 *
 * Merging two records keeps the more conservative (higher) severity - taking the lower one
 * would mean a source that under-reports severity could quietly suppress a real risk - and
 * keeps the union of both their ranges so remediation still sees every known fixed version.
 * The surviving id prefers a CVE identifier when one is present in the group, since that's the
 * identifier most people recognize; otherwise the first id encountered is kept.
 *
 * Expects every {@link Finding} passed in to be for the same dependency (it's designed to be
 * called once per dependency's raw correlation results, before remediation) - that's what lets
 * it use one ecosystem's version comparator when deciding which of two known fix versions is
 * more conservative.
 */
public class Deduplicator {

    public List<Finding> deduplicate(List<Finding> findings) {
        if (findings.size() <= 1) {
            return new ArrayList<>(findings);
        }

        // Union-find over vulnerability identifiers.
        Map<String, String> parent = new HashMap<>();
        for (Finding f : findings) {
            for (String id : f.vulnerability().allIdentifiers()) {
                parent.putIfAbsent(id, id);
            }
        }
        for (Finding f : findings) {
            Iterator<String> ids = f.vulnerability().allIdentifiers().iterator();
            if (!ids.hasNext()) continue;
            String first = ids.next();
            while (ids.hasNext()) {
                union(parent, first, ids.next());
            }
        }

        Map<String, List<Finding>> groups = new LinkedHashMap<>();
        for (Finding f : findings) {
            String root = find(parent, f.vulnerability().id());
            groups.computeIfAbsent(root, k -> new ArrayList<>()).add(f);
        }

        List<Finding> result = new ArrayList<>();
        for (List<Finding> group : groups.values()) {
            result.add(mergeGroup(group));
        }
        return result;
    }

    private Finding mergeGroup(List<Finding> group) {
        if (group.size() == 1) {
            return group.get(0);
        }

        VersionComparator cmp = VersionComparators.forEcosystem(group.get(0).dependency().ecosystem());
        VulnerabilityRecord merged = group.get(0).vulnerability();
        String fixedVersion = group.get(0).fixedVersion();

        for (int i = 1; i < group.size(); i++) {
            VulnerabilityRecord other = group.get(i).vulnerability();

            Set<String> aliases = new LinkedHashSet<>(merged.aliases());
            aliases.addAll(other.allIdentifiers());
            aliases.remove(merged.id());

            String id = preferCveId(merged.id(), other.id());
            Severity severity = other.severity().atLeastAsSevereAs(merged.severity())
                    ? other.severity() : merged.severity();
            List<VersionRange> ranges = new ArrayList<>(merged.ranges());
            ranges.addAll(other.ranges());

            merged = new VulnerabilityRecord(id, aliases, merged.summary(), severity,
                    merged.ecosystem(), merged.packageKey(), ranges, merged.source() + "+" + other.source());

            String otherFix = group.get(i).fixedVersion();
            fixedVersion = pickMoreSpecificFix(cmp, fixedVersion, otherFix);
        }

        return new Finding(group.get(0).dependency(), merged, fixedVersion);
    }

    private String preferCveId(String a, String b) {
        if (a.startsWith("CVE-")) return a;
        if (b.startsWith("CVE-")) return b;
        return a;
    }

    /** Keep whichever fix version is known; if both sources name one, keep the smaller (more
     *  conservative - a merged finding shouldn't silently forget a lower fix another source
     *  knew about), using the ecosystem's real version ordering, never lexical comparison. */
    private String pickMoreSpecificFix(VersionComparator cmp, String a, String b) {
        if (a == null) return b;
        if (b == null) return a;
        return cmp.lessThanOrEqual(a, b) ? a : b;
    }

    private String find(Map<String, String> parent, String x) {
        String root = x;
        while (!parent.get(root).equals(root)) {
            root = parent.get(root);
        }
        while (!parent.get(x).equals(root)) {
            String next = parent.get(x);
            parent.put(x, root);
            x = next;
        }
        return root;
    }

    private void union(Map<String, String> parent, String a, String b) {
        String ra = find(parent, a);
        String rb = find(parent, b);
        if (!ra.equals(rb)) {
            parent.put(ra, rb);
        }
    }
}
