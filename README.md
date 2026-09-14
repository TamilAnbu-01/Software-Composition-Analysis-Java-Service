# SCA Scanner

A Java backend service that takes a list of a project's dependencies, correlates them against
the [GitHub Advisory Database](https://github.com/advisories) using version-matching and
deduplication logic implemented from scratch, and recommends the minimal upgrade that resolves
the most known vulnerabilities.

This is not a wrapper around an existing SCA tool (OWASP Dependency-Check, Snyk, Trivy, ...) -
the only thing pulled from outside is raw vulnerability *data*. Package-identity matching,
affected-version range evaluation, deduplication, and the remediation algorithm are all
implemented in this repository.

## Quick start

```bash
mvn spring-boot:run
```

```bash
curl -X POST localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
        "project": "payment-service",
        "dependencies": [
          {"ecosystem": "maven", "group": "org.apache.logging.log4j", "name": "log4j-core", "version": "2.14.1"}
        ]
      }'
```

That request, run against the live GitHub Advisory Database, returns the real Log4Shell chain
(CVE-2021-44228, CVE-2021-45046, CVE-2021-45105, ...) and recommends `2.25.4` - the smallest
version that clears every one of them as of the advisories currently on record. See "How this
was tested" below for the actual output of that call.

`GET /api/v1/scans/{scanId}` retrieves a previous scan. `GET /api/v1/health` is a liveness check.

## Architecture

```
DependencyInput (raw JSON)
      │
      ▼
DependencyNormalizer  ──►  NormalizedDependency (canonical package key + version)
      │
      ▼
VulnerabilitySource (GitHubAdvisorySource)  ──►  List<VulnerabilityRecord>
      │
      ▼
CorrelationEngine  ──►  List<Finding>   (installed version actually falls in an affected range)
      │
      ▼
Deduplicator       ──►  List<Finding>   (same vulnerability reported under >1 identifier, merged)
      │
      ▼
RemediationEngine  ──►  RemediationPlan (smallest version resolving the most findings)
```

`ScanService` is the only class that wires these together, and it - along with everything
above it in the diagram - **imports nothing from Spring**. The web framework is a thin adapter
(`api/ScanController`) on top of a plain Java pipeline. Two reasons for that split:

1. It's directly testable. All 45 of the tests described below run against plain objects with
   no web server, no application context, and (except for the one live smoke-test call
   described below) no network.
2. It makes the "swap the data source" and "add an ecosystem" extension points real rather than
   theoretical - `VulnerabilitySource` and `VersionComparator` are interfaces the core code
   depends on, not concrete GitHub/Maven-specific classes.

### Package layout

| Package | Responsibility |
|---|---|
| `model` | Immutable domain records - no logic, no framework annotations |
| `version` | `VersionComparator` interface + Maven and SemVer implementations |
| `normalize` | Turns raw input into a `NormalizedDependency`, or rejects it clearly |
| `intel` | `VulnerabilitySource` interface + the GitHub Advisory Database client |
| `correlate` | Range parsing + installed-version-vs-range evaluation |
| `dedup` | Merges findings that are the same vulnerability under different identifiers |
| `remediate` | The minimal-safe-upgrade algorithm, and a bonus cross-dependency ranker |
| `service` | Orchestration (`ScanService`) + in-memory result store (`ScanStore`) |
| `api` | Spring REST controller + a global exception handler |
| `config` | Wires the framework-free core as Spring beans |

## Data model

Everything is an immutable Java `record`. A few decisions worth calling out:

- **`NormalizedDependency.packageKey`** is ecosystem-shaped, not a raw string pair: Maven gets
  `group:artifact` (matching how the GitHub Advisory Database itself names Maven packages),
  npm/Go get `scope/name`, PyPI is flat. This is the one place ecosystem-specific coordinate
  assembly happens - everything downstream just sees a `packageKey` string.
- **`VersionRange`** models three independent bounds (`introducedInclusive`,
  `fixedExclusive`, `lastAffectedInclusive`) rather than a single "affected version string",
  because real advisory data needs all three: most ranges have a clean fix version, some only
  know the last bad version, and a still-unpatched 0-day has no upper bound at all.
- **`VulnerabilityRecord.aliases`** exists specifically so the deduplicator has something to
  union over - a GHSA id and its cross-referenced CVE id are both first-class identifiers, not
  "one canonical id plus a display string".
- **`ScanError`** (not an exception) is how a per-dependency failure is represented in a
  response. A malformed request throws (see the API section); a *particular dependency* being
  unparseable, or a *particular package* failing to look up, does not - see "Error handling".

## Normalization (`DependencyNormalizer`)

Validates ecosystem, name, version, and group (required for Maven, optional/ignored elsewhere),
then builds the canonical `packageKey`. Rejects rather than guesses: an unrecognized ecosystem
string becomes a `ScanError`, not a silent `UNKNOWN` that quietly matches nothing further down
the pipeline.

## Version comparison

This is the part the assignment weights highest, and the part most SCA tools get subtly wrong
by treating versions as strings. `1.9` must be less than `1.10` even though it isn't lexically.

**`MavenVersionComparator`** (written from scratch, no `maven-artifact` dependency) tokenizes a
version into an alternating sequence of numeric and qualifier tokens - `.`, `-`, `_`, `+` are
all treated as separators, and a digit-run/letter-run boundary is itself a separator, so
`2.15.0-beta1` becomes `[2, 15, 0, beta, 1]`. Comparison rules:

- Numbers compare numerically (`BigInteger`, so no overflow, and no `"1.10" < "1.9"` bug).
- Qualifiers compare by release-cycle rank: `alpha < beta < milestone < rc < snapshot <
  (final/ga/release) < sp`. An unrecognized qualifier ranks just above "final" (like a vendor
  patch suffix) and falls back to case-insensitive string comparison against another
  unrecognized qualifier at the same rank, so the ordering stays total even where it isn't
  meaningful.
- A number always outranks a qualifier at the same position (Maven's own rule -
  `"1.0.5" > "1.0-beta"`).
- If one version runs out of tokens first, the *other* side's next token decides: an implicit
  numeric `0` if it's a number (`"1.0" == "1.0.0"`), or an implicit "final release" if it's a
  qualifier - meaning `"1.0" > "1.0-beta"` but `"1.0" < "1.0-sp1"`, and `"1.0.0.RELEASE" ==
  "1.0.0"`.

**Known limitation:** this does not reproduce every corner of Maven's real `ComparableVersion`
algorithm (in particular its exact list-nesting rules when `.` and `-` are mixed). It's correct
for the overwhelming majority of real-world versions and for every example in the assignment
brief - see `MavenVersionComparatorTest` for the 11 cases it's checked against, including the
full log4j chain (`2.14.1 < 2.15.0 < 2.16.0 < 2.17.0`) and qualifier ordering.

**`SemverLikeComparator`** (bonus) implements SemVer 2.0.0 precedence for npm, and is reused
as an approximation for PyPI - PEP 440's epoch/`.postN`/`.devN` segments aren't modeled, which
is called out as a limitation rather than silently mishandled.

Adding a third ecosystem is: implement `VersionComparator`, register it in
`VersionComparators`, teach `DependencyNormalizer` its package-key shape, and add
`Ecosystem.githubEcosystemName()`'s mapping if it should also pull from GitHub Advisories.
Nothing else changes.

## Correlation (`CorrelationEngine` + `RangeParser`)

`RangeParser` turns a constraint string like `">= 2.21.0, < 2.25.4"` into a `VersionRange`.
Constraints within one string AND together (they describe a single interval); a package with
several *disjoint* vulnerable intervals (log4j's `2.x` line and `3.0.0-beta` line under the
same advisory is a real example, captured live below) gets one `VersionRange` per interval,
OR'd together at the `VulnerabilityRecord` level. Unrecognized operator text is skipped rather
than failing the advisory - see "Error handling".

`CorrelationEngine` then checks, per candidate vulnerability, whether the installed version
falls in *any* of its ranges, using the ecosystem's real comparator (never lexical comparison).
Verified against the assignment's own log4j-core `2.14.1` example (finds both the CRITICAL and
HIGH CVE), plus boundary cases: installed exactly at a fix version is not vulnerable
(`fixedExclusive` is exclusive), installed exactly at a `lastAffectedInclusive` boundary is
still vulnerable (inclusive), and an open-ended range with no upper bound at all is treated as
vulnerable from its lower bound onward - what an unpatched 0-day actually looks like.

## Deduplication (`Deduplicator`)

The GitHub Advisory Database already gives a GHSA id and its CVE id together on one advisory,
so a single query naturally produces records with more than one identifier. The deduplicator
generalizes this with union-find over identifier sets: any two records sharing *any* id (in
`id` or `aliases`) are the same vulnerability, transitively - `A` and `C` merge even if they
only share an id through `B`, not directly with each other.

Merging keeps the **higher** severity of the two (a source under-reporting severity shouldn't
suppress a real risk), the union of both records' ranges, and prefers a CVE id as the
display id when one is present in the merged group. Verified with exact-duplicate records,
cross-referenced-alias records, and a check that genuinely unrelated CVEs are *not* merged.

## Remediation (`RemediationEngine`)

The algorithm, and why it's correct:

> For a fixed set of findings, "number of findings resolved by upgrading to version *V*" is
> monotonically non-decreasing as *V* increases - a finding is resolved by any version at or
> above its own known fix version, and "at or above" only gets easier to satisfy as *V* grows.
> That means the **maximum** achievable resolution count is always reached by the *largest*
> known fix version among the findings. The only open question is the assignment's actual ask -
> the **minimum** version that still reaches that maximum - so: score every distinct known fix
> version by how many findings it resolves, take the global maximum, and recommend the smallest
> candidate that reaches it.

Findings with no known fixed version (an advisory with no patch yet) can never be resolved by
any recommendation and always land in `remaining`, regardless of which candidate is chosen.

Verified against the assignment's own worked example - CRITICAL fixed in `2.15.0`, HIGH in
`2.16.0`, MEDIUM+LOW in `2.17.0`, recommends `2.17.0`, resolves 4/4 - plus a case
specifically checking that a *smaller* version is preferred when it already reaches the same
maximum as a larger one, and a case with an unfixable finding staying in `remaining` no matter
what's recommended.

**Bonus - `RemediationPriorityRanker`:** given remediation plans for several dependencies,
ranks them by a severity-weighted resolved-finding score (CRITICAL counts 10x, HIGH 5x, MEDIUM
2x, LOW/UNKNOWN 1x), so "fixes 2 CRITICALs" outranks "fixes 5 LOWs" in a prioritized backlog -
matching how a security team actually triages upgrades.

## Vulnerability data source

`GitHubAdvisorySource` queries `GET api.github.com/advisories?ecosystem=...&affects=...` with
`java.net.http.HttpClient` - no HTTP client framework dependency. It deliberately does **not**
use a version-aware query: it fetches every advisory GitHub has recorded for the package,
unfiltered by version, and hands all of it to `CorrelationEngine`. Asking the source to also
decide "is this version affected" would just be delegating the part of the assignment that
matters back to a third party.

Unauthenticated requests are capped at 60/hour per IP by GitHub. Setting a `GITHUB_TOKEN`
environment variable (no scopes needed - advisory data is public) raises that to 5,000/hour.
A 403/429 from GitHub is surfaced as a clear per-dependency error naming this, rather than a
generic failure.

`VulnerabilitySource` is an interface specifically so a second or third source (OSV, a
downloaded NVD mirror, a private feed) could be added and fanned out to, with the existing
`Deduplicator` already positioned to merge their overlapping results - see "Known limitations"
for why that isn't done in this submission.

## API

| Method | Path | |
|---|---|---|
| `POST` | `/api/v1/scans` | Body: `{"project": "...", "dependencies": [{"ecosystem","group","name","version"}]}`. Returns `201` with the full `ScanResult` (see below), **even if some dependencies had errors** - see "Error handling". |
| `GET` | `/api/v1/scans/{scanId}` | Retrieves a previous result (in-memory store), or `404`. |
| `GET` | `/api/v1/health` | Liveness check. |

`ScanResult` shape:
```json
{
  "scanId": "…",
  "project": "payment-service",
  "scannedAt": "2026-09-13T...Z",
  "findings": [ { "dependency": {...}, "vulnerability": {...}, "fixedVersion": "2.15.0" } ],
  "remediations": [ { "dependency": {...}, "currentVersion": "2.14.1", "recommendedVersion": "2.17.0",
                       "findingsBefore": 4, "findingsAfter": 0, "resolved": 4, "remaining": 0,
                       "severityResolved": {...}, "severityRemaining": {...} } ],
  "errors": [ { "dependency": "bad-lib@1.0", "reason": "unrecognized ecosystem 'cargo'" } ]
}
```

## Error handling

| Situation | Behavior |
|---|---|
| Malformed request JSON, or missing/blank `project` | `400`, via `GlobalExceptionHandler` |
| One dependency entry missing a name/version/required group | That entry -> `ScanError`; rest of the scan still runs |
| Unrecognized ecosystem on one entry | Same - `ScanError`, not a crash or a silent `UNKNOWN` |
| Vulnerability source unreachable / rate-limited for one package | `ScanError` naming the cause (incl. the `GITHUB_TOKEN` hint on rate limit); other dependencies in the same request are unaffected |
| Unparseable advisory range syntax | That one range is skipped (open-range fallback favors over-reporting a finding over silently dropping it); the rest of the advisory and the rest of the scan proceed |
| Empty dependency list | Valid, clean `200`/`201` result with empty arrays |
| Any other unexpected exception | `500`, generic message, no stack trace leaked to the client |

The guiding principle: a request-level problem (bad JSON) is a client error worth failing
loudly on; a single-dependency-level problem should never take an entire batch scan down.

## How this was tested

45 JUnit 5 tests across the framework-free core, all passing, run in this development
environment with the real JUnit 5 platform (not just hand-rolled assertions):

| Class | Tests | Covers |
|---|---|---|
| `MavenVersionComparatorTest` | 11 | Numeric ordering, all qualifier ranks, missing-segment padding, the brief's own examples |
| `CorrelationEngineTest` | 7 | The brief's log4j example, range boundary conditions, multi-range records |
| `DeduplicatorTest` | 5 | Exact duplicates, cross-referenced aliases, severity conservatism, non-merging of unrelated CVEs |
| `RemediationEngineTest` | 7 | The brief's worked example, minimal-vs-maximal candidate selection, unfixable findings |
| `DependencyNormalizerTest` | 9 | Per-ecosystem key building, required-field validation |
| `ScanServiceTest` | 6 | End-to-end orchestration against a fake source; error isolation for bad input and source failures |

Beyond unit tests, the full pipeline (normalize -> real `GitHubAdvisorySource` call -> correlate
-> dedup -> remediate) was run once against the **live** GitHub Advisory Database for
`org.apache.logging.log4j:log4j-core@2.14.1`. It correctly identified the real Log4Shell chain
and recommended the version that clears all of it:

```
Findings for 2.14.1: 7
  - GHSA-jfh8-c2jp-5v3q  aliases=[CVE-2021-44228]  CRITICAL  nearestFix=2.15.0
  - GHSA-7rjr-3q55-vv33  aliases=[CVE-2021-45046]  CRITICAL  nearestFix=2.16.0
  - GHSA-p6xc-xr62-6r2g  aliases=[CVE-2021-45105]  HIGH      nearestFix=2.17.0
  - GHSA-8489-44mv-ggj8  aliases=[CVE-2021-44832]  MEDIUM    nearestFix=2.17.1
  ...
Recommended upgrade: 2.25.4   (resolves 7/7)
```

**One test file, `ScanControllerTest`, was not run.** It needs `spring-test` + Mockito
(pulled in via `spring-boot-starter-test`), and this project was built in a sandboxed
environment without access to Maven Central, so those jars couldn't be fetched. Everything
else - all 45 tests above, plus the live smoke test - ran against real JUnit 5 and a real HTTP
call, installed via the OS package manager and Java's built-in `HttpClient`, specifically so
the important logic wasn't just eyeballed. `ScanControllerTest` follows the standard
MockMvc-standalone + Mockito pattern; run `mvn test` after cloning to confirm it.

## Known limitations / what a v2 would add

- **Single vulnerability source.** Only the GitHub Advisory Database is queried.
  `VulnerabilitySource` is an interface specifically so OSV or a downloaded NVD feed could be
  added as a second implementation, fanned out to alongside GitHub, with `Deduplicator`
  already able to merge their overlapping results - just not wired up in this submission.
- **No transitive dependency resolution.** The input is a flat list; a real project's build
  produces a dependency *tree*, and a vulnerable transitive dependency needs a path back to
  the direct dependency that pulled it in for the remediation advice to be actionable. Adding
  this means accepting a tree (or a build-tool-specific format like a Maven `dependency:tree`
  output) instead of a flat list, and carrying a path alongside each `Finding`.
- **PyPI version handling is an approximation.** PEP 440 (`epoch!`, `.postN`, `.devN`) isn't
  fully modeled by `SemverLikeComparator` - see the version-comparison section above.
- **In-memory result store.** `ScanStore` doesn't survive a restart or scale across instances -
  swapping it for a real database is isolated to that one class.
- **GitHub's unauthenticated rate limit (60/hour)** makes this unsuitable for scanning large
  dependency trees without a `GITHUB_TOKEN`. Even with one, one HTTP call per unique package is
  made with no caching between scans of the same project - an obvious next optimization.

## Scaling this to many dependencies / repositories

- **Cache advisory lookups.** Advisories change infrequently; caching `packageKey ->
  List<VulnerabilityRecord>` (with a TTL, or invalidated by GitHub's `updated_at` field) would
  cut redundant calls to near zero for repeated scans of similar dependency sets, and is the
  single highest-leverage change for both latency and staying under GitHub's rate limit.
- **Fan out per-dependency lookups concurrently** (e.g. via `CompletableFuture`/a bounded
  executor) instead of the current sequential loop in `ScanService` - each dependency's fetch
  is independent, so wall-clock time for a large manifest is currently the sum of every HTTP
  call rather than the slowest one.
- **Move `ScanStore` to a real database** once results need to survive a restart or be shared
  across instances; the interface (`save`/`get`) doesn't need to change.
- **Pull a full advisory dataset locally on a schedule** (GitHub, OSV, and NVD all publish bulk
  exports) instead of querying per-package-per-scan, once request volume makes that cheaper
  than live API calls - this is the same normalize/correlate/dedup/remediate pipeline either
  way, only `VulnerabilitySource`'s implementation would change.

## Requirements

Java 21, Maven 3.8+. `mvn spring-boot:run` to start on `:8080`, `mvn test` to run the suite.
