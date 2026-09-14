SCA Scanner
A Java backend service that takes a list of a project's dependencies, correlates them against the GitHub Advisory Database using custom version-matching, correlation, deduplication, and remediation logic, and recommends the minimum upgrade that resolves the maximum number of known vulnerabilities.
This is not a wrapper around an existing SCA tool such as OWASP Dependency-Check, Snyk, or Trivy. The application uses an external source only for raw vulnerability intelligence. Package identity matching, affected-version evaluation, deduplication, and remediation are implemented in this repository.
Quick Start
Requirements
- Java 21
- Maven 3.8+
- Internet access for the GitHub Advisory Database
- Optional: GITHUB_TOKEN environment variable for a higher GitHub API rate limit
Run the application
mvn spring-boot:run
The service starts on:
http://localhost:8080
Run tests
mvn test
Current test result:
Tests run: 51
Failures: 0
Errors: 0
Skipped: 0

BUILD SUCCESS
Example Scan
The primary endpoint is:
POST /scan
Example request:
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{
    "project": "payment-service",
    "dependencies": [
      {
        "ecosystem": "maven",
        "group": "org.apache.logging.log4j",
        "name": "log4j-core",
        "version": "2.14.1"
      }
    ]
  }'
The request is evaluated through the complete pipeline:
normalize
    ->
fetch vulnerability data
    ->
correlate affected versions
    ->
deduplicate findings
    ->
calculate remediation
A live test against the GitHub Advisory Database using org.apache.logging.log4j:log4j-core@2.14.1 produced 7 findings and recommended version 2.25.4, resolving all 7 findings.
Architecture
DependencyInput (raw JSON)
        |
        v
DependencyNormalizer
        |
        v
NormalizedDependency
(canonical package key + version)
        |
        v
VulnerabilitySource
(GitHubAdvisorySource)
        |
        v
List<VulnerabilityRecord>
        |
        v
CorrelationEngine
(installed version vs affected ranges)
        |
        v
List<Finding>
        |
        v
Deduplicator
(merge duplicate/aliased vulnerabilities)
        |
        v
List<Finding>
        |
        v
RemediationEngine
(minimum version resolving maximum findings)
        |
        v
RemediationPlan
ScanService orchestrates the pipeline.
The core scanning logic is intentionally separated from Spring. The web layer is a thin REST adapter over the framework-free scanning pipeline.
This provides two benefits:
1. The core logic can be unit tested without starting a web server or Spring application context.
2. Vulnerability sources and version comparators can be replaced or extended through interfaces.
Package Layout
Package	Responsibility
model	Immutable domain records
version	VersionComparator interface and ecosystem-specific comparators
normalize	Converts raw dependency input into canonical dependencies
intel	Vulnerability source interface and GitHub Advisory Database client
correlate	Vulnerability range parsing and affected-version evaluation
dedup	Merges duplicate vulnerabilities and cross-referenced aliases
remediate	Minimum-safe-upgrade algorithm
service	Scan orchestration and in-memory scan storage
api	REST controller and global exception handling
config	Spring bean configuration


Data Model
The application uses immutable Java records for its main domain objects.
NormalizedDependency
Represents a validated dependency after normalization.
Important fields:
ecosystem
packageKey
version
The packageKey is ecosystem-specific.
For Maven:
group:artifact
For example:
org.apache.logging.log4j:log4j-core
For npm, Go, and PyPI the package key is normalized according to the ecosystem-specific input shape.
The ecosystem-specific package identity is created once by DependencyNormalizer and reused throughout the rest of the pipeline.
VulnerabilityRecord
Represents vulnerability intelligence independently of the external source format.
It contains:
id
aliases
summary
severity
ecosystem
packageKey
ranges
source
The aliases field allows identifiers such as:
GHSA-jfh8-c2jp-5v3q
CVE-2021-44228
to represent the same underlying vulnerability.
VersionRange
Represents an affected version interval using:
introducedInclusive
fixedExclusive
lastAffectedInclusive
This supports:
- vulnerabilities with a known fixed version
- vulnerabilities where only the last affected version is known
- vulnerabilities with no known upper bound
Finding
A finding connects:
NormalizedDependency
+
VulnerabilityRecord
+
nearest known fixed version

RemediationPlan
A remediation plan records:
- current dependency version
- recommended version
- findings before remediation
- findings after remediation
- number of findings resolved
- findings remaining
- severity breakdown
Normalization
DependencyNormalizer is responsible for converting raw API input into a canonical dependency representation.
It validates:
- ecosystem
- package name
- version
- Maven group ID
- supported version comparator
Invalid data is rejected rather than guessed.
For example, a Maven dependency without a group ID produces an error instead of silently creating an invalid package identity.
Unknown ecosystems are also rejected.
This prevents malformed or ambiguous package identifiers from entering the correlation stage.
Version Comparison
Version comparison is one of the most important parts of an SCA scanner.
Versions must not be compared as ordinary strings.
For example:
2.10.0 > 2.9.0
even though lexical string comparison would produce the wrong ordering.
Maven Version Comparator
MavenVersionComparator is implemented from scratch without using Maven's ComparableVersion implementation or the maven-artifact dependency.
Numeric segments are compared numerically using BigInteger.
Examples:
1.9 < 1.10
2.14.1 < 2.15.0
2.15.0 == 2.15.0
2.16.0 > 2.15.0
2.10.0 > 2.9.0
The implementation also handles Maven-style qualifiers.
The release ordering used by the implementation is:
alpha < beta < milestone < rc < snapshot < final / ga / release < sp
It also handles:
1.0 == 1.0.0
1.0.0 == 1.0.0.0
1.0.0.RELEASE == 1.0.0
1.0.0-GA == 1.0.0
and mixed versions such as:
1.0.0-alpha
1.0.0-beta
1.0.0-rc1
Known Limitation
The implementation does not reproduce every corner case of Maven's actual ComparableVersion algorithm, particularly the exact list-nesting behavior for mixed . and - separators.
It is designed to correctly handle the version patterns relevant to this assessment and the majority of normal Maven dependency versions.
SemVer-like Comparator
SemverLikeComparator implements SemVer-style precedence and is used for npm.
It is also reused as an approximation for PyPI.
PyPI's full PEP 440 behavior is not completely modeled. In particular, features such as:
epoch
.postN
.devN
are outside the current implementation.
This is documented as a limitation rather than silently treating those versions as fully SemVer-compatible.
Correlation
CorrelationEngine determines whether a vulnerability actually applies to the installed dependency version.
The process is:
Package identity
      ->
Affected version range
      ->
Vulnerable / not vulnerable
The vulnerability source first identifies advisories associated with the package.
CorrelationEngine then performs the version-aware decision itself.
For each vulnerability, it evaluates all of its ranges.
Introduced Version
If:
installed < introduced
the vulnerability does not apply.
Fixed Version
fixedExclusive is treated as exclusive.
For example:
introducedInclusive = 2.13.0
fixedExclusive      = 2.15.0
means:
2.14.1 -> vulnerable
2.15.0 -> not vulnerable
Last Affected Version
lastAffectedInclusive is inclusive.
Therefore:
lastAffectedInclusive = 2.14.1

means:
2.14.1 -> vulnerable
2.14.2 -> not vulnerable

Open-ended Vulnerabilities
If there is no upper bound, the dependency is considered vulnerable from the introduction version onward, because the source has not provided a known fix.
Multiple Vulnerabilities
A dependency may have several vulnerabilities.
For example:
log4j-core 2.14.1

can have multiple advisories with different fixed versions.
Each applicable vulnerability becomes a separate Finding.
The remediation engine then considers the complete set of findings for that dependency.
Deduplication
The same underlying vulnerability may appear under multiple identifiers or from multiple sources.
For example:
GHSA-jfh8-c2jp-5v3q
CVE-2021-44228

may refer to the same vulnerability.
Deduplicator uses vulnerability identifiers and aliases to merge equivalent findings.
The implementation supports:
- exact duplicate IDs
- cross-referenced aliases
- transitive identifier relationships
- severity preservation
- range union
- CVE preference for the display identifier
When vulnerabilities are merged, the higher severity is retained.
Unrelated vulnerabilities are not merged.
Remediation
RemediationEngine determines the smallest candidate version that achieves the maximum possible number of resolved findings.
It does not simply recommend the latest version.
For each finding with a known fixed version, candidate versions are evaluated based on how many findings they resolve.
The algorithm:
1. Collect distinct known fixed versions.
2. Evaluate each candidate against all findings.
3. Count how many findings each candidate resolves.
4. Find the maximum achievable resolution count.
5. Among candidates reaching that maximum, choose the smallest version.

This satisfies the requirement to minimize the recommended upgrade while still resolving the maximum number of known vulnerabilities.
Example
Suppose a dependency has:
Vulnerability A -> fixed in 1.0
Vulnerability B -> fixed in 1.1
Vulnerability C -> fixed in 1.5

The recommended version is:
1.5

because it is the smallest candidate that resolves all three findings.
If no single candidate resolves every vulnerability, the engine performs partial remediation and reports the unresolved findings.
A finding with no known fixed version can never be resolved by a version recommendation and remains in the remaining set.
Vulnerability Data Source
The application currently uses the public GitHub Advisory Database.
GitHubAdvisorySource queries the GitHub Advisory API for the dependency ecosystem and package.
The application deliberately does not ask the external service to decide whether the installed version is vulnerable.
Instead:
GitHub
  ->
raw advisory information
  ->
our VulnerabilityRecord model
  ->
our CorrelationEngine

This keeps affected-version evaluation inside the application.
The VulnerabilitySource interface also makes it possible to add additional sources later, such as:
- OSV
- NVD
- private security feeds
- local advisory databases
The existing deduplication layer can then merge overlapping vulnerability records from different sources.
GitHub API Rate Limits
Unauthenticated GitHub API requests have a limited rate allowance.
A GITHUB_TOKEN environment variable can be supplied to increase the available GitHub API limit.
Example on Windows PowerShell:
$env:GITHUB_TOKEN="your-token"

Example on Linux/macOS:
export GITHUB_TOKEN="your-token"

The token is only used to authenticate requests to GitHub.
If GitHub returns a rate-limit response, the application records a clear per-dependency error rather than crashing the entire scan.
API
1. Scan Dependencies
POST /scan

Request
{
  "project": "payment-service",
  "dependencies": [
    {
      "ecosystem": "maven",
      "group": "org.apache.logging.log4j",
      "name": "log4j-core",
      "version": "2.14.1"
    }
  ]
}

Response
Returns:
201 Created

Example shape:
{
  "scanId": "6a5c4fed-2aa1-4826-9d15-3d0f7f69ce69",
  "project": "payment-service",
  "scannedAt": "2026-09-14T...",
  "findings": [
    {
      "dependency": {},
      "vulnerability": {},
      "fixedVersion": "2.15.0"
    }
  ],
  "remediations": [
    {
      "dependency": {},
      "currentVersion": "2.14.1",
      "recommendedVersion": "2.25.4",
      "findingsBefore": 7,
      "findingsAfter": 0,
      "resolved": 7,
      "remaining": 0,
      "severityResolved": {},
      "severityRemaining": {}
    }
  ],
  "errors": []
}
A scan can still return 201 Created when individual dependencies fail.
Those dependency-specific failures are reported in errors[] while the remaining dependencies continue to be scanned.
2. Get Vulnerability
GET /vulnerabilities/{id}
Returns vulnerability information previously loaded into the local in-memory vulnerability store during a scan.
Example:
GET /vulnerabilities/CVE-2021-44228
A successful response contains the vulnerability's:
- ID
- aliases
- summary
- severity
- ecosystem
- package key
- affected ranges
- source
Both the primary vulnerability ID and its aliases can be used for lookup.
For example, a record with:
id = GHSA-jfh8-c2jp-5v3q
alias = CVE-2021-44228
can be retrieved using either identifier.
If the vulnerability is not known to the current application instance:
404 Not Found
3. Get Scan Result — Bonus
GET /scans/{scanId}
Retrieves a previously created scan result.
Example:
GET /scans/6a5c4fed-2aa1-4826-9d15-3d0f7f69ce69
Returns 200 OK when the scan exists.
Otherwise:
404 Not Found
The current implementation uses an in-memory ScanStore, so scan results are available only while the application instance is running.
4. Health Check
GET /health
Returns:
{
  "status": "UP"
}
Error Handling
The application distinguishes between request-level errors and dependency-level errors.
Situation	Behavior
Malformed JSON	400 Bad Request
Missing/invalid request fields	400 Bad Request
Missing dependency name	Dependency becomes a ScanError
Missing dependency version	Dependency becomes a ScanError
Missing Maven group	Dependency becomes a ScanError
Unknown ecosystem	Dependency becomes a ScanError
Vulnerability source unavailable	Dependency becomes a ScanError
GitHub API rate limited	Dependency becomes a ScanError
Unknown vulnerability ID	404 Not Found
Unknown scan ID	404 Not Found
Empty dependency list	Valid clean scan
Unexpected server exception	500 Internal Server Error


The guiding principle is:
Request-level problems -> reject the request clearly

Dependency-level problems -> isolate the failure and continue scanning
This prevents one malformed dependency or unavailable package lookup from destroying an entire batch scan.
Testing
The project currently contains 51 automated tests.
Latest result:
Tests run: 51
Failures: 0
Errors: 0
Skipped: 0

BUILD SUCCESS
Test Coverage
Test Class	Tests	Coverage
ScanControllerTest	6	REST endpoints, status codes, response shapes
CorrelationEngineTest	7	Version ranges, boundaries, multiple ranges
DeduplicatorTest	5	Duplicate IDs, aliases, severity, unrelated CVEs
DependencyNormalizerTest	9	Package identity and validation
RemediationEngineTest	7	Minimum safe version and partial remediation
ScanServiceTest	6	Pipeline orchestration and error isolation
MavenVersionComparatorTest	11	Numeric ordering and qualifier handling
Total	51	All passing


Important Version Tests
The test suite explicitly checks the assessment examples:
2.14.1 < 2.15.0
2.15.0 == 2.15.0
2.16.0 > 2.15.0
2.10.0 > 2.9.0
It also tests:
1.0 == 1.0.0
1.0.0 == 1.0.0.RELEASE
1.0.0 == 1.0.0-GA
alpha < beta < milestone < rc < final
SNAPSHOT < final
final < SP
Live API Verification
The complete pipeline was also exercised against the live GitHub Advisory Database.
Dependency:
org.apache.logging.log4j:log4j-core@2.14.1
Observed result:
Findings: 7
Recommended upgrade: 2.25.4
Resolved: 7/7
Remaining: 0
Errors: 0
Representative findings included:
GHSA-jfh8-c2jp-5v3q
CVE-2021-44228
CRITICAL
nearestFix = 2.15.0
GHSA-7rjr-3q55-vv33
CVE-2021-45046
CRITICAL
nearestFix = 2.16.0
GHSA-p6xc-xr62-6r2g
CVE-2021-45105
HIGH
nearestFix = 2.17.0
The remediation engine ultimately recommended:
2.25.4
which resolved all 7 findings observed during the live test.
Security Considerations
This project is an assessment implementation rather than a production-ready security platform.
Important security considerations include:
- Vulnerability data comes from an external service and should be treated as untrusted input.
- Advisory parsing is separated from correlation logic.
- Request validation prevents missing package identity information from silently entering the scanner.
- The GitHub token is read from an environment variable rather than being hard-coded.
- Internal exception details are not returned directly to API clients.
- The application does not execute dependency code.
- Vulnerability data is not blindly trusted to determine whether an installed version is vulnerable; affected-version evaluation is performed by the application's own correlation logic.
Known Limitations
Single Vulnerability Source
Only the GitHub Advisory Database is currently connected.
The VulnerabilitySource abstraction allows additional sources to be added later.
No Transitive Dependency Resolution
The API accepts a flat dependency list.
It does not currently resolve a Maven/npm/etc. dependency tree.
A production implementation would need to preserve dependency paths so that a vulnerable transitive dependency can be traced back to the dependency that introduced it.
PyPI Version Handling
PyPI versions currently use the SemVer-like comparator as an approximation.
PEP 440 features such as:
epoch
.postN
.devN

are not fully modeled.
In-Memory Scan Store
ScanStore currently uses an in-memory map.
Therefore:
- results disappear when the application restarts
- results are not shared across multiple application instances
- it is not suitable for durable production storage
A database-backed implementation would be the natural next step.
GitHub API Rate Limits
Without authentication, GitHub API requests are rate limited.
A GITHUB_TOKEN can be supplied for a higher limit.
The current implementation also makes an HTTP request for each unique dependency package and does not persist an advisory cache between scans.
Scalability and Reliability
Several improvements would be appropriate for a production implementation.
Advisory Caching
Cache:
packageKey -> List<VulnerabilityRecord>
with an appropriate TTL.
This would reduce repeated calls for the same package and improve both latency and API-rate usage.
Concurrent Dependency Lookups
The current scan processes dependencies sequentially.
For a large dependency manifest, independent vulnerability lookups could be performed concurrently using a bounded executor or CompletableFuture.
This would reduce total wall-clock scan time.
Persistent Storage
Replace the in-memory ScanStore with a database once scan results need to survive restarts or be shared between service instances.
The storage responsibility is isolated behind the service layer, making this change localized.
Local Advisory Dataset
At higher request volumes, a periodically refreshed local vulnerability dataset could replace per-package live API calls.
The rest of the pipeline could remain unchanged:
normalize
    ->
correlate
    ->
dedup
    ->
remediate
Only the VulnerabilitySource implementation would change.
Extensibility
Adding another ecosystem requires:
1. Implementing a VersionComparator.
2. Registering it with VersionComparators.
3. Teaching DependencyNormalizer how to construct its package key.
4. Adding the ecosystem's GitHub Advisory mapping if GitHub advisory lookup is supported.
5. Adding tests for the ecosystem's version semantics.
The correlation, deduplication, remediation, and REST layers do not need to be rewritten.
Project Requirements
Java 21
Maven 3.8+
Spring Boot
JUnit 5
Start the application:
mvn spring-boot:run
Run the tests:
mvn test
Default server port:
8080
Assessment Coverage
The implementation addresses the main assessment areas:
- Java/Spring backend
- Dependency normalization
- Package identity matching
- Custom vulnerability correlation
- Non-lexical version comparison
- Multiple vulnerabilities per dependency
- Deduplication and aliases
- Minimum safe-version remediation
- Partial remediation
- Error isolation
- REST API
- Automated testing
- Bonus scan persistence endpoint
- Security reasoning
- Scalability and reliability considerations
The implementation intentionally focuses on correctness of package identity, version semantics, vulnerability correlation, deduplication, remediation, API behavior, and testability rather than attempting to reproduce a complete production SCA platform.