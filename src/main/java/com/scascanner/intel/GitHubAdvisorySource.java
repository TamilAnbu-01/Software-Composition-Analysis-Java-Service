package com.scascanner.intel;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.scascanner.correlate.RangeParser;
import com.scascanner.exception.VulnerabilitySourceException;
import com.scascanner.intel.dto.GhAdvisory;
import com.scascanner.intel.dto.GhVulnerability;
import com.scascanner.model.*;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Queries the public GitHub Advisory Database REST API (GET /advisories) for every known
 * vulnerability recorded against one package, and maps the response into this service's own
 * {@link VulnerabilityRecord} model.
 *
 * Deliberately does NOT use a version-aware query - it fetches every advisory GitHub has for
 * the package, unfiltered by version, and leaves affected-version evaluation entirely to
 * {@link com.scascanner.correlate.CorrelationEngine}. Asking the source itself to also decide
 * "is this version affected" would defeat the point of building that logic ourselves.
 *
 * Unauthenticated requests are capped at 60/hour per IP by GitHub. Setting a GITHUB_TOKEN
 * environment variable (no scopes needed - advisory data is public) raises that to 5,000/hour.
 * See README, "Known limitations".
 */
public class GitHubAdvisorySource implements VulnerabilitySource {

    private static final String API_BASE = "https://api.github.com/advisories";
    private static final int MAX_ATTEMPTS = 2;

    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final RangeParser rangeParser;
    private final String githubToken;

    public GitHubAdvisorySource() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build(),
                System.getenv("GITHUB_TOKEN"));
    }

    public GitHubAdvisorySource(HttpClient httpClient, String githubToken) {
        this.httpClient = httpClient;
        this.githubToken = githubToken;
        this.mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.rangeParser = new RangeParser();
    }

    @Override
    public String name() {
        return "GHSA";
    }

    @Override
    public List<VulnerabilityRecord> findVulnerabilities(NormalizedDependency dependency) {
        String url = API_BASE
                + "?ecosystem=" + urlEncode(dependency.ecosystem().githubEcosystemName())
                + "&affects=" + urlEncode(dependency.packageKey())
                + "&per_page=100";

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .timeout(Duration.ofSeconds(15))
                .GET();
        if (githubToken != null && !githubToken.isBlank()) {
            requestBuilder.header("Authorization", "Bearer " + githubToken);
        }

        HttpResponse<String> response = sendWithRetry(requestBuilder.build(), dependency.packageKey());
        checkStatus(response, dependency.packageKey());

        List<GhAdvisory> advisories = parseBody(response.body(), dependency.packageKey());

        List<VulnerabilityRecord> records = new ArrayList<>();
        for (GhAdvisory advisory : advisories) {
            VulnerabilityRecord record = toRecord(advisory, dependency);
            if (record != null) {
                records.add(record);
            }
        }
        return records;
    }

    private void checkStatus(HttpResponse<String> response, String packageKey) {
        if (response.statusCode() == 403 || response.statusCode() == 429) {
            throw new VulnerabilitySourceException(
                    "GitHub Advisory API rate limit hit while querying '" + packageKey
                            + "'. Set a GITHUB_TOKEN environment variable to raise the limit from 60/hr to 5,000/hr.");
        }
        if (response.statusCode() != 200) {
            throw new VulnerabilitySourceException(
                    "GitHub Advisory API returned HTTP " + response.statusCode() + " for '" + packageKey + "'");
        }
    }

    private List<GhAdvisory> parseBody(String body, String packageKey) {
        try {
            return mapper.readValue(body, new TypeReference<List<GhAdvisory>>() {
            });
        } catch (IOException e) {
            throw new VulnerabilitySourceException(
                    "Could not parse GitHub Advisory API response for '" + packageKey + "'", e);
        }
    }

    private VulnerabilityRecord toRecord(GhAdvisory advisory, NormalizedDependency dependency) {
        if (advisory.vulnerabilities() == null) {
            return null;
        }

        List<VersionRange> ranges = new ArrayList<>();
        for (GhVulnerability v : advisory.vulnerabilities()) {
            if (v.pkg() == null) continue;
            boolean ecosystemMatches = dependency.ecosystem().githubEcosystemName()
                    .equalsIgnoreCase(v.pkg().ecosystem());
            boolean packageMatches = dependency.packageKey().equalsIgnoreCase(v.pkg().name());
            if (!ecosystemMatches || !packageMatches) continue;

            ranges.add(rangeParser.parse(v.vulnerableVersionRange(), v.firstPatchedVersion()));
        }
        if (ranges.isEmpty()) {
            return null; // this advisory's own package/ecosystem fields didn't actually match
        }

        String id = advisory.ghsaId() != null ? advisory.ghsaId() : "GHSA-UNKNOWN-" + System.identityHashCode(advisory);
        Set<String> aliases = advisory.cveId() != null ? Set.of(advisory.cveId()) : Set.of();

        return new VulnerabilityRecord(id, aliases, advisory.summary(),
                Severity.fromString(advisory.severity()), dependency.ecosystem(),
                dependency.packageKey(), ranges, name());
    }

    private HttpResponse<String> sendWithRetry(HttpRequest request, String packageKey) {
        IOException lastError = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (IOException e) {
                lastError = e;
                if (attempt < MAX_ATTEMPTS) {
                    sleepBriefly(attempt);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new VulnerabilitySourceException(
                        "Interrupted while querying GitHub Advisory API for '" + packageKey + "'", e);
            }
        }
        throw new VulnerabilitySourceException(
                "GitHub Advisory API unreachable for '" + packageKey + "' after " + MAX_ATTEMPTS + " attempts",
                lastError);
    }

    private void sleepBriefly(int attempt) {
        try {
            Thread.sleep(200L * attempt);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
