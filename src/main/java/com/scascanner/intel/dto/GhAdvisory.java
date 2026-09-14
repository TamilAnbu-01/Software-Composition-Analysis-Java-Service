package com.scascanner.intel.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * The subset of a GitHub Security Advisory (from GET /advisories) this service cares about.
 * The real response has many more fields (references, credits, cvss_severities, cwes, ...);
 * everything not listed here is ignored rather than failing deserialization.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GhAdvisory(
        @JsonProperty("ghsa_id") String ghsaId,
        @JsonProperty("cve_id") String cveId,
        @JsonProperty("summary") String summary,
        @JsonProperty("severity") String severity,
        @JsonProperty("vulnerabilities") List<GhVulnerability> vulnerabilities
) {
    @JsonCreator
    public GhAdvisory {
    }
}
