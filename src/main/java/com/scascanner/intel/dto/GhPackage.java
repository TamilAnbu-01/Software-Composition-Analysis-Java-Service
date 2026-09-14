package com.scascanner.intel.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Maps the "package" object nested inside one GitHub Advisory "vulnerabilities[]" entry. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GhPackage(
        @JsonProperty("ecosystem") String ecosystem,
        @JsonProperty("name") String name
) {
    @JsonCreator
    public GhPackage {
    }
}
