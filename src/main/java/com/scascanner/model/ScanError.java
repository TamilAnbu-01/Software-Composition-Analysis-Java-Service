package com.scascanner.model;

/**
 * A per-item problem that did not stop the scan - the offending dependency was skipped and
 * everything else was still processed. This is how section 10 (error handling) surfaces:
 * the response is 200 with partial results plus a list of these, not a 500.
 */
public record ScanError(String dependency, String reason) {
}
