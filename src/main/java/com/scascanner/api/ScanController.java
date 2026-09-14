package com.scascanner.api;

import com.scascanner.model.ScanRequest;
import com.scascanner.model.ScanResult;
import com.scascanner.service.ScanService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST surface for the scanner. A scan always returns 201 with a body - even when individual
 * dependencies inside the request were invalid or the vulnerability source failed for one of
 * them, those are reported as {@code errors[]} in the body (see {@link ScanResult}), not as an
 * HTTP error. HTTP-level errors here are reserved for the request itself being malformed - see
 * {@link GlobalExceptionHandler}.
 */
@RestController
@RequestMapping("/api/v1")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @PostMapping("/scans")
    public ResponseEntity<ScanResult> createScan(@Valid @RequestBody ScanRequest request) {
        ScanResult result = scanService.scan(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @GetMapping("/scans/{scanId}")
    public ResponseEntity<ScanResult> getScan(@PathVariable String scanId) {
        ScanResult result = scanService.getScan(scanId);
        return result != null ? ResponseEntity.ok(result) : ResponseEntity.notFound().build();
    }

    @GetMapping("/health")
    public ResponseEntity<HealthResponse> health() {
        return ResponseEntity.ok(new HealthResponse("UP"));
    }

    public record HealthResponse(String status) {
    }
}
