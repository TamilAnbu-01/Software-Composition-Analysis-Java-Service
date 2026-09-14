package com.scascanner.api;

import com.scascanner.model.ScanRequest;
import com.scascanner.model.ScanResult;
import com.scascanner.model.VulnerabilityRecord;
import com.scascanner.service.ScanService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST surface for the scanner.
 */
@RestController
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @PostMapping("/scan")
    public ResponseEntity<ScanResult> createScan(
            @Valid @RequestBody ScanRequest request) {

        ScanResult result = scanService.scan(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(result);
    }

    @GetMapping("/vulnerabilities/{id}")
    public ResponseEntity<VulnerabilityRecord> getVulnerability(
            @PathVariable String id) {

        VulnerabilityRecord vulnerability =
                scanService.getVulnerability(id);

        return vulnerability != null
                ? ResponseEntity.ok(vulnerability)
                : ResponseEntity.notFound().build();
    }

    @GetMapping("/scans/{scanId}")
    public ResponseEntity<ScanResult> getScan(
            @PathVariable String scanId) {

        ScanResult result = scanService.getScan(scanId);

        return result != null
                ? ResponseEntity.ok(result)
                : ResponseEntity.notFound().build();
    }

    @GetMapping("/health")
    public ResponseEntity<HealthResponse> health() {
        return ResponseEntity.ok(new HealthResponse("UP"));
    }

    public record HealthResponse(String status) {
    }
}