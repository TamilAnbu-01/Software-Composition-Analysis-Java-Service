package com.scascanner.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scascanner.model.Ecosystem;
import com.scascanner.model.ScanResult;
import com.scascanner.model.Severity;
import com.scascanner.model.VulnerabilityRecord;
import com.scascanner.service.ScanService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ScanControllerTest {

    private MockMvc mockMvc;
    private ScanService scanService;
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        scanService = mock(ScanService.class);

        mockMvc = MockMvcBuilders
                .standaloneSetup(new ScanController(scanService))
                .build();
    }

    @Test
    void postScan_returnsCreatedWithScanId() throws Exception {

        ScanResult fake = new ScanResult(
                "scan-123",
                "demo",
                Instant.now(),
                List.of(),
                List.of(),
                List.of()
        );

        when(scanService.scan(any())).thenReturn(fake);

        String body = """
                {
                  "project": "demo",
                  "dependencies": [
                    {
                      "ecosystem": "maven",
                      "group": "org.apache.logging.log4j",
                      "name": "log4j-core",
                      "version": "2.14.1"
                    }
                  ]
                }
                """;

        mockMvc.perform(
                        post("/scan")
                                .contentType("application/json")
                                .content(body)
                )
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.scanId").value("scan-123"))
                .andExpect(jsonPath("$.project").value("demo"));
    }

    @Test
    void getVulnerability_knownId_returnsOk() throws Exception {

        VulnerabilityRecord fake = new VulnerabilityRecord(
                "CVE-2021-44228",
                Set.of(),
                "Log4Shell",
                Severity.CRITICAL,
                Ecosystem.MAVEN,
                "org.apache.logging.log4j:log4j-core",
                List.of(),
                "FAKE"
        );

        when(scanService.getVulnerability("CVE-2021-44228"))
                .thenReturn(fake);

        mockMvc.perform(
                        get("/vulnerabilities/CVE-2021-44228")
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("CVE-2021-44228"))
                .andExpect(jsonPath("$.summary").value("Log4Shell"))
                .andExpect(jsonPath("$.severity").value("CRITICAL"));
    }

    @Test
    void getVulnerability_unknownId_returnsNotFound() throws Exception {

        when(scanService.getVulnerability("missing"))
                .thenReturn(null);

        mockMvc.perform(
                        get("/vulnerabilities/missing")
                )
                .andExpect(status().isNotFound());
    }

    @Test
    void getScan_knownId_returnsOk() throws Exception {

        ScanResult fake = new ScanResult(
                "scan-abc",
                "demo",
                Instant.now(),
                List.of(),
                List.of(),
                List.of()
        );

        when(scanService.getScan("scan-abc"))
                .thenReturn(fake);

        mockMvc.perform(
                        get("/scans/scan-abc")
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scanId").value("scan-abc"));
    }

    @Test
    void getScan_unknownId_returnsNotFound() throws Exception {

        when(scanService.getScan("missing"))
                .thenReturn(null);

        mockMvc.perform(
                        get("/scans/missing")
                )
                .andExpect(status().isNotFound());
    }

    @Test
    void health_returnsUp() throws Exception {

        mockMvc.perform(
                        get("/health")
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }
}