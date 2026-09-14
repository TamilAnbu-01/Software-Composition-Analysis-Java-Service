package com.scascanner.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scascanner.model.ScanResult;
import com.scascanner.service.ScanService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Controller-level tests using a mocked ScanService (standaloneSetup, no full Spring context) -
 * these check request/response wiring, not the scanning logic itself, which is covered
 * exhaustively by ScanServiceTest and the engine-level tests instead.
 *
 * Note: this test needs spring-test + Mockito, pulled in transitively by
 * spring-boot-starter-test. Unlike the other 45 tests in this suite, it could not be compiled
 * or run in the sandbox this project was developed in (no access to Maven Central to fetch
 * Spring's own jars - see README "How this was tested"). It follows the standard
 * MockMvc/Mockito pattern; run `mvn test` to verify it after cloning.
 */
class ScanControllerTest {

    private MockMvc mockMvc;
    private ScanService scanService;
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        scanService = mock(ScanService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new ScanController(scanService)).build();
    }

    @Test
    void postScan_returnsCreatedWithScanId() throws Exception {
        ScanResult fake = new ScanResult("scan-123", "demo", Instant.now(), List.of(), List.of(), List.of());
        when(scanService.scan(any())).thenReturn(fake);

        String body = """
                {"project":"demo","dependencies":[
                  {"ecosystem":"maven","group":"org.apache.logging.log4j","name":"log4j-core","version":"2.14.1"}
                ]}""";

        mockMvc.perform(post("/api/v1/scans").contentType("application/json").content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.scanId").value("scan-123"))
                .andExpect(jsonPath("$.project").value("demo"));
    }

    @Test
    void getScan_knownId_returnsOk() throws Exception {
        ScanResult fake = new ScanResult("scan-abc", "demo", Instant.now(), List.of(), List.of(), List.of());
        when(scanService.getScan("scan-abc")).thenReturn(fake);

        mockMvc.perform(get("/api/v1/scans/scan-abc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scanId").value("scan-abc"));
    }

    @Test
    void getScan_unknownId_returnsNotFound() throws Exception {
        when(scanService.getScan("missing")).thenReturn(null);

        mockMvc.perform(get("/api/v1/scans/missing"))
                .andExpect(status().isNotFound());
    }

    @Test
    void health_returnsUp() throws Exception {
        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }
}
