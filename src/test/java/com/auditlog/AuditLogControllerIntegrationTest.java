package com.auditlog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.auditlog.entity.AuditEvent;
import com.auditlog.repository.AuditEventRepository;
import com.auditlog.service.AuditEventService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuditLogControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private AuditEventService auditEventService;

    @BeforeEach
    void setUp() {
        auditEventRepository.deleteAll();
    }

    @Test
    void shouldCreateAuditEventAndPersistHashChain() throws Exception {
        String requestBody = """
                {
                  "eventType": "USER_LOGIN",
                  "actorId": "user-1",
                  "resourceType": "USER",
                  "resourceId": "user-123",
                  "payload": {"ipAddress": "10.0.0.1", "loginResult": "SUCCESS"}
                }
                """;

        MvcResult result = mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode response = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(response.get("eventType").asText()).isEqualTo("USER_LOGIN");
        assertThat(response.get("actorId").asText()).isEqualTo("user-1");
        assertThat(response.get("timestamp").asText()).isNotBlank();
        assertThat(response.get("previousHash").asText()).isNotBlank();
        assertThat(response.get("hash").asText()).isNotBlank();

        assertThat(auditEventRepository.count()).isEqualTo(1L);
    }

    @Test
    void shouldFilterEventsByFieldsAndReturnPaginatedResults() throws Exception {
        auditEventRepository.save(new AuditEvent("USER_LOGIN", "user-1", "USER", "user-123",
                Map.of("ipAddress", "10.0.0.1"), "2026-08-19T12:00:00Z", "GENESIS", "hash-1"));
        auditEventRepository.save(new AuditEvent("RECORD_UPDATED", "user-2", "USER", "user-123",
                Map.of("field", "email"), "2026-08-19T12:10:00Z", "hash-1", "hash-2"));
        auditEventRepository.save(new AuditEvent("USER_LOGIN", "user-1", "ACCOUNT", "acct-9",
                Map.of("ipAddress", "10.0.0.2"), "2026-08-19T12:20:00Z", "hash-2", "hash-3"));

        mockMvc.perform(get("/audit/events")
                        .param("actorId", "user-1")
                        .param("eventType", "USER_LOGIN")
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(2));

        mockMvc.perform(get("/audit/events")
                        .param("resourceType", "USER")
                        .param("resourceId", "user-123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(2));
    }

    @Test
    void shouldVerifyHashChainWhenInternalStateIsIntact() throws Exception {
        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "eventType": "USER_LOGIN",
                                  "actorId": "user-1",
                                  "resourceType": "USER",
                                  "resourceId": "user-123",
                                  "payload": {"ipAddress": "10.0.0.1"}
                                }
                                """))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true));
    }

    @Test
    void shouldHandleMalformedSortParameterWithoutServerError() throws Exception {
        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "eventType": "USER_LOGIN",
                                  "actorId": "user-1",
                                  "resourceType": "USER",
                                  "resourceId": "user-123",
                                  "payload": {"ipAddress": "10.0.0.1"}
                                }
                                """))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/audit/events")
                        .param("eventType", "USER_LOGIN")
                        .param("page", "0")
                        .param("size", "1")
                        .param("sort", "[\"string\"]"))
                .andExpect(status().isOk());
    }

    @Test
    void shouldReturnIntactTrueForCleanHashChain() throws Exception {
        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "eventType": "USER_LOGIN",
                                  "actorId": "user-1",
                                  "resourceType": "USER",
                                  "resourceId": "user-123",
                                  "payload": {"ipAddress": "10.0.0.1", "loginResult": "SUCCESS"}
                                }
                                """))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "eventType": "RECORD_UPDATED",
                                  "actorId": "user-1",
                                  "resourceType": "USER",
                                  "resourceId": "user-123",
                                  "payload": {"field": "email", "value": "user@example.com"}
                                }
                                """))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.violationType").doesNotExist());
    }

    @Test
    void shouldRejectInvalidAuditEventPayload() throws Exception {
        String requestBody = """
                {
                  "eventType": "USER_LOGIN",
                  "actorId": "user-1",
                  "resourceType": "USER",
                  "payload": {"ipAddress": "10.0.0.1"}
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldSkipArchivedRecordsWhenVerifyingActiveChain() throws Exception {
        String createFirst = """
                {
                  "eventType": "USER_LOGIN",
                  "actorId": "user-1",
                  "resourceType": "USER",
                  "resourceId": "user-123",
                  "payload": {"ipAddress": "10.0.0.1"}
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createFirst))
                .andExpect(status().isCreated());

        AuditEvent archived = auditEventRepository.findAllByOrderByIdAsc().get(0);
        archived.setArchived(true);
        archived.setArchivedAt("2026-08-19T12:00:00Z");
        auditEventRepository.save(archived);

        String createSecond = """
                {
                  "eventType": "RECORD_UPDATED",
                  "actorId": "user-1",
                  "resourceType": "USER",
                  "resourceId": "user-123",
                  "payload": {"field": "email", "value": "user@example.com"}
                }
                """;

        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createSecond))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true));
    }

    @Test
    void shouldMaskSensitiveCustomerIdInRedactedView() throws Exception {
        mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "eventType": "USER_LOGIN",
                                  "actorId": "user-1",
                                  "resourceType": "USER",
                                  "resourceId": "user-123",
                                  "payload": {"customerId": "CUST-4321", "ipAddress": "10.0.0.1"}
                                }
                                """))
                .andExpect(status().isCreated());

        AuditEvent created = auditEventRepository.findAllByOrderByIdAsc().get(0);

        mockMvc.perform(get("/audit/events/{id}/redacted", created.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload.customerId").value("[REDACTED]"))
                .andExpect(jsonPath("$.payload.redaction.customerId.redacted").value(true))
                .andExpect(jsonPath("$.payload.redaction.customerId.mask").value("[REDACTED]"));
    }

    @Test
    void shouldGenerateAccountAccessComplianceReport() throws Exception {
        auditEventRepository.save(new AuditEvent("ACCOUNT_VIEW", "user-1", "ACCOUNT", "acct-100",
                Map.of("customerId", "CUST-4321", "ipAddress", "10.0.0.1"), "2026-08-19T12:00:00Z", "GENESIS", "hash-1"));
        auditEventRepository.save(new AuditEvent("ACCOUNT_VIEW", "user-2", "ACCOUNT", "acct-100",
                Map.of("customerId", "CUST-4321", "ipAddress", "10.0.0.2"), "2026-08-19T12:05:00Z", "hash-1", "hash-2"));

        mockMvc.perform(get("/audit/compliance/account-access")
                        .param("resourceId", "acct-100")
                        .param("eventType", "ACCOUNT_VIEW"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recordCount").value(2))
                .andExpect(jsonPath("$.records[0].resourceId").value("acct-100"))
                .andExpect(jsonPath("$.records[0].eventType").value("ACCOUNT_VIEW"));
    }

    @Test
    void shouldReturnEmptyComplianceReportWhenNoMatchingAccountAccessEvents() throws Exception {
        mockMvc.perform(get("/audit/compliance/account-access")
                        .param("resourceId", "acct-404")
                        .param("eventType", "ACCOUNT_VIEW"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recordCount").value(0))
                .andExpect(jsonPath("$.records").isArray());
    }

    @Test
    void shouldPersistRedactionWhenSensitiveFieldsAreProvided() throws Exception {
        AuditEvent event = auditEventRepository.save(new AuditEvent("ACCOUNT_VIEW", "user-1", "ACCOUNT", "acct-100",
                Map.of("customerId", "CUST-4321", "ipAddress", "10.0.0.1"), "2026-08-19T12:00:00Z", "GENESIS", "hash-1"));

        mockMvc.perform(post("/audit/events/{id}/redact", event.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fields": ["customerId"]
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload.customerId").value("[REDACTED]"))
                .andExpect(jsonPath("$.redaction.customerId.redacted").value(true))
                .andExpect(jsonPath("$.redaction.customerId.mask").value("[REDACTED]"));
    }

    @Test
    void shouldLeavePayloadUnchangedWhenRedactCalledWithoutFields() throws Exception {
        AuditEvent event = auditEventRepository.save(new AuditEvent("ACCOUNT_VIEW", "user-1", "ACCOUNT", "acct-100",
                Map.of("customerId", "CUST-4321", "ipAddress", "10.0.0.1"), "2026-08-19T12:00:00Z", "GENESIS", "hash-1"));

        mockMvc.perform(post("/audit/events/{id}/redact", event.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fields": []
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload.customerId").value("CUST-4321"))
                .andExpect(jsonPath("$.redaction").isEmpty());
    }

    @Test
    void shouldArchiveHistoricalRecords() throws Exception {
        AuditEvent oldEvent = auditEventRepository.save(new AuditEvent("ACCOUNT_VIEW", "user-1", "ACCOUNT", "acct-100",
                Map.of("customerId", "CUST-4321"), "2026-08-18T12:00:00Z", "GENESIS", "hash-1"));

        mockMvc.perform(post("/audit/retention/archive")
                        .param("olderThan", "2026-08-19T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(1))
                .andExpect(jsonPath("$.archivedIds[0]").value(oldEvent.getId().intValue()));
    }

    @Test
    void shouldArchiveHistoricalRecordsFromRequestBody() throws Exception {
        AuditEvent oldEvent = auditEventRepository.save(new AuditEvent("ACCOUNT_VIEW", "user-1", "ACCOUNT", "acct-100",
                Map.of("customerId", "CUST-4321"), "2026-08-18T12:00:00Z", "GENESIS", "hash-1"));

        mockMvc.perform(post("/audit/retention/archive")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "olderThan": "2026-08-19T00:00:00Z"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(1))
                .andExpect(jsonPath("$.archivedIds[0]").value(oldEvent.getId().intValue()));
    }

    @Test
    void shouldRejectBlankRedactionFieldNames() throws Exception {
        AuditEvent event = auditEventRepository.save(new AuditEvent("ACCOUNT_VIEW", "user-1", "ACCOUNT", "acct-100",
                Map.of("customerId", "CUST-4321", "ipAddress", "10.0.0.1"), "2026-08-19T12:00:00Z", "GENESIS", "hash-1"));

        mockMvc.perform(post("/audit/events/{id}/redact", event.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fields": ["  ", "customerId"]
                                }
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldNotArchiveRecentRecords() throws Exception {
        auditEventRepository.save(new AuditEvent("ACCOUNT_VIEW", "user-1", "ACCOUNT", "acct-100",
                Map.of("customerId", "CUST-4321"), "2026-08-20T12:00:00Z", "GENESIS", "hash-1"));

        mockMvc.perform(post("/audit/retention/archive")
                        .param("olderThan", "2026-08-18T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(0))
                .andExpect(jsonPath("$.archivedIds").isArray());
    }

    @Test
    void shouldExportBundleForResourceAndKeepChainMetadata() throws Exception {
        auditEventRepository.save(new AuditEvent("USER_LOGIN", "user-1", "USER", "user-123",
                Map.of("ipAddress", "10.0.0.1"), "2026-08-19T12:00:00Z", "GENESIS", "hash-1"));
        auditEventRepository.save(new AuditEvent("RECORD_UPDATED", "user-1", "USER", "user-123",
                Map.of("field", "email"), "2026-08-19T12:05:00Z", "hash-1", "hash-2"));

        mockMvc.perform(get("/audit/export")
                        .param("resourceId", "user-123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recordCount").value(2))
                .andExpect(jsonPath("$.records[0].previousHash").value("GENESIS"))
                .andExpect(jsonPath("$.bundleHash").isNotEmpty());
    }

    @Test
    void shouldReturnEmptyExportBundleWhenNoRecordsMatch() throws Exception {
        mockMvc.perform(get("/audit/export")
                        .param("resourceId", "missing-resource"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recordCount").value(0))
                .andExpect(jsonPath("$.records").isArray())
                .andExpect(jsonPath("$.bundleHash").isNotEmpty());
    }

    @Test
    void shouldDetectTamperingInHashChain() throws Exception {
        AuditEvent firstEvent = auditEventRepository.save(new AuditEvent("USER_LOGIN", "user-1", "USER", "user-123",
                Map.of("ipAddress", "10.0.0.1"), "2026-08-19T12:00:00Z", "GENESIS", "hash-1"));
        auditEventRepository.save(new AuditEvent("RECORD_UPDATED", "user-1", "USER", "user-123",
                Map.of("field", "email"), "2026-08-19T12:05:00Z", "hash-1", "hash-2"));

        firstEvent.setPayload(Map.of("ipAddress", "10.0.0.9"));
        auditEventRepository.save(firstEvent);

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(false))
                .andExpect(jsonPath("$.firstBrokenRecordId").value(firstEvent.getId().intValue()));
    }
}
