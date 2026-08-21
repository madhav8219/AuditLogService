package com.auditlog;

import com.auditlog.dto.CreateAuditEventRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.auditlog.entity.AuditEvent;
import com.auditlog.repository.AuditEventRepository;
import com.auditlog.security.JwtTokenProvider;
import com.auditlog.service.AuditEventService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@WithMockUser(username = "admin-user", roles = "ADMIN")
class AuditLogControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private AuditEventService auditEventService;

    @Value("${jwt.secret}")
    private String jwtSecret;

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
    @WithAnonymousUser
    void shouldRequireAuthenticationForRedactionEndpoint() throws Exception {
        AuditEvent created = auditEventRepository.save(new AuditEvent(
                "USER_LOGIN",
                "user-1",
                "USER",
                "user-123",
                Map.of("ipAddress", "10.0.0.1"),
                "2026-08-19T12:00:00Z",
                "GENESIS",
                "hash-1"));

        mockMvc.perform(post("/audit/events/{id}/redact", created.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fields": ["ipAddress"]
                                }
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "viewer-user", roles = "USER")
    void shouldRejectUsersWithoutRequiredRoleForAuditEventCreation() throws Exception {
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
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin-user", roles = "ADMIN")
    void shouldAllowAdminRoleOnProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "audit-officer", roles = "AUDIT_OFFICER")
    void shouldRejectAuditOfficerOnAdminOnlyEndpoint() throws Exception {
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
                .andExpect(status().isForbidden());
    }

    @Test
    @WithAnonymousUser
    void shouldDenyAnonymousAccessToProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithAnonymousUser
    void shouldRejectNonBearerAuthorizationHeader() throws Exception {
        mockMvc.perform(get("/audit/verify")
                        .header("Authorization", "Token " + jwtTokenProvider.generateToken("admin-user", List.of("ADMIN"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithAnonymousUser
    void shouldRejectBlankBearerToken() throws Exception {
        mockMvc.perform(get("/audit/verify")
                        .header("Authorization", "Bearer "))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "audit-officer", roles = "AUDIT_OFFICER")
    void shouldRejectNegativePageNumberForEventQuery() throws Exception {
        mockMvc.perform(get("/audit/events")
                        .param("page", "-1")
                        .param("size", "10"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "audit-officer", roles = "AUDIT_OFFICER")
    void shouldRejectOversizedPageSizeForEventQuery() throws Exception {
        mockMvc.perform(get("/audit/events")
                        .param("page", "0")
                        .param("size", "1000"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithAnonymousUser
    void shouldRejectWhitespaceOnlyBearerToken() throws Exception {
        mockMvc.perform(get("/audit/verify")
                        .header("Authorization", "Bearer    "))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "viewer-user", roles = "USER")
    void shouldRejectUserRoleForAdminOnlyArchiveEndpoint() throws Exception {
        mockMvc.perform(post("/audit/retention/archive")
                        .param("olderThan", "2026-08-19T00:00:00Z"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "rate-limited-user-unique", roles = "ADMIN")
    void shouldThrottleUserAfterExceedingRateLimit() throws Exception {
        for (int i = 0; i < 1000; i++) {
            mockMvc.perform(get("/audit/verify"))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    @WithAnonymousUser
    void shouldDenyExpiredJwtOnProtectedEndpoint() throws Exception {
        SecretKey key = Keys.hmacShaKeyFor(java.util.Base64.getDecoder().decode(java.util.Base64.getEncoder().encodeToString(jwtSecret.getBytes())));
        String expiredToken = Jwts.builder()
                .subject("expired-user")
                .claim("roles", List.of("ADMIN"))
                .expiration(new Date(System.currentTimeMillis() - 60_000))
                .signWith(key)
                .compact();

        mockMvc.perform(get("/audit/verify")
                        .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithAnonymousUser
    void shouldDenyModifiedJwtOnProtectedEndpoint() throws Exception {
        String validToken = jwtTokenProvider.generateToken("admin-user", List.of("ADMIN"));
        String modifiedToken = validToken.substring(0, validToken.length() - 1) + "A";

        mockMvc.perform(get("/audit/verify")
                        .header("Authorization", "Bearer " + modifiedToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithAnonymousUser
    void shouldRejectJwtWithMalformedStructure() throws Exception {
        mockMvc.perform(get("/audit/verify")
                        .header("Authorization", "Bearer invalid.jwt.token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "security-user", roles = "SECURITY_ANALYST")
    void shouldAllowAuthorizedSecurityAnalystToReadAuditEvents() throws Exception {
        mockMvc.perform(get("/audit/events")
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "compliance-user", roles = "COMPLIANCE_REVIEWER")
    void shouldRejectComplianceReviewerForArchiveEndpoint() throws Exception {
        mockMvc.perform(post("/audit/retention/archive")
                        .param("olderThan", "2026-08-19T00:00:00Z"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "audit-officer", roles = "AUDIT_OFFICER")
    void shouldAllowAuditOfficerToArchiveHistoricalRecords() throws Exception {
        mockMvc.perform(post("/audit/retention/archive")
                        .param("olderThan", "2026-08-19T00:00:00Z"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "admin-user", roles = "ADMIN")
    void shouldAllowAdminToAccessHighPrivilegeComplianceActions() throws Exception {
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk());
    }

    @Test
    void shouldDeduplicateSameAppendPayload() {
        CreateAuditEventRequest request = new CreateAuditEventRequest();
        request.setEventType("USER_LOGIN");
        request.setActorId("user-1");
        request.setResourceType("USER");
        request.setResourceId("user-123");
        request.setPayload(Map.of("ipAddress", "10.0.0.1"));

        AuditEvent first = auditEventService.createEvent(request);
        AuditEvent second = auditEventService.createEvent(request);

        assertThat(first.getId()).isEqualTo(second.getId());
        assertThat(auditEventRepository.count()).isEqualTo(1L);
        assertThat(auditEventService.verifyChain().get("intact")).isEqualTo(true);
    }

    @Test
    void shouldKeepHashChainIntactUnderConcurrentAppend() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(4);
        CountDownLatch ready = new CountDownLatch(4);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuditEvent>> futures = new ArrayList<>();

        for (int i = 0; i < 4; i++) {
            final int index = i;
            futures.add(executor.submit(() -> {
                ready.countDown();
                start.await();
                CreateAuditEventRequest request = new CreateAuditEventRequest();
                request.setEventType("USER_LOGIN");
                request.setActorId("user-" + index);
                request.setResourceType("USER");
                request.setResourceId("user-" + index);
                request.setPayload(Map.of("ipAddress", "10.0.0." + index));
                return auditEventService.createEvent(request);
            }));
        }

        ready.await();
        start.countDown();

        for (Future<AuditEvent> future : futures) {
            future.get();
        }
        executor.shutdown();

        assertThat(auditEventRepository.count()).isEqualTo(4L);
        assertThat(auditEventService.verifyChain().get("intact")).isEqualTo(true);
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
    void shouldPlaceLegalHoldAndBlockRedactionWhileOnHold() throws Exception {
        AuditEvent event = auditEventRepository.save(new AuditEvent("ACCOUNT_VIEW", "user-1", "ACCOUNT", "acct-100",
                Map.of("customerId", "CUST-4321", "ipAddress", "10.0.0.1"), "2026-08-19T12:00:00Z", "GENESIS", "hash-1"));

        mockMvc.perform(post("/audit/events/{id}/hold", event.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "Litigation hold"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.legalHold").value(true))
                .andExpect(jsonPath("$.holdReason").value("Litigation hold"));

        mockMvc.perform(post("/audit/events/{id}/redact", event.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fields": ["customerId"]
                                }
                                """))
                .andExpect(status().isConflict());
    }

    @Test
    void shouldExportAnAttestedBundleWithEvidenceActionMetadata() throws Exception {
        auditEventRepository.save(new AuditEvent("USER_LOGIN", "user-1", "USER", "user-123",
                Map.of("ipAddress", "10.0.0.1"), "2026-08-19T12:00:00Z", "GENESIS", "hash-1"));

        mockMvc.perform(get("/audit/export")
                        .param("resourceId", "user-123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.bundleAttestation").isNotEmpty())
                .andExpect(jsonPath("$.attestationAlgorithm").value("HMAC-SHA256"))
                .andExpect(jsonPath("$.evidenceActionCount").value(1));
    }

    @Test
    void shouldFlagIntegrityViolationAfterRedactionOrArchiveAction() throws Exception {
        AuditEvent event = auditEventRepository.save(new AuditEvent(
                "USER_LOGIN",
                "user-1",
                "USER",
                "user-123",
                Map.of("customerId", "CUST-4321", "ipAddress", "10.0.0.1"),
                "2026-08-19T12:00:00Z",
                "GENESIS",
                "hash-1"));

        mockMvc.perform(post("/audit/events/{id}/redact", event.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "fields": ["customerId"]
                                }
                                """))
                .andExpect(status().isOk());

        mockMvc.perform(post("/audit/retention/archive")
                        .param("olderThan", "2026-08-19T00:00:00Z"))
                .andExpect(status().isOk());

        Map<String, Object> verification = auditEventService.verifyChain();
        assertThat((Boolean) verification.get("intact")).isFalse();
        assertThat(verification.get("violationType")).isNotNull();
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
    void shouldCreateEventsWithChainMetadataAndOrderedHashLinks() throws Exception {
        MvcResult firstResult = mockMvc.perform(post("/audit/events")
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
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode firstResponse = objectMapper.readTree(firstResult.getResponse().getContentAsString());
        assertThat(firstResponse.get("id").isNumber()).isTrue();
        assertThat(firstResponse.get("timestamp").asText()).isNotBlank();
        assertThat(firstResponse.get("previousHash").asText()).isEqualTo("GENESIS");
        assertThat(firstResponse.get("hash").asText()).isNotBlank();

        MvcResult secondResult = mockMvc.perform(post("/audit/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "eventType": "RECORD_UPDATED",
                                  "actorId": "user-1",
                                  "resourceType": "USER",
                                  "resourceId": "user-123",
                                  "payload": {"field": "email"}
                                }
                                """))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode secondResponse = objectMapper.readTree(secondResult.getResponse().getContentAsString());
        assertThat(secondResponse.get("previousHash").asText()).isEqualTo(firstResponse.get("hash").asText());
        assertThat(secondResponse.get("hash").asText()).isNotBlank();
        assertThat(secondResponse.get("timestamp").asText()).isNotBlank();
    }

    @Test
    void shouldFlagBrokenExportAsNotIndependentlyVerifiable() throws Exception {
        AuditEvent firstEvent = auditEventRepository.save(new AuditEvent("USER_LOGIN", "user-1", "USER", "user-123",
                Map.of("ipAddress", "10.0.0.1"), "2026-08-19T12:00:00Z", "GENESIS", "hash-1"));
        auditEventRepository.save(new AuditEvent("RECORD_UPDATED", "user-1", "USER", "user-123",
                Map.of("field", "email"), "2026-08-19T12:05:00Z", "hash-1", "hash-2"));

        MvcResult firstExport = mockMvc.perform(get("/audit/export")
                        .param("resourceId", "user-123"))
                .andExpect(status().isOk())
                .andReturn();

        String originalAttestation = objectMapper.readTree(firstExport.getResponse().getContentAsString())
                .get("bundleAttestation").asText();

        firstEvent.setPayload(Map.of("ipAddress", "10.0.0.9"));
        auditEventRepository.save(firstEvent);

        MvcResult secondExport = mockMvc.perform(get("/audit/export")
                        .param("resourceId", "user-123"))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode secondExportBody = objectMapper.readTree(secondExport.getResponse().getContentAsString());
        assertThat(secondExportBody.get("bundleAttestation").asText()).isNotEqualTo(originalAttestation);
        assertThat(secondExportBody.get("independentlyVerifiable").asBoolean()).isFalse();
        assertThat(auditEventService.verifyChain().get("intact")).isEqualTo(false);
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

    @Test
    void shouldUseConfiguredDefaultRetentionWhenCutoffIsNotProvided() throws Exception {
        AuditEvent oldEvent = auditEventRepository.save(new AuditEvent("ACCOUNT_VIEW", "user-1", "ACCOUNT", "acct-100",
                Map.of("customerId", "CUST-4321"), "2023-08-18T12:00:00Z", "GENESIS", "hash-1"));

        mockMvc.perform(post("/audit/retention/archive"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(1))
                .andExpect(jsonPath("$.archivedIds[0]").value(oldEvent.getId().intValue()));
    }
}
