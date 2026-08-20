package com.auditlog.service;

import com.auditlog.dto.ArchiveResponse;
import com.auditlog.dto.ComplianceReportResponse;
import com.auditlog.dto.CreateAuditEventRequest;
import com.auditlog.dto.ExportResponse;
import com.auditlog.dto.RedactionResponse;
import com.auditlog.entity.AuditEvent;
import com.auditlog.exception.InvalidAuditRequestException;
import com.auditlog.repository.AuditEventRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

@Service
public class AuditEventService {

    private static final String GENESIS_HASH = "GENESIS";

    private final AuditEventRepository auditEventRepository;
    private final ObjectMapper objectMapper;

    public AuditEventService(AuditEventRepository auditEventRepository, ObjectMapper objectMapper) {
        this.auditEventRepository = auditEventRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public AuditEvent createEvent(CreateAuditEventRequest request) {
        String previousHash = auditEventRepository.findTopByOrderByIdDesc()
                .map(AuditEvent::getHash)
                .orElse(GENESIS_HASH);

        String payloadHashSource = canonicalizePayload(request.getPayload());
        String hashInput = String.join("|",
                request.getEventType(),
                request.getActorId(),
                request.getResourceType(),
                request.getResourceId(),
                request.getTimestamp().toString(),
                payloadHashSource,
                previousHash
        );

        String hash = sha256(hashInput);

        AuditEvent entity = new AuditEvent(
                request.getEventType(),
                request.getActorId(),
                request.getResourceType(),
                request.getResourceId(),
                request.getPayload(),
                request.getTimestamp(),
                previousHash,
                hash
        );
        entity.setOriginalPayload(new HashMap<>(request.getPayload()));

        return auditEventRepository.save(entity);
    }

    public Page<AuditEvent> findEvents(String actorId,
                                      String resourceType,
                                      String resourceId,
                                      String eventType,
                                      Instant from,
                                      Instant to,
                                      Pageable pageable) {
        Specification<AuditEvent> specification = Specification.where(null);

        if (actorId != null && !actorId.isBlank()) {
            specification = specification.and((root, query, cb) -> cb.equal(root.get("actorId"), actorId));
        }
        if (resourceType != null && !resourceType.isBlank()) {
            specification = specification.and((root, query, cb) -> cb.equal(root.get("resourceType"), resourceType));
        }
        if (resourceId != null && !resourceId.isBlank()) {
            specification = specification.and((root, query, cb) -> cb.equal(root.get("resourceId"), resourceId));
        }
        if (eventType != null && !eventType.isBlank()) {
            specification = specification.and((root, query, cb) -> cb.equal(root.get("eventType"), eventType));
        }
        if (from != null) {
            specification = specification.and((root, query, cb) -> cb.greaterThanOrEqualTo(root.get("timestamp"), from));
        }
        if (to != null) {
            specification = specification.and((root, query, cb) -> cb.lessThanOrEqualTo(root.get("timestamp"), to));
        }

        return auditEventRepository.findAll(specification, pageable);
    }

    public Map<String, Object> verifyChain() {
        List<AuditEvent> events = auditEventRepository.findAllByOrderByIdAsc();
        Map<String, Object> result = new HashMap<>();
        result.put("intact", true);
        result.put("firstBrokenRecordId", null);
        result.put("violationType", null);

        String expectedPreviousHash = GENESIS_HASH;
        for (AuditEvent event : events) {
            Map<String, Object> payloadForHash = event.getOriginalPayload().isEmpty() ? event.getPayload() : event.getOriginalPayload();
            String expectedHash = sha256(String.join("|",
                    event.getEventType(),
                    event.getActorId(),
                    event.getResourceType(),
                    event.getResourceId(),
                    event.getTimestamp().toString(),
                    canonicalizePayload(payloadForHash),
                    expectedPreviousHash
            ));

            if (!GENESIS_HASH.equals(expectedPreviousHash) && !expectedPreviousHash.equals(event.getPreviousHash())) {
                result.put("intact", false);
                result.put("firstBrokenRecordId", event.getId());
                result.put("violationType", "PREVIOUS_HASH_MISMATCH");
                return result;
            }

            if (!expectedHash.equals(event.getHash())) {
                result.put("intact", false);
                result.put("firstBrokenRecordId", event.getId());
                result.put("violationType", "HASH_MISMATCH");
                return result;
            }

            expectedPreviousHash = event.getHash();
        }

        return result;
    }

    public ArchiveResponse archiveOldRecords(Instant cutoff) {
        if (cutoff == null) {
            throw new InvalidAuditRequestException("olderThan is required");
        }

        List<AuditEvent> events = auditEventRepository.findAllByOrderByIdAsc();
        List<Long> archivedIds = new ArrayList<>();
        for (AuditEvent event : events) {
            if (!event.isArchived() && event.getTimestamp().isBefore(cutoff)) {
                event.setArchived(true);
                event.setArchivedAt(Instant.now());
                auditEventRepository.save(event);
                archivedIds.add(event.getId());
            }
        }
        return new ArchiveResponse(archivedIds.size(), archivedIds);
    }

    public RedactionResponse redactPayload(Long eventId, List<String> sensitiveFields) {
        if (eventId == null || eventId <= 0) {
            throw new InvalidAuditRequestException("eventId must be positive");
        }

        List<String> normalizedFields = sensitiveFields == null ? List.of() : sensitiveFields.stream()
                .map(String::trim)
                .filter(field -> !field.isEmpty())
                .distinct()
                .toList();

        AuditEvent event = auditEventRepository.findById(eventId)
                .orElseThrow(() -> new IllegalArgumentException("Audit event not found: " + eventId));

        Map<String, Object> redaction = event.getRedaction();
        Map<String, Object> payload = new HashMap<>(event.getOriginalPayload().isEmpty() ? event.getPayload() : event.getOriginalPayload());
        Map<String, Object> redactedPayload = new HashMap<>();
        Map<String, Object> redactionPayload = new HashMap<>();

        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (normalizedFields.contains(key)) {
                Map<String, Object> redactionEntry = new HashMap<>();
                redactionEntry.put("redacted", true);
                redactionEntry.put("originalHash", sha256(String.valueOf(value)));
                redactionEntry.put("mask", "[REDACTED]");
                redaction.put(key, redactionEntry);
                redactionPayload.put(key, redactionEntry);
                redactedPayload.put(key, "[REDACTED]");
            } else {
                redactedPayload.put(key, value);
            }
        }

        redactedPayload.put("redaction", redactionPayload);
        event.setRedaction(redaction);
        event.setPayload(redactedPayload);
        event.setOriginalPayload(new HashMap<>(payload));
        auditEventRepository.save(event);

        return new RedactionResponse(event.getId(), event.getPayload(), event.getRedaction(), event.getHash());
    }

    public Map<String, Object> getRedactedView(Long eventId) {
        AuditEvent event = auditEventRepository.findById(eventId)
                .orElseThrow(() -> new IllegalArgumentException("Audit event not found: " + eventId));

        Map<String, Object> source = event.getOriginalPayload().isEmpty() ? event.getPayload() : event.getOriginalPayload();
        Map<String, Object> payload = new HashMap<>();
        Map<String, Object> redactionPayload = new HashMap<>();

        for (Map.Entry<String, Object> entry : source.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (key.equals("accountNumber") || key.equals("ssn") || key.equals("personalId") || key.equals("customerId")) {
                Map<String, Object> redactionEntry = new HashMap<>();
                redactionEntry.put("redacted", true);
                redactionEntry.put("mask", "[REDACTED]");
                redactionEntry.put("originalHash", sha256(String.valueOf(value)));
                redactionPayload.put(key, redactionEntry);
                payload.put(key, "[REDACTED]");
            } else {
                payload.put(key, value);
            }
        }
        if (!redactionPayload.isEmpty()) {
            payload.put("redaction", redactionPayload);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("id", event.getId());
        result.put("payload", payload);
        result.put("redaction", event.getRedaction());
        result.put("hash", event.getHash());
        result.put("previousHash", event.getPreviousHash());
        return result;
    }

    public ComplianceReportResponse generateAccountAccessReport(String actorId, String resourceId, String eventType,
                                                               Instant from, Instant to) {
        if (from != null && to != null && from.isAfter(to)) {
            throw new InvalidAuditRequestException("from must be before to");
        }

        Specification<AuditEvent> specification = Specification.where(null);

        if (actorId != null && !actorId.isBlank()) {
            specification = specification.and((root, query, cb) -> cb.equal(root.get("actorId"), actorId));
        }
        if (resourceId != null && !resourceId.isBlank()) {
            specification = specification.and((root, query, cb) -> cb.equal(root.get("resourceId"), resourceId));
        }
        if (eventType != null && !eventType.isBlank()) {
            specification = specification.and((root, query, cb) -> cb.equal(root.get("eventType"), eventType));
        }
        if (from != null) {
            specification = specification.and((root, query, cb) -> cb.greaterThanOrEqualTo(root.get("timestamp"), from));
        }
        if (to != null) {
            specification = specification.and((root, query, cb) -> cb.lessThanOrEqualTo(root.get("timestamp"), to));
        }

        List<AuditEvent> events = auditEventRepository.findAll(specification, Sort.by(Sort.Direction.ASC, "timestamp"));
        List<ComplianceReportResponse.ComplianceReportRecord> accessRecords = new ArrayList<>();

        for (AuditEvent event : events) {
            accessRecords.add(new ComplianceReportResponse.ComplianceReportRecord(
                    event.getId(),
                    event.getTimestamp(),
                    event.getActorId(),
                    event.getResourceType(),
                    event.getResourceId(),
                    event.getEventType(),
                    event.getRedaction() != null && !event.getRedaction().isEmpty(),
                    event.getHash()));
        }

        return new ComplianceReportResponse(
                accessRecords.size(),
                accessRecords,
                Instant.now(),
                new ComplianceReportResponse.Filters(actorId, resourceId, eventType, from, to));
    }

    public ExportResponse exportBundle(String resourceId, String actorId) {
        List<AuditEvent> records = new ArrayList<>();
        if (resourceId != null && !resourceId.isBlank()) {
            records.addAll(auditEventRepository.findAllByResourceIdOrderByIdAsc(resourceId));
        }
        if (actorId != null && !actorId.isBlank()) {
            records.addAll(auditEventRepository.findAllByActorIdOrderByIdAsc(actorId));
        }
        if (records.isEmpty()) {
            return new ExportResponse(0, List.of(), sha256("empty"), Instant.now());
        }

        List<ExportResponse.ExportRecord> exportRecords = new ArrayList<>();
        StringBuilder chainSeed = new StringBuilder();
        for (AuditEvent event : records) {
            exportRecords.add(new ExportResponse.ExportRecord(
                    event.getId(),
                    event.getEventType(),
                    event.getActorId(),
                    event.getResourceType(),
                    event.getResourceId(),
                    event.getPayload(),
                    event.getTimestamp(),
                    event.getPreviousHash(),
                    event.getHash(),
                    event.isArchived(),
                    event.getArchivedAt()));
            chainSeed.append(event.getId()).append('|').append(event.getHash()).append('|');
        }

        return new ExportResponse(exportRecords.size(), exportRecords, sha256(chainSeed.toString()), Instant.now());
    }

    private String canonicalizePayload(Map<String, Object> payload) {
        Object normalized = normalizeForHash(payload == null ? Map.of() : payload);
        try {
            return objectMapper.writeValueAsString(normalized);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unable to serialize payload for audit hash", e);
        }
    }

    private Object normalizeForHash(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> ordered = new TreeMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                ordered.put(String.valueOf(entry.getKey()), normalizeForHash(entry.getValue()));
            }
            return ordered;
        }
        if (value instanceof Iterable<?> iterable) {
            List<Object> normalizedList = new ArrayList<>();
            for (Object item : iterable) {
                normalizedList.add(normalizeForHash(item));
            }
            return Map.of("__list__", normalizedList);
        }
        if (value instanceof Object[] array) {
            List<Object> normalizedList = new ArrayList<>();
            for (Object item : array) {
                normalizedList.add(normalizeForHash(item));
            }
            return Map.of("__list__", normalizedList);
        }
        return value == null ? null : value;
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                String hexValue = Integer.toHexString(0xff & b);
                if (hexValue.length() == 1) {
                    hex.append('0');
                }
                hex.append(hexValue);
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
