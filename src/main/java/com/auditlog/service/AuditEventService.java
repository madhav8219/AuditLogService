package com.auditlog.service;

import com.auditlog.dto.CreateAuditEventRequest;
import com.auditlog.entity.AuditEvent;
import com.auditlog.repository.AuditEventRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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

        String payloadHashSource = canonicalizePayload(request.payload());
        String hashInput = String.join("|",
                request.eventType(),
                request.actorId(),
                request.resourceType(),
                request.resourceId(),
                request.timestamp().toString(),
                payloadHashSource,
                previousHash
        );

        String hash = sha256(hashInput);

        AuditEvent entity = new AuditEvent(
                request.eventType(),
                request.actorId(),
                request.resourceType(),
                request.resourceId(),
                request.payload(),
                request.timestamp(),
                previousHash,
                hash
        );

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
            String expectedHash = sha256(String.join("|",
                    event.getEventType(),
                    event.getActorId(),
                    event.getResourceType(),
                    event.getResourceId(),
                    event.getTimestamp().toString(),
                    canonicalizePayload(event.getPayload()),
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
