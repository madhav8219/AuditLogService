package com.auditlog.dto;

import com.auditlog.entity.AuditEvent;

import java.time.Instant;
import java.util.Map;

public record AuditEventResponse(
        Long id,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Map<String, Object> payload,
        Instant timestamp,
        String previousHash,
        String hash
) {
    public static AuditEventResponse fromEntity(AuditEvent event) {
        return new AuditEventResponse(
                event.getId(),
                event.getEventType(),
                event.getActorId(),
                event.getResourceType(),
                event.getResourceId(),
                event.getPayload(),
                event.getTimestamp(),
                event.getPreviousHash(),
                event.getHash()
        );
    }
}
