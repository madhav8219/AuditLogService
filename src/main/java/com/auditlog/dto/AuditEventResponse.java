package com.auditlog.dto;

import com.auditlog.entity.AuditEvent;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuditEventResponse {
    private Long id;
    private String eventType;
    private String actorId;
    private String resourceType;
    private String resourceId;
    private Map<String, Object> payload;
    private Map<String, Object> redaction;
    private Instant timestamp;
    private String previousHash;
    private String hash;
    private boolean archived;
    private Instant archivedAt;

    public static AuditEventResponse fromEntity(AuditEvent event) {
        return new AuditEventResponse(
                event.getId(),
                event.getEventType(),
                event.getActorId(),
                event.getResourceType(),
                event.getResourceId(),
                event.getPayload(),
                event.getRedaction(),
                event.getTimestamp(),
                event.getPreviousHash(),
                event.getHash(),
                event.isArchived(),
                event.getArchivedAt()
        );
    }
}
