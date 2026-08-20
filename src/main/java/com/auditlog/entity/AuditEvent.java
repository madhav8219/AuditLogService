package com.auditlog.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Entity
@Table(name = "audit_events")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String eventType;

    @Column(nullable = false)
    private String actorId;

    @Column(nullable = false)
    private String resourceType;

    @Column(nullable = false)
    private String resourceId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "JSON", nullable = false)
    private Map<String, Object> payload = new HashMap<>();

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "JSON")
    private Map<String, Object> originalPayload = new HashMap<>();

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "JSON")
    private Map<String, Object> redaction = new HashMap<>();

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "JSON")
    private Map<String, Object> evidenceMetadata = new HashMap<>();

    @Column(nullable = false)
    private Instant timestamp;

    @Column(nullable = false)
    private boolean legalHold = false;

    @Column
    private Instant holdPlacedAt;

    @Column(length = 1024)
    private String holdReason;

    @Column(nullable = false, length = 512)
    private String previousHash;

    @Column(nullable = false, length = 512)
    private String hash;

    @Column(nullable = false)
    private boolean archived = false;

    @Column
    private Instant archivedAt;

    protected AuditEvent() {
    }

    public AuditEvent(String eventType, String actorId, String resourceType, String resourceId,
                      Map<String, Object> payload, Instant timestamp, String previousHash, String hash) {
        this.eventType = eventType;
        this.actorId = actorId;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.payload = payload == null ? new HashMap<>() : payload;
        this.timestamp = timestamp;
        this.previousHash = previousHash;
        this.hash = hash;
    }

    public AuditEvent(String eventType, String actorId, String resourceType, String resourceId,
                      Map<String, Object> payload, String timestamp, String previousHash, String hash) {
        this(eventType, actorId, resourceType, resourceId, payload, Instant.parse(timestamp), previousHash, hash);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getActorId() {
        return actorId;
    }

    public void setActorId(String actorId) {
        this.actorId = actorId;
    }

    public String getResourceType() {
        return resourceType;
    }

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public Map<String, Object> getPayload() {
        return payload;
    }

    public void setPayload(Map<String, Object> payload) {
        this.payload = payload == null ? new HashMap<>() : payload;
    }

    public Map<String, Object> getOriginalPayload() {
        return originalPayload == null ? new HashMap<>() : originalPayload;
    }

    public void setOriginalPayload(Map<String, Object> originalPayload) {
        this.originalPayload = originalPayload == null ? new HashMap<>() : originalPayload;
    }

    public Map<String, Object> getRedaction() {
        return redaction == null ? new HashMap<>() : redaction;
    }

    public void setRedaction(Map<String, Object> redaction) {
        this.redaction = redaction == null ? new HashMap<>() : redaction;
    }

    public Map<String, Object> getEvidenceMetadata() {
        return evidenceMetadata == null ? new HashMap<>() : evidenceMetadata;
    }

    public void setEvidenceMetadata(Map<String, Object> evidenceMetadata) {
        this.evidenceMetadata = evidenceMetadata == null ? new HashMap<>() : evidenceMetadata;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public boolean isLegalHold() {
        return legalHold;
    }

    public void setLegalHold(boolean legalHold) {
        this.legalHold = legalHold;
    }

    public Instant getHoldPlacedAt() {
        return holdPlacedAt;
    }

    public void setHoldPlacedAt(Instant holdPlacedAt) {
        this.holdPlacedAt = holdPlacedAt;
    }

    public String getHoldReason() {
        return holdReason;
    }

    public void setHoldReason(String holdReason) {
        this.holdReason = holdReason;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = Instant.parse(timestamp);
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public boolean isArchived() {
        return archived;
    }

    public void setArchived(boolean archived) {
        this.archived = archived;
    }

    public Instant getArchivedAt() {
        return archivedAt;
    }

    public void setArchivedAt(Instant archivedAt) {
        this.archivedAt = archivedAt;
    }

    public void setArchivedAt(String archivedAt) {
        this.archivedAt = archivedAt == null ? null : Instant.parse(archivedAt);
    }
}
