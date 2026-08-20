package com.auditlog.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ExportResponse {
    private long recordCount;
    private List<ExportRecord> records;
    private String bundleHash;
    private Instant exportedAt;
    private String bundleAttestation;
    private String attestationAlgorithm;
    private boolean independentlyVerifiable;
    private int evidenceActionCount;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ExportRecord {
        private Long id;
        private String eventType;
        private String actorId;
        private String resourceType;
        private String resourceId;
        private Object payload;
        private Instant timestamp;
        private String previousHash;
        private String hash;
        private boolean archived;
        private Instant archivedAt;
    }
}
