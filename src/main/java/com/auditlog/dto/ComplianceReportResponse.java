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
public class ComplianceReportResponse {
    private long recordCount;
    private List<ComplianceReportRecord> records;
    private Instant generatedAt;
    private Filters filters;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Filters {
        private String actorId;
        private String resourceId;
        private String eventType;
        private Instant from;
        private Instant to;
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ComplianceReportRecord {
        private Long id;
        private Instant timestamp;
        private String actorId;
        private String resourceType;
        private String resourceId;
        private String eventType;
        private boolean redacted;
        private String hash;
    }
}
