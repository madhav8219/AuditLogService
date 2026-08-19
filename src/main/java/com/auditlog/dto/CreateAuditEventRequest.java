package com.auditlog.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.util.Map;

public record CreateAuditEventRequest(
        @NotBlank String eventType,
        @NotBlank String actorId,
        @NotBlank String resourceType,
        @NotBlank String resourceId,
        @NotNull Map<String, Object> payload,
        @NotNull Instant timestamp
) {
}
