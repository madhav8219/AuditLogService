package com.auditlog.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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
public class CreateAuditEventRequest {
    @NotBlank
    private String eventType;

    @NotBlank
    private String actorId;

    @NotBlank
    private String resourceType;

    @NotBlank
    private String resourceId;

    @NotNull
    private Map<String, Object> payload;

    @NotNull
    private Instant timestamp;
}
