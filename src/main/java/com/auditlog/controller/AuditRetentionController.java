package com.auditlog.controller;

import com.auditlog.service.AuditEventService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/audit")
public class AuditRetentionController {

    private final AuditEventService auditEventService;

    public AuditRetentionController(AuditEventService auditEventService) {
        this.auditEventService = auditEventService;
    }

    @PostMapping("/retention/archive")
    public Map<String, Object> archiveOldRecords(@RequestParam Instant olderThan) {
        return auditEventService.archiveOldRecords(olderThan);
    }

    @GetMapping("/events/{eventId}/redacted")
    public Map<String, Object> getRedactedEvent(@PathVariable Long eventId) {
        return auditEventService.getRedactedView(eventId);
    }

    @PostMapping("/events/{eventId}/redact")
    public Map<String, Object> redactEvent(@PathVariable Long eventId,
                                          @RequestBody Map<String, Object> request) {
        List<String> sensitiveFields = List.of();
        if (request != null && request.get("fields") instanceof List<?> rawFields) {
            sensitiveFields = rawFields.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        }
        return auditEventService.redactPayload(eventId, sensitiveFields);
    }

    @GetMapping("/export")
    public Map<String, Object> exportBundle(
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String actorId) {
        return auditEventService.exportBundle(resourceId, actorId);
    }
}
