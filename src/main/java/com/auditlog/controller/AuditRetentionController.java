package com.auditlog.controller;

import com.auditlog.dto.ArchiveRequest;
import com.auditlog.dto.ArchiveResponse;
import com.auditlog.dto.ExportResponse;
import com.auditlog.dto.RedactionRequest;
import com.auditlog.dto.RedactionResponse;
import com.auditlog.exception.InvalidAuditRequestException;
import com.auditlog.service.AuditEventService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/audit")
public class AuditRetentionController {

    private final AuditEventService auditEventService;

    public AuditRetentionController(AuditEventService auditEventService) {
        this.auditEventService = auditEventService;
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'AUDIT_OFFICER')")
    @PostMapping("/retention/archive")
    public ArchiveResponse archiveOldRecords(
            @RequestParam(required = false) Instant olderThan,
            @Valid @RequestBody(required = false) ArchiveRequest request) {
        Instant cutoff = request != null ? request.getOlderThan() : olderThan;
        if (cutoff == null) {
            return auditEventService.archiveOldRecords(null);
        }
        return auditEventService.archiveOldRecords(cutoff);
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'AUDIT_OFFICER', 'SECURITY_ANALYST', 'COMPLIANCE_REVIEWER')")
    @GetMapping("/events/{eventId}/redacted")
    public Map<String, Object> getRedactedEvent(@PathVariable Long eventId) {
        return auditEventService.getRedactedView(eventId);
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @PostMapping("/events/{eventId}/redact")
    public RedactionResponse redactEvent(@PathVariable Long eventId,
                                        @Valid @RequestBody RedactionRequest request) {
        return auditEventService.redactPayload(eventId, request.getFields());
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'AUDIT_OFFICER')")
    @GetMapping("/export")
    public ExportResponse exportBundle(
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String actorId) {
        return auditEventService.exportBundle(resourceId, actorId);
    }
}
