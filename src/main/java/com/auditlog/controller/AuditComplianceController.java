package com.auditlog.controller;

import com.auditlog.dto.ComplianceReportResponse;
import com.auditlog.exception.InvalidAuditRequestException;
import com.auditlog.service.AuditEventService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequestMapping("/audit")
public class AuditComplianceController {

    private final AuditEventService auditEventService;

    public AuditComplianceController(AuditEventService auditEventService) {
        this.auditEventService = auditEventService;
    }

    @GetMapping("/compliance/account-access")
    public ComplianceReportResponse getAccountAccessReport(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to) {
        if (from != null && to != null && from.isAfter(to)) {
            throw new InvalidAuditRequestException("from must be before to");
        }
        return auditEventService.generateAccountAccessReport(actorId, resourceId, eventType, from, to);
    }
}
