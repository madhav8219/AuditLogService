package com.auditlog.controller;

import com.auditlog.service.AuditEventService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/audit")
public class AuditComplianceController {

    private final AuditEventService auditEventService;

    public AuditComplianceController(AuditEventService auditEventService) {
        this.auditEventService = auditEventService;
    }

    @GetMapping("/compliance/account-access")
    public Map<String, Object> getAccountAccessReport(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to) {
        return auditEventService.generateAccountAccessReport(actorId, resourceId, eventType, from, to);
    }
}
