package com.auditlog.controller;

import com.auditlog.dto.AuditEventResponse;
import com.auditlog.dto.CreateAuditEventRequest;
import com.auditlog.entity.AuditEvent;
import com.auditlog.service.AuditEventService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/audit")
public class AuditEventController {

    private final AuditEventService auditEventService;

    public AuditEventController(AuditEventService auditEventService) {
        this.auditEventService = auditEventService;
    }

    @PostMapping("/events")
    public ResponseEntity<AuditEventResponse> createEvent(@Valid @RequestBody CreateAuditEventRequest request) {
        AuditEvent saved = auditEventService.createEvent(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(AuditEventResponse.fromEntity(saved));
    }

    @GetMapping("/events")
    public Page<AuditEventResponse> getEvents(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String[] sort
    ) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.max(size, 1);
        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.unsorted());
        return auditEventService.findEvents(actorId, resourceType, resourceId, eventType, from, to, pageable)
                .map(AuditEventResponse::fromEntity);
    }

    @GetMapping("/verify")
    public Map<String, Object> verify() {
        return auditEventService.verifyChain();
    }
}
