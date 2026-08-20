package com.auditlog.repository;

import com.auditlog.entity.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.List;
import java.util.Optional;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long>, JpaSpecificationExecutor<AuditEvent> {
    Optional<AuditEvent> findTopByOrderByIdDesc();
    List<AuditEvent> findAllByOrderByIdAsc();
    List<AuditEvent> findByArchivedFalseOrderByIdAsc();
    List<AuditEvent> findAllByResourceIdAndArchivedFalseOrderByIdAsc(String resourceId);
    List<AuditEvent> findAllByActorIdAndArchivedFalseOrderByIdAsc(String actorId);
    List<AuditEvent> findAllByResourceIdOrderByIdAsc(String resourceId);
    List<AuditEvent> findAllByActorIdOrderByIdAsc(String actorId);
}
