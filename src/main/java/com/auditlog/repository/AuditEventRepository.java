package com.auditlog.repository;

import com.auditlog.entity.AuditEvent;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long>, JpaSpecificationExecutor<AuditEvent> {
    Optional<AuditEvent> findTopByOrderByIdDesc();

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select e from AuditEvent e order by e.id desc")
    List<AuditEvent> findLatestForUpdate(Pageable pageable);

    List<AuditEvent> findAllByOrderByIdAsc();
    List<AuditEvent> findByArchivedFalseOrderByIdAsc();
    List<AuditEvent> findAllByResourceIdAndArchivedFalseOrderByIdAsc(String resourceId);
    List<AuditEvent> findAllByActorIdAndArchivedFalseOrderByIdAsc(String actorId);
    List<AuditEvent> findAllByResourceIdOrderByIdAsc(String resourceId);
    List<AuditEvent> findAllByActorIdOrderByIdAsc(String actorId);
}
