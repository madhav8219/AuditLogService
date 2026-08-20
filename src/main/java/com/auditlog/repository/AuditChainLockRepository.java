package com.auditlog.repository;

import com.auditlog.entity.AuditChainLock;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface AuditChainLockRepository extends JpaRepository<AuditChainLock, Long> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select l from AuditChainLock l where l.id = :id")
    Optional<AuditChainLock> findByIdForUpdate(Long id);
}
