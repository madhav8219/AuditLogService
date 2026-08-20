package com.auditlog.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "audit_chain_lock")
public class AuditChainLock {

    @Id
    @Column(nullable = false)
    private Long id = 1L;

    public AuditChainLock() {
    }

    public Long getId() {
        return id;
    }
}
