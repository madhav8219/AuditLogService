package com.auditlog.exception;

public class InvalidAuditRequestException extends IllegalArgumentException {
    public InvalidAuditRequestException(String message) {
        super(message);
    }
}
