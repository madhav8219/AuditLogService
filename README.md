# Audit Log Service

A Spring Boot 3 application for tamper-evident audit event processing, hash-chain verification, retention, redaction, export, and RBAC-protected compliance operations.

## Overview

This project implements an internal audit trail service for evidence-grade event tracking. It supports:

- creating append-only audit events
- maintaining hash-chain integrity across event history
- verifying chain integrity and detecting tampering
- redacting configured sensitive fields from read views
- legal-hold enforcement on sensitive records
- archival of historical records
- exporting attested bundles with metadata
- generating access/compliance reports
- JWT-based authentication with role-based authorization

## Current implementation status

This repository currently includes:

- JWT authentication and filter-based authorization
- controller-level `@PreAuthorize` checks for protected endpoints
- MySQL-backed JPA persistence
- H2 test profile for automated integration tests
- hash-chain verification logic in the service layer
- redaction and legal-hold workflow logic
- export attestation metadata and evidence-action counts
- OpenAPI / Swagger endpoints for API documentation

## Tech stack

- Java 17
- Spring Boot 3.x
- Spring Security
- JJWT for JWT handling
- Spring Data JPA
- MySQL (runtime database)
- H2 (test database)
- Springdoc OpenAPI / Swagger UI
- Maven

## Project structure

- `src/main/java/com/auditlog` — application code
- `src/test/java/com/auditlog` — integration and security tests
- `src/main/resources` — runtime config files
- `src/test/resources` — test config files
- `docs/` — design, audit, and security review documents
- `WORKING_PROTOTYPE.md` — end-to-end local setup and usage guide
- `ATTESTATION.md` — attestation for the submission

## Prerequisites

- Java 17+
- Maven 3.9+
- MySQL 8.x or a reachable MySQL instance
- A terminal environment such as PowerShell, bash, or zsh

## Environment variables

Set the following environment variables before starting the service.

### PowerShell

```powershell
$env:DB_URL = "jdbc:mysql://localhost:3306/audit_log?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
$env:DB_USERNAME = "app_user"
$env:DB_PASSWORD = "your-strong-password"
$env:JWT_SECRET = "replace-with-a-long-random-secret"
$env:JWT_EXPIRATION_MS = "3600000"
```

### Bash / zsh

```bash
export DB_URL="jdbc:mysql://localhost:3306/audit_log?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
export DB_USERNAME="app_user"
export DB_PASSWORD="your-strong-password"
export JWT_SECRET="replace-with-a-long-random-secret"
export JWT_EXPIRATION_MS="3600000"
```

### Test profile

```powershell
$env:TEST_DB_URL = "jdbc:h2:mem:auditdb;MODE=MYSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
$env:TEST_DB_USERNAME = "sa"
$env:TEST_DB_PASSWORD = ""
$env:TEST_JWT_SECRET = "test-secret-key-123456789012345678901234567890"
$env:TEST_JWT_EXPIRATION_MS = "3600000"
```

## Database setup

Create a MySQL database and grant privileges:

```sql
CREATE DATABASE audit_log;
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'your-strong-password';
GRANT ALL PRIVILEGES ON audit_log.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;
```

The app uses `spring.jpa.hibernate.ddl-auto=update`, so schema tables are created automatically when the app starts.

## Build and run

### Build

```bash
mvn clean package
```

### Run the application

```bash
mvn spring-boot:run
```

The service starts on:

```text
http://localhost:8080
```

## Swagger / API documentation

Open the Swagger UI here:

```text
http://localhost:8080/swagger-ui/index.html
```

OpenAPI JSON can be accessed at:

```text
http://localhost:8080/v3/api-docs
```

## Authentication and authorization

The service uses JWT-based authentication with method-level role validation.

### Public endpoint

```http
POST /auth/token
```

Example request body:

```json
{
  "username": "admin-user",
  "password": "your-password"
}
```

Example response:

```json
{
  "token": "<jwt-token>"
}
```

Use the value as:

```http
Authorization: Bearer <jwt-token>
```

### Supported roles

- ADMIN
- AUDIT_OFFICER
- SECURITY_ANALYST
- COMPLIANCE_REVIEWER
- SERVICE_ACCOUNT

### Role and permission matrix

| Role | Create event | Read events | Verify chain | View redacted | Redact | Archive | Export | Legal hold | Compliance report |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ADMIN | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| AUDIT_OFFICER | No | Yes | Yes | Yes | No | Yes | Yes | Yes | Yes |
| SECURITY_ANALYST | No | Yes | Yes | Yes | Yes | No | No | No | No |
| COMPLIANCE_REVIEWER | No | Yes | No | Yes | No | No | No | No | Yes |
| SERVICE_ACCOUNT | Yes | No | No | No | No | No | No | No | No |

This matrix reflects the current `@PreAuthorize` rules implemented in the controllers:

- `POST /audit/events` — `hasAnyRole('ADMIN', 'SERVICE_ACCOUNT')`
- `GET /audit/events` — `hasAnyRole('ADMIN', 'AUDIT_OFFICER', 'SECURITY_ANALYST', 'COMPLIANCE_REVIEWER')`
- `GET /audit/verify` — `hasAnyRole('ADMIN', 'AUDIT_OFFICER', 'SECURITY_ANALYST')`
- `GET /audit/events/{eventId}/redacted` — `hasAnyRole('ADMIN', 'AUDIT_OFFICER', 'SECURITY_ANALYST', 'COMPLIANCE_REVIEWER')`
- `POST /audit/events/{eventId}/redact` — `hasAnyRole('ADMIN', 'SECURITY_ANALYST')`
- `POST /audit/retention/archive` — `hasAnyRole('ADMIN', 'AUDIT_OFFICER')`
- `GET /audit/export` — `hasAnyRole('ADMIN', 'AUDIT_OFFICER')`
- `POST /audit/events/{eventId}/hold` — `hasAnyRole('ADMIN', 'AUDIT_OFFICER')`
- `GET /audit/compliance/account-access` — `hasAnyRole('ADMIN', 'AUDIT_OFFICER', 'COMPLIANCE_REVIEWER')`

## API summary

### Audit event endpoints

- `POST /audit/events` — create an event
- `GET /audit/events` — list events with filters and pagination
- `GET /audit/verify` — verify the hash chain integrity

### Redaction and legal hold

- `GET /audit/events/{eventId}/redacted` — view a redacted version of an event
- `POST /audit/events/{eventId}/redact` — redact sensitive fields
- `POST /audit/events/{eventId}/hold` — place a legal hold

### Retention and archive

- `POST /audit/retention/archive` — archive old records

### Compliance and export

- `GET /audit/compliance/account-access` — generate an account access report
- `GET /audit/export` — export an attested evidence bundle

## Security notes

The current implementation includes:

- BCrypt password handling in the user service path
- JWT signature verification and expiration checks
- filter-based authentication extraction
- endpoint-level authorization via `@PreAuthorize`
- evidence-action metadata tracking for archive / redaction / export actions
- API error handling for unauthorized and forbidden responses

Important caveat:

- This is a prototype and the project notes still identify production hardening gaps such as secret rotation, stronger token lifecycle controls, replay protection, and resource-scoped authorization.

## Testing

Run the full test suite:

```bash
mvn test
```

## Useful docs

- `WORKING_PROTOTYPE.md` — local setup and end-to-end run instructions
- `ATTESTATION.md` — attestation for security and submission status
- `docs/formal-compliance-note.md` — review note and compliance posture
- `docs/production-readiness-review.md` — production readiness analysis
- `docs/audit-evidence-production-checklist.md` — evidence checklist
- `docs/authorization-security-policy.md` — RBAC policy guidance

## Notes

- Use strong environment-managed secrets in real deployments.
- Keep the database credentials and JWT secret out of source control.
- Prefer database migration tooling for production schema changes.
- This implementation is suitable for prototype/demo and controlled internal validation, but not yet a fully hardened production evidence system.

## License

This project is intended for internal educational or prototype usage unless otherwise specified.
