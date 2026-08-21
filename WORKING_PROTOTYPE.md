# Working Prototype — Runnable End-to-End

## Overview

This project is a runnable Spring Boot prototype for an audit-log and evidence service. It supports:

- JWT-based authentication and role-based access control
- creation of tamper-evident audit events
- hash-chain verification and integrity checks
- legal-hold enforcement on sensitive records
- retention and archival workflows
- redaction of configured sensitive fields
- export of attested audit bundles
- compliance/account-access reporting
- OpenAPI-based API documentation

## Current implementation scope

This repository currently contains the following working behaviors:

- JWT generation and parsing with signature verification and expiration enforcement
- `@PreAuthorize` checks on protected endpoints
- event creation, event listing, and verification APIs
- redaction and legal hold workflows
- archive workflow for historical records
- export bundle generation with attestation metadata
- account-access compliance reporting
- automated integration and security tests

## Prerequisites

Before running the prototype, install:

- Java 17+
- Maven 3.9+
- MySQL 8.x or a reachable MySQL instance
- Git
- A terminal such as PowerShell, bash, or zsh

## 1) Clone and enter the project

```bash
git clone <repository-url>
cd AuditLogService
```

## 2) Configure environment variables

Set the following environment variables before starting the app.

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

> Note: Do not hardcode real secrets into source-controlled files. Use environment variables or a secret manager in deployment.

## 3) Prepare the database

Create the database and grant access:

```sql
CREATE DATABASE audit_log;
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'your-strong-password';
GRANT ALL PRIVILEGES ON audit_log.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;
```

The application is configured with JPA `ddl-auto=update`, so required schema objects will be generated automatically on startup.

## 4) Build the project

From the project root:

```bash
mvn clean package
```

If you want to run only the test suite:

```bash
mvn test
```

## 5) Run the application

```bash
mvn spring-boot:run
```

The app starts on:

```text
http://localhost:8080
```

## 6) Access Swagger / API docs

```text
http://localhost:8080/swagger-ui/index.html
```

OpenAPI docs:

```text
http://localhost:8080/v3/api-docs
```

## 7) Obtain a JWT token

The service includes a public token endpoint:

```http
POST /auth/token
```

Sample body:

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

Use the returned token as:

```http
Authorization: Bearer <jwt-token>
```

## 8) Example end-to-end workflow

### Create an audit event

```http
POST /audit/events
Authorization: Bearer <jwt-token>
Content-Type: application/json
```

Request body:

```json
{
  "eventType": "USER_LOGIN",
  "actorId": "user-1",
  "resourceType": "USER",
  "resourceId": "user-123",
  "payload": {
    "ipAddress": "10.0.0.1",
    "device": "desktop"
  }
}
```

### List audit events

```http
GET /audit/events?page=0&size=10
Authorization: Bearer <jwt-token>
```

### Verify the chain

```http
GET /audit/verify
Authorization: Bearer <jwt-token>
```

### View a redacted record

```http
GET /audit/events/1/redacted
Authorization: Bearer <jwt-token>
```

### Redact a configured field

```http
POST /audit/events/1/redact
Authorization: Bearer <jwt-token>
Content-Type: application/json
```

Body:

```json
{
  "fields": ["customerId"]
}
```

### Place a legal hold

```http
POST /audit/events/1/hold
Authorization: Bearer <jwt-token>
Content-Type: application/json
```

Body:

```json
{
  "reason": "Legal review"
}
```

### Archive historical records

```http
POST /audit/retention/archive?olderThan=2026-08-19T00:00:00Z
Authorization: Bearer <jwt-token>
```

### Export an attested bundle

```http
GET /audit/export
Authorization: Bearer <jwt-token>
```

### Generate an account access report

```http
GET /audit/compliance/account-access?actorId=user-1
Authorization: Bearer <jwt-token>
```

## 9) Supported roles

The current implementation defines these roles:

- ADMIN
- AUDIT_OFFICER
- SECURITY_ANALYST
- COMPLIANCE_REVIEWER
- SERVICE_ACCOUNT

Access is enforced with controller-level `@PreAuthorize` rules.

## 10) Test profile and validation

The project includes a test profile using H2. This is useful for quick validation without a live MySQL instance.

### Test environment variables

```powershell
$env:TEST_DB_URL = "jdbc:h2:mem:auditdb;MODE=MYSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
$env:TEST_DB_USERNAME = "sa"
$env:TEST_DB_PASSWORD = ""
$env:TEST_JWT_SECRET = "test-secret-key-123456789012345678901234567890"
$env:TEST_JWT_EXPIRATION_MS = "3600000"
```

Run the tests:

```bash
mvn test
```

## 11) Known prototype caveats

This project is a working prototype and currently still has production-hardening gaps, including:

- no explicit JWT secret rotation strategy
- no token revocation/replay protection model
- no full resource-scoped authorization beyond role checks
- secret management still depends on environment configuration rather than a dedicated secret manager

These limitations are documented in the project review files under `docs/` and in the attestation documents.

## 12) Relevant project files

- `pom.xml` — Maven configuration and dependencies
- `src/main/resources/application.properties` — runtime config
- `src/main/java/com/auditlog/security/*` — JWT and security configuration
- `src/main/java/com/auditlog/controller/*` — protected endpoints
- `src/main/java/com/auditlog/service/AuditEventService.java` — audit logic and verification
- `docs/` — policy, compliance, and readiness reviews
- `ATTESTATION.md` — evidence and submission attestation
- `WORKING_PROTOTYPE.md` — this guide

## 13) Quick start summary

```bash
mvn clean package
mvn spring-boot:run
```

Then open:

```text
http://localhost:8080/swagger-ui/index.html
```

Generate a token through `/auth/token`, then use it as a Bearer token for the protected endpoints.


## 12) Relevant project files

- `pom.xml` — Maven configuration and dependencies
- `src/main/resources/application.properties` — runtime config
- `src/main/java/com/auditlog/security/*` — JWT and security config
- `src/main/java/com/auditlog/controller/*` — API endpoints
- `src/main/java/com/auditlog/service/AuditEventService.java` — business logic and integrity checks
- `docs/` — compliance, security, and audit review notes

## 13) Quick start summary

```bash
mvn clean package
mvn spring-boot:run
```

Then open:

```text
http://localhost:8080/swagger-ui/index.html
```

Use `/auth/token` to generate a JWT, then call the protected audit endpoints with `Authorization: Bearer ...`.
