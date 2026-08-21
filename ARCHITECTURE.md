# Architecture Overview

## 1. System purpose

The Audit Log Service is a Spring Boot application that stores audit events in a tamper-evident form and provides role-controlled access to read, verify, redact, archive, export, and report on those events. The core design goal is to provide application-level audit integrity without depending on an external blockchain or immutable storage layer.

The system is built around three core ideas:

- append-only audit history
- hash-chain integrity verification
- controlled access to evidence actions

## 2. High-level component overview

### API layer

The API layer is implemented with Spring MVC controllers under the `com.auditlog.controller` package.

Key controllers:

- `AuditEventController` — event creation, listing, and verification endpoints
- `AuditRetentionController` — archive, redaction, redacted view, export, and legal-hold endpoints
- `AuditComplianceController` — compliance reporting endpoint
- `AuthController` — JWT issuance for authenticated clients

Responsibilities:

- accept HTTP requests
- validate input data
- enforce security with `@PreAuthorize`
- delegate business logic to the service layer

### Security layer

Security is handled by:

- `SecurityConfig` — HTTP security configuration, stateless session setup, 401/403 handlers, and JWT filter registration
- `JwtAuthenticationFilter` — reads bearer tokens and populates the Spring Security context
- `JwtTokenProvider` — generates and validates signed JWTs and extracts roles

Key design decisions:

- stateless authentication using bearer tokens
- role-based access control at method level
- JWT claims include subject and roles
- all protected routes require authentication by default

### Domain and persistence layer

Core domain objects:

- `AuditEvent` — stores event metadata, payload, redaction metadata, legal-hold state, and hash values
- `AuditChainLock` — provides a lock for coordinating chain updates

Repositories:

- `AuditEventRepository`
- `AuditChainLockRepository`

Persistence is handled through Spring Data JPA and MySQL in runtime configuration, with H2 used for tests.

### Service layer

The main orchestration logic lives in `AuditEventService`.

Responsibilities:

- create events
- detect duplicate events based on a canonical payload fingerprint
- compute a cryptographic hash using prior-chain state
- verify chain integrity over all record IDs in ascending order
- archive old records
- redact sensitive data
- apply legal hold and block mutation while the record is on hold
- export attested bundles
- generate compliance/account-access reports

## 3. Data model

### AuditEvent

The `AuditEvent` entity stores the following core fields:

- `id` — numeric primary key
- `eventType` — classification of the event
- `actorId` — actor or subject generating the action
- `resourceType` — category of resource
- `resourceId` — concrete resource identifier
- `payload` — original event data
- `originalPayload` — preserved payload for verification and redaction logic
- `redaction` — metadata for fields that were redacted
- `evidenceMetadata` — metadata about evidence-related actions
- `timestamp` — event time in UTC instant form
- `legalHold` / `holdPlacedAt` / `holdReason` — legal hold state
- `previousHash` — previous event hash in the chain
- `hash` — current event hash
- `archived` / `archivedAt` — retention status

Important modeling choice:

- The event payload uses JSON columns for flexible storage.
- The service preserves both the original payload and redacted output metadata, which allows controlled access without losing evidence traceability.

### Hash and integrity design

Each event hash is computed as:

- eventType
- actorId
- resourceType
- resourceId
- timestamp
- canonicalized payload
- previous hash

This creates a linked chain where each record depends on the immediately previous record. The `previousHash` field anchors sequence order and prevents reordering or silent mutation.

The verification process checks:

1. the hash of each event against its actual content and prior hash
2. whether the stored `previousHash` matches the chain state
3. whether any broken record is detected before the chain ends

If any mismatch is found, the verification result reports a violation and the first broken record ID.

## 4. API design

The service exposes a REST API under the `/audit` base path, with authentication required for protected routes.

### Authentication API

- `POST /auth/token`
  - authenticates a user and returns a JWT

### Event APIs

- `POST /audit/events`
  - creates a new event
- `GET /audit/events`
  - lists filtered and paginated events
- `GET /audit/verify`
  - verifies the event hash chain

### Retention and redaction APIs

- `POST /audit/retention/archive`
  - archives records older than a cutoff
- `GET /audit/events/{eventId}/redacted`
  - returns a redacted-safe representation
- `POST /audit/events/{eventId}/redact`
  - redacts configured sensitive fields
- `POST /audit/events/{eventId}/hold`
  - places a legal hold

### Compliance and export APIs

- `GET /audit/compliance/account-access`
  - generates an access report
- `GET /audit/export`
  - exports an attested bundle

### API style decisions

- RESTful resource naming is used consistently
- JSON bodies are used for create and update operations
- query parameters are used for filtering and pagination
- JWT bearer tokens are used for stateless identity propagation

## 5. Security model

### Authentication

Authentication is implemented using JWTs:

- token generation occurs in `JwtTokenProvider.generateToken`
- token parsing verifies signatures and expiration
- the `JwtAuthenticationFilter` populates the Spring security context from the bearer token

### Authorization

Authorization is enforced by controller-level `@PreAuthorize` checks such as:

- ADMIN and SERVICE_ACCOUNT may create events
- ADMIN, AUDIT_OFFICER, SECURITY_ANALYST, and COMPLIANCE_REVIEWER may read audit events
- ADMIN, AUDIT_OFFICER, and SECURITY_ANALYST may verify the chain
- ADMIN and SECURITY_ANALYST may redact sensitive fields
- ADMIN and AUDIT_OFFICER may archive and export
- ADMIN, AUDIT_OFFICER, and COMPLIANCE_REVIEWER may access compliance reporting

This creates a role-based access layer over the application and is appropriate for a prototype or controlled deployment.

## 6. Hash algorithm choice and chain design

### Hash algorithm

The implementation uses SHA-256 via Java `MessageDigest`.

Why this choice fits the current prototype:

- SHA-256 is a widely used, fast, well-understood cryptographic hash
- it is easy to implement and validate in a Java service
- it provides a strong integrity signal for append-only audit records
- it is sufficient for an application-level evidence chain in a controlled environment

### Chain design

The chain is implemented as a simple append-only linked record structure:

- newest record stores the hash of the preceding record in `previousHash`
- the current record computes a new hash based on its own content and previous hash
- verification iterates across all records in strict ID order
- it detects if the chain has been altered, reordered, or tampered with

Trade-offs:

- Advantages:
  - simple to reason about and implement
  - easy to inspect and debug
  - suitable for a prototype and internal audit workflows
- Limitations:
  - it is not a cryptographically independent attestation system
  - it protects only against application-level tampering in this service boundary
  - it does not provide external witness or signing integrity against database-level attacks
  - it does not implement replay protection or token revocation for JWTs

This means the chain is strong for internal integrity checks, but not for a fully independent evidence-trust model.

## 7. Redaction and legal-hold model

### Redaction

The audit service supports field-level redaction based on a configured sensitive field list in `AuditPolicyProperties`.

Process:

- sensitive fields are identified by name
- values are replaced in the exposed payload with `[REDACTED]`
- original value hashes are preserved in redaction metadata
- the redaction metadata is stored in the event for review and traceability

### Legal hold

The system includes a legal-hold mechanism:

- `legalHold` is set on an event
- `holdPlacedAt` and `holdReason` are stored
- mutating actions such as redaction are blocked while the hold is active
- this prevents unauthorized changes to evidence during legal review

This is a practical compromise between functional control and audit safety.

## 8. Export and attestation model

The export flow creates a bundle from audit records and includes:

- exported record list
- bundle hash
- attestation metadata
- evidence action count
- attestation algorithm label

The design is intended to provide a verifiable exported snapshot of the audit trail. It is not a full external signature model, but it gives the system a stronger evidence export posture than a raw dump alone.

## 9. Key decisions and trade-offs

### Decision: use Spring Boot + JPA + MySQL

Why:

- rapid application development
- straightforward persistence and transaction support
- easy integration with role-based security and REST controllers

Trade-off:

- strong application-layer features, but still dependent on infrastructure controls for full evidence assurance

### Decision: use JWT bearer auth with role claims

Why:

- stateless and simple for service-to-service or client-to-service usage
- aligned with the current architecture and APIs
- minimal server-side session storage

Trade-off:

- requires strong secret management and token lifecycle controls to be production-safe

### Decision: keep integrity logic in the application layer

Why:

- the service is self-contained and easier to test
- it avoids external infrastructure complexity in the prototype stage

Trade-off:

- not the strongest independent attestation model for production evidence handling

### Decision: store both original and redacted payload state

Why:

- preserves evidence while allowing controlled exposure
- supports investigations and compliance review

Trade-off:

- adds schema and business complexity
- must be carefully governed to avoid accidental leakage

## 10. Architectural summary

The system is best understood as a prototype-grade audit evidence service with a solid internal integrity model. It is structured around a Spring Boot REST API, a JPA-backed audit event store, JWT authentication, and a hash-linked record chain. This makes it effective for controlled internal uses, verification workflows, and policy-based audit operations.

The main architectural limitation is that the trust boundary remains within the application itself. For regulated or high-assurance evidence handling, the service would need stronger external attestation, stronger key lifecycle controls, and a more formal authorization model than simple role checks.
