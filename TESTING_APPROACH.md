# Testing Approach, Limitations, and Trade-offs

## 1. Testing approach

The project uses a mix of integration-style Spring Boot tests and targeted unit-style validation for security and audit behavior. The focus is on validating the actual service behavior end-to-end through the application stack rather than asserting only mocked outputs.

The test suite covers:

- authentication and authorization expectations
- expired, malformed, modified, and forged JWT rejection
- role-based access checks for protected endpoints
- creation and verification of audit events
- redaction behavior and legal-hold enforcement
- archive workflow and export bundle generation
- hash-chain integrity checks
- compliance report creation

The main test file is:

- `src/test/java/com/auditlog/AuditLogControllerIntegrationTest.java`

The JWT-specific tests are in:

- `src/test/java/com/auditlog/security/JwtTokenProviderTest.java`

## 2. What is covered

### Authentication and authorization

The tests verify that:

- anonymous access to protected endpoints is rejected
- non-bearer authorization headers are rejected
- blank bearer tokens are rejected
- expired JWTs are rejected
- modified JWTs are rejected
- malformed JWT strings are rejected
- valid users with valid roles can access permitted endpoints
- users without the required role receive forbidden responses

This is important because the security boundary is enforced at runtime and not only by static configuration.

### Event integrity

The tests cover:

- upload and persistence of audit events
- verification of the append-only hash chain
- detection of a broken chain after tampering or mutation
- skipping archived records during verification logic where this is part of the intended behavior

### Redaction and legal hold

The tests validate:

- redacted views mask sensitive values
- redaction metadata is stored correctly
- redaction is blocked while an event is under legal hold
- legal hold uses explicit enforcement rather than simple policy note only

### Archive and export

The tests validate:

- historical records can be archived
- export responses include metadata and attestation-like values
- export operations preserve evidence action metadata

### Compliance reporting

The suite also checks that account-access reporting can be generated and that empty results are handled correctly.

## 3. What is not covered deeply

Although the suite is useful, it does not fully cover every high-assurance production concern. For example:

- no full key rotation test for JWT secret rollover
- no replay-attack or token-reuse test for a stored `jti`
- no audit trail review for all security decisions at the operational level
- no multi-tenant or resource-scoped authorization tests beyond role checks
- no production secret manager integration tests
- no load or concurrency tests specifically for a multi-user operational environment
- no external attestation verification against an independent trust anchor

This is important because the current implementation is a prototype-grade service, not a full evidence-grade production platform.

## 4. Trade-offs in the testing strategy

### Why integration-style tests are valuable

The project prefers realistic HTTP and security flows over a pure mock-heavy testing approach. This is a good choice because the most critical behaviors are actually in the application boundaries:

- JWT parsing and validation
- Spring Security `@PreAuthorize` checks
- persistence and repository behavior
- controller request handling

Testing these behaviors in context gives much better confidence than testing internals in isolation.

### Why some coverage remains limited

The implementation deliberately keeps a relatively light operational model. This reduces complexity and keeps the prototype runnable, but it also means the test suite does not yet reflect enterprise-level concerns such as:

- token revocation and blacklist handling
- key rotation pipelines
- signed export validation outside the application
- formal security incident response workflows

### Why this is acceptable for the current stage

The service is designed as a prototype that demonstrates:

- append-only evidence handling
- chain verification
- role-bound access control
- redaction and legal hold constraints

This is a valid and important technical scope for assignment work. The cost of broader enterprise security testing would be much higher, and it would not be justified unless the system is being positioned as a production evidence platform.

## 5. Core limitation of the current tests

The most important limitation is that the tests check the service’s internal trust model, not an externally independent trust anchor. In other words:

- the hash chain is validated by the same application logic that stores and reads the records
- JWT validation is performed by the same software stack that issues and consumes tokens
- authorization checks are enforced inside the service boundary

This is strong for internal correctness and validation, but it is not the same as independent, third-party attestation. That is still a design gap for regulated or evidence-sensitive production use.

## 6. Summary

The current tests provide credible coverage for the system’s core functional claims:

- authn/authz behavior
- event creation and integrity verification
- redaction and legal hold
- export and archive logic

However, the suite does not yet cover the full production-hardening envelope required for a regulated evidence system. The reasons are practical and architectural: the service is intentionally designed as a working prototype with a strong internal integrity model and a lighter operational security footprint.

This is a sensible trade-off for the current project stage, but it should be clearly acknowledged in any formal review or production-readiness assessment.
