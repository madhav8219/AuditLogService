# Attestation

## Candidate Information

Full Name: Madhav Dhanorkar  
Email address: dhanorkar.madhav@gmail.com  
Assignment title: Build an AI-Assisted Software Engineering System — Audit Log Service  
Start date: 19-08-2026  
Submission date: 21-08-2026

## Section 0.4 — Security and Trust Attestation

This attestation records the current implementation status of the Audit Log Service with respect to authorization, authentication, evidence integrity, and operational security controls as reviewed in the source implementation and associated test coverage.

### Scope
This attestation covers the following controls:
- role-based authorization for evidence-sensitive operations
- JWT lifecycle and validation controls
- evidence integrity and verification controls
- export and redaction protections
- operational readiness of the deployment baseline

### Attestation statement
The system currently demonstrates a functional baseline for secure audit processing and role-based access control. In particular:

- JWT-based authentication is implemented and token parsing verifies signature and expiration.
- Access control is enforced at the controller layer using method-level authorization for create, read, verify, redact, archive, export, and report operations.
- The service includes evidence-chain verification logic to detect tampering and preserve audit integrity within the application boundary.
- Redaction, legal-hold, archive, and export workflows are implemented and protected by authorized role checks.
- The service includes tests covering rejected anonymous access, malformed/expired/forged JWTs, and unauthorized role attempts.

However, this attestation is limited to the current implementation status and should not be interpreted as full production-grade evidence assurance. The following residual gaps remain:

- JWT secret lifecycle is not yet hardened for production-grade key management and rotation.
- Token revocation, replay protection, and audience validation are not fully implemented.
- Resource-scoped authorization is not yet enforced beyond role-based checks.
- Secret handling is not yet fully externalized to a vault or production secret manager.
- The implementation remains dependent on application-layer controls rather than independently attested infrastructure controls.

### Conclusion
Based on the current implementation, the service is suitable for internal/demo or controlled deployment use, with a credible baseline for audit integrity and role-based security. It does not yet satisfy the full standard of a production-grade evidence system for regulated or high-assurance deployment without additional hardening, operational controls, and independent attestation measures.

### Reviewer declaration
I, Madhav Dhanorkar, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process and use of AI.

I attest that the above assessment reflects the current implementation status as reviewed in the application code and automated tests available in this repository.

Signed: Madhav Dhanorkar
Date: 2026-08-21
