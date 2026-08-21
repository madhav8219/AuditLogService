# Three execution scenarios

This document describes three representative scenarios for the Audit Log Service. Each scenario is structured in the same way:

1. decomposition
2. execution
3. validation

---

## Scenario A — Create and verify a normal audit event

### Decomposition

A user creates a standard audit event representing a business action, such as a user login or a resource access event. The service must:

- accept the event payload
- infer the event metadata
- compute the event hash using the current chain state
- persist the event with the previous hash and new hash
- retain the original payload for verification purposes

### Execution

1. A caller sends a request to `POST /audit/events` with a JSON payload.
2. The controller validates the request and delegates to `AuditEventService.createEvent(...)`.
3. The service computes a canonical payload representation and checks whether the event is a duplicate of an existing record.
4. It loads the latest record in the chain and sets the previous hash to the latest known hash.
5. It builds the hash input from:
   - event type
   - actor ID
   - resource type
   - resource ID
   - timestamp
   - canonicalized payload
   - previous hash
6. It stores the new `AuditEvent` with `previousHash`, `hash`, and the payload.

### Validation

1. A caller invokes `GET /audit/verify`.
2. The service iterates over the events in ascending ID order.
3. It recalculates the expected hash for each event using the same canonicalized payload and previous hash logic.
4. It compares the expected hash with the stored hash.
5. If every record matches, the response reports the chain as intact.

Expected result:

- `intact = true`
- `firstBrokenRecordId = null`
- `violationType = null`

---

## Scenario B — Redaction under a legal-hold boundary

### Decomposition

A sensitive record is created, later placed under legal hold, and then a redaction attempt is made. The system must enforce the business rule that evidence under legal hold cannot be mutated.

### Execution

1. A user creates a record using `POST /audit/events`.
2. An authorized user calls `POST /audit/events/{eventId}/hold` with a reason.
3. The service sets `legalHold = true` and stores `holdPlacedAt` and `holdReason`.
4. An attempted redaction is made with `POST /audit/events/{eventId}/redact`.
5. The service checks whether the event is under legal hold before modifying the payload.
6. Because the record is on hold, it throws an `EvidenceLockException` and rejects the change.

### Validation

1. The API response returns a failure status and an error indicating the event is locked.
2. The underlying event remains unchanged.
3. The stored `hash` and `previousHash` values remain consistent with the audit chain.
4. The service does not permit a mutation that would invalidate chain integrity while legal hold is active.

Expected result:

- redaction is blocked
- event payload is unchanged
- integrity remains intact
- legal hold remains active

---

## Scenario C — Archive and export of evidence with attestation metadata

### Decomposition

An older event is eligible for archival. The system must archive the record only if it is not under hold and is older than the retention cutoff. The archived record should then be represented in an export bundle that includes attestation metadata.

### Execution

1. An authorized user calls `POST /audit/retention/archive?olderThan=<cutoff>`.
2. The service filters all events and selects records that are:
   - not archived
   - not under legal hold
   - older than the effective cutoff
3. For each eligible event it marks the record as archived and records `archivedAt`.
4. It appends evidence metadata for the archive action to the event.
5. An authorized user later calls `GET /audit/export`.
6. The export service gathers the relevant records, validates the current chain integrity, and prepares a bundle with:
   - exported record list
   - bundle hash
   - attestation algorithm label
   - evidence action count
   - timestamp

### Validation

1. The archive response reports the number of archived records and their IDs.
2. The export response includes a non-empty `bundleAttestation` and `attestationAlgorithm` value.
3. The service verifies chain integrity before generating a bundle, and it indicates whether the chain is independently verifiable.
4. Any export reflects the current audit evidence state and preserves metadata for later review.

Expected result:

- archived records are marked as archived
- archive actions are evidence-logged
- export contains attestation metadata
- verification can confirm the returned evidence bundle is consistent with the stored chain

---

## Cross-scenario observations

These three scenarios demonstrate the system’s core pattern:

- create and verify events
- protect mutation under legal hold
- preserve chain integrity during archive/export workflows

Across all scenarios, the system relies on the same underlying principles:

- canonical payload hashing
- previous-hash chaining
- event-level metadata for redaction, legal hold, archive, and export
- role-based access control for security-sensitive actions

This gives the service a consistent and testable decision path from input to validation.
