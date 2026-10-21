# Threat model — v0.1.0 release candidate

This model covers the local Development showcase. It is a design review, not a penetration test or production security certification.

## Assets and trust boundaries

Assets are JWT signing material, short-lived identity tokens, authorization decisions, seeded CRM data, and sanitized SQLite audit records. A browser and any MCP client are untrusted. The .NET gateway is the authorization boundary. It validates JWT signature, algorithm, issuer, audience, lifetime, and single subject/role claims before a protected handler. `AuthorizationPolicy` then defaults to Deny and checks exact tool names and arguments. Only allowed calls reach the internal CRM MCP SDK client.

The CRM server is bound to an ephemeral loopback port, and the SQLite database is a local file. The browser's Admin reporting credential accesses only read-only reporting endpoints; Playground execution uses the selected identity's credential. Development CORS permits one exact loopback origin, but origin policy is not a substitute for authentication.

## Threats and current controls

| Threat | Current control | Residual risk |
| --- | --- | --- |
| Forged role in headers, arguments or a malformed JWT | Identity comes only from a validated JWT; duplicate subject/role and undefined roles fail closed; tool arguments never grant roles. | The Development demo issuer lets any loopback peer request any seeded identity. |
| Unknown tool or policy bypass | Exact-name catalog check and shared default-deny policy run inside `tools/call` before forwarding; denied calls have zero upstream invocations in regression tests. | A local process can call the loopback CRM server directly and bypass the gateway. Host isolation is required for real data. |
| Remote use of demo issuer | Issuer exists only in Development, checks the transport peer's loopback address, and ignores forwarded IP headers. | A reverse proxy on the same host appears as a loopback peer. Do not expose the demo issuer or Vite through one. |
| Browser token exposure or cross-origin call | Tokens remain in memory, never in URLs or storage; requests omit cookies and reject redirects; CORS is exact to `http://127.0.0.1:5173`. | XSS or a compromised local browser process could read the in-memory token. No production browser security program is claimed. |
| Audit data disclosure | Admin-only reporting, bounded pagination, opaque correlation ID validation and allowlisted Terminal metadata; no public write API. | SQLite, WAL and SHM files have no application-layer encryption. Host permissions and backups are operator responsibilities. |
| Audit gap or misleading totals | Decision and Terminal events use stable codes; reports aggregate persisted Terminal rows only; write failures do not alter enforcement. | Audit is best effort. Crash, timeout or storage failure can omit either event. Counts are not proof of completeness. |
| Retry, cancellation or timeout after forwarding | Caller cancellation and upstream budget are linked; the app does not add a retry loop. | The SDK may continue or reissue a permitted call. A canceled response does not establish that no upstream side effect occurred; no exactly-once guarantee. |
| Sensitive data in logs, API or showcase assets | Audit model allowlists metadata; errors and application warnings omit exception detail; dashboard hides CRM payloads; screenshots are captured without developer tools. | Operational logs from external infrastructure and host-level traces are outside this demonstration's control. |

## Review before any production adaptation

Replace the demo issuer with a real identity provider and key lifecycle, isolate the CRM upstream from other local processes, secure the database and backups, review SDK behavior and dependency updates, define audit completeness/retention guarantees, add deployment controls, and perform an independent security review. These are future work, not v0.1.0 features.
