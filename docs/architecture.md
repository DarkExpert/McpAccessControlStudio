# Architecture and security boundary

The .NET 10 solution has a framework-independent `Core`, an authenticated API/MCP gateway, and a seeded CRM SDK server. `AuthorizationPolicy` is the single immutable role and argument policy for both REST evaluation and MCP execution. It matches names exactly with ordinal comparison and defaults to deny. The gateway does not take role or identity from client headers or tool arguments.

```text
SDK MCP client → JWT validation at /mcp → validated subject and role
  → SDK tools/call handler → AuthorizationPolicy → catalog check → audit decision
  → SDK Streamable HTTP client → loopback CRM MCP server
  → audit terminal outcome
```

| Tool | Viewer | Operator | Admin |
| --- | --- | --- | --- |
| `crm.get_customer` | allow | allow | allow |
| `crm.list_orders` | allow | allow | allow |
| `crm.update_order` | deny | allow if amount ≤ 1000 | allow if amount ≤ 1000 |
| `crm.delete_customer` | deny | deny | allow |
| `crm.export_customers` | deny | deny | allow |

`crm.update_order` requires one nonnegative JSON decimal `amount`. Missing, malformed, duplicate, and excessive amounts are blocked before forwarding. A bounded raw JSON guard rejects duplicate properties before the SDK decodes argument objects into dictionaries. Unknown and case-mismatched tool names are denied even when called without discovery. The amount limit is a demo policy constant.

## Startup and execution

The API creates an internal CRM server bound to an ephemeral `127.0.0.1` port. Before opening the public gateway listener, it creates an official SDK `McpClient` in Streamable HTTP mode, discovers the full CRM tool catalog, and verifies the five exact names. A failed connection or invalid catalog prevents gateway startup. The internal server has seeded, non-sensitive data and in-process invocation counters for tests; there is no public CRM or counter endpoint.

`MapMcp("/mcp").RequireAuthorization()` applies the same JWT configuration as the REST endpoint. Signature, HS256 algorithm, issuer, audience, expiration and exactly one valid subject and role are checked. Authentication or policy evaluation failure denies. Only an explicit allow for a discovered name enters `CallToolAsync`; denied requests do not invoke the CRM. The SDK owns MCP framing, discovery, serialization and tool error semantics. A completed upstream tool error remains an MCP tool error. The gateway adapts completed results to the downstream protocol revision, including older revisions without structured content.

Startup discovery and each forwarded operation have ten-second budgets. The upstream HTTP client disallows redirects and system proxies. Caller cancellation is linked to the forwarding budget. The application has no retry loop, but SDK continuation can reissue an allowed upstream request. Cancellation, timeout or error **after forwarding** does not establish that no upstream side effect occurred; exactly-once execution is not guaranteed.

## M2 audit boundary

`SecurityAuditEvent` is a fixed allowlist of fields. The handler creates an opaque correlation ID for each authenticated `tools/call`, records a decision before forwarding, and records one terminal outcome in `finally`. Decision events use `Pending` enforcement and `NotAttempted` upstream status; only Terminal events report actual `Blocked` or `Forwarded` enforcement. Unknown client-supplied tool names are replaced with `UnknownTool` in storage. Denials remain blocked regardless of audit availability. `AuditRecorder` catches write failures, emits a generic warning, and never retries forwarding. Its independent two-second write budget lets it attempt a terminal record after client cancellation. A crash, storage failure or write timeout can leave incomplete pairs. JWT and raw JSON guard rejections occur before this handler and are not attributed in this audit.

`SqliteAuditStore` uses parameterized commands, per-operation connections, serialized transactional writes, a schema version, and a 20,000-row retention cap. Startup reads `PRAGMA user_version` before setting WAL mode or executing schema SQL. Unsupported versions stop startup without modifying the existing database. It creates a new file at startup; initialization failure stops the API. The local database has no encryption or built-in backup. Access to the path, WAL and SHM files must be controlled by the host. Reads use descending row IDs and a bounded cursor/limit. Admin-only REST endpoints expose sanitized records and aggregate **persisted terminal rows**. Reports are not completeness guarantees. There is no public write endpoint. The store and authorization policy have separate responsibilities.

## M3 browser boundary

`apps/studio-web` is a React + TypeScript Vite client. In the local workflow, the API binds `127.0.0.1:5077` and Vite binds `127.0.0.1:5173`. Development CORS permits only `http://127.0.0.1:5173`, only GET/POST/DELETE, and no browser credentials. CORS is absent outside Development; it is not an authentication boundary. The demo token issuer still checks the transport peer's loopback IP, not forwarded headers. Do not expose either service through a remote reverse proxy.

The browser's official MCP SDK Streamable HTTP transport calls `/mcp` with the selected identity's short-lived JWT. The gateway adds only safe `accessControlStudio` result metadata: correlation ID, decision, reason code, enforcement, and upstream status. The UI neither reconstructs policy decisions nor shows CRM response payloads. It closes the SDK client after each scenario. Tokens remain in React memory, are not placed in URLs or browser storage, and are cleared on identity change or expiry. Requests carry no cookies and reject redirects. Client cancellation and request generations prevent stale results from appearing after an identity switch.

The authenticated read-only `/api/security/policy` endpoint serializes descriptors from `AuthorizationPolicy`; it does not duplicate enforcement or permit mutation. Seeded identity labels and scenario inputs are presentation data. Global M2 reporting remains Admin-only. The UI requires an explicit, separate Admin reporting session and never substitutes that token for a Viewer or Operator tool call. When reporting is active, it looks up the MCP correlation ID in bounded audit pages to show a persisted Terminal outcome. Missing or failed audit lookup is shown as unavailable; gateway metadata still states the handler's result. Overview aggregates only persisted Terminal events.

## Security limits

The demo issuer operates only in Development for loopback transport peers, never from forwarded IP headers. A reverse proxy connecting locally would itself be a loopback peer, so do not expose the demo route through one. The signing key must be externally supplied and cryptographically random; length alone does not verify entropy. Production requires a distinct configured issuer and key, but production identity management and key rotation are not included.

The CRM listener is loopback-only, but another local process could reach it directly and bypass the gateway. Host isolation is required before using this pattern with real data. CRM data and tool schemas are demonstration content; no prompt-injection filtering exists. SDK diagnostic logging is disabled, and application code does not log bearer tokens, credentials, tool arguments or result payloads. The demo token response necessarily contains its issued token.

The REST evaluation endpoint never executes a tool. Dashboard, enterprise identity providers, multitenancy, multiple upstream servers, approvals and cloud deployment remain out of scope.
