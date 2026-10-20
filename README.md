# MCP Access Control Studio

This is an **early .NET 10 reference implementation, not production ready**. M3 adds a React dashboard and real MCP Playground to M0 identity, M1 gateway enforcement and M2 SQLite auditing. It is distinct from [MCP Sentinel](https://github.com/DarkExpert/mcp-sentinel); Sentinel's SDK transport, timeout and protocol tests informed this implementation without copying its gateway.

## Architecture

An SDK MCP client connects to authenticated `/mcp` over Streamable HTTP. The API validates the JWT, then the SDK call handler evaluates the exact tool name and decoded arguments with the existing `AccessControlStudio.Core.AuthorizationPolicy`. Only an explicit allow for a tool in the startup-validated CRM catalog is forwarded through an SDK client to the seeded CRM server. The CRM server listens on an ephemeral loopback port inside the API process and has no public management or counter endpoint. `/api/authorization/evaluate` remains a policy-only endpoint.

The five demo tools are `crm.get_customer`, `crm.list_orders`, `crm.update_order`, `crm.delete_customer`, and `crm.export_customers`. See [architecture](docs/architecture.md) for the role matrix, trust boundaries, and result behavior.

## Run the Security Studio locally

Install .NET 10 and Node.js 24+. From the repository root, run one command:

```text
node scripts/run-studio.mjs
```

The command restores and builds .NET, runs `npm ci`, starts the gateway only on `127.0.0.1:5077` and Vite only on `127.0.0.1:5173`, and prints the local dashboard URL. It generates an ephemeral cryptographically random JWT signing key and stores demo audit records in the ignored `.local-data/` directory. Press Ctrl+C to stop both services. The first run needs NuGet and npm access. Keep this local Development workflow off reverse proxies and public networks.

The **Security Playground** uses the official TypeScript MCP SDK in the browser to call the actual authenticated `/mcp` Streamable HTTP endpoint. Pick Viewer, Operator or Admin and one of the predefined safe scenarios; the UI displays the gateway's decision, reason, tool-level `isError`, enforcement status and server-generated correlation ID. Successful forwarding is not an exact physical upstream invocation count. CRM payloads are hidden in the dashboard. The **Users & Roles** cards are labeled seeded demo definitions; the permission matrix comes from authenticated `GET /api/security/policy`, which reads the enforcing backend policy.

**Security Overview** and **Audit History** use the existing M2 APIs. Click **Enable Admin reporting** to acquire a separate, clearly labeled Admin reporting session. Viewer and Operator MCP calls always use their own tokens. Changing the selected identity clears both sessions and displayed results; tokens stay in browser memory and expire after ten minutes. Admin reporting credentials are never used for Viewer or Operator tool execution. Audit history distinguishes Decision/Pending from Terminal outcomes, and overview totals count persisted Terminal records only. If a Playground result has no matching persisted Terminal event, the UI says so instead of inventing one.

For screenshots, run the local workflow, execute a Playground scenario, and capture the **actual running UI** with your browser or OS screenshot tool. Do not include browser developer tools, JWT responses, or secrets in published screenshots.

## One-command real MCP demo

Install .NET 10 and PowerShell 7.2+. From the repository root:

```powershell
pwsh -File ./scripts/run-demo.ps1
```

The command builds Release, launches only its own loopback API process, obtains short-lived demo JWTs for Viewer, Operator and Admin, runs real SDK discovery and tool calls, checks allow/deny outcomes and reporting, then restarts the API to verify SQLite persistence. It generates a fresh signing key and prints no token or tool response. The first run needs NuGet access.

## Manual local API

Supply a unique **cryptographically random** signing key of at least 32 UTF-8 bytes through `Jwt__SigningKey` or user secrets. Length cannot prove entropy. Never commit the key. The demo token issuer is unauthenticated, restricted to loopback transport peers in Development, and absent outside Development. Do not expose the API or the demo route through a reverse proxy: a local proxy appears as a loopback peer even for remote users.

```powershell
$env:ASPNETCORE_ENVIRONMENT = "Development"
$env:ASPNETCORE_URLS = "http://127.0.0.1:5077"
$env:Jwt__SigningKey = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(64))
dotnet run --no-launch-profile --project src/AccessControlStudio.Api
```

Seeded demo identities are `viewer`, `operator`, and `admin`. `POST /api/demo/token` with `{"identity":"viewer"}` issues a ten-minute token to a loopback client. The token response necessarily contains the requested token; keep it private. The sample SDK client shows the MCP connection and role scenarios.

## Security audit and reporting

The API writes a decision record before forwarding and a terminal record after each authenticated MCP `tools/call` handled by the gateway. Both share a server-generated correlation ID. Decision records use `Pending` enforcement and `NotAttempted` upstream status; Terminal records state the actual `Blocked` or `Forwarded` outcome. Records contain only UTC time, validated subject and role, a known tool name (or `UnknownTool`), stable decision/reason/outcome codes, a safe error category, and duration. They contain no arguments, tokens, credentials, CRM responses, or exception text. Requests rejected by JWT authentication or the raw JSON guard do not reach the handler and have no attributed handler audit record.

SQLite defaults to `data/security-audit.db` under the API content root. Override with `Audit__DatabasePath` for a protected local directory; database, WAL and SHM files are ignored by Git. Startup reads `PRAGMA user_version` before changing the schema or journal mode and rejects unsupported versions without modifying the database. The schema has a 20,000-row rolling retention limit. Back up and protect the database with filesystem permissions. This demo does not encrypt the database or manage backups.

`GET /api/audit?limit=25&cursor=<id>` returns newest-first records and an optional `nextCursor`; limit is 1–100. `GET /api/security/overview` aggregates **persisted terminal records only**. Both require a validated Admin JWT. There is no public audit write API. An audit write failure is logged without sensitive details and does not change enforcement or retry an upstream call. Auditing is best effort: a storage failure can leave a missing decision or terminal record, so report counts are not proof of complete activity.

## Verify

```text
dotnet restore
dotnet build -c Release
dotnet test -c Release
pwsh -File ./scripts/run-demo.ps1
cd apps/studio-web
npm ci
npm test
npm run build
npx playwright install chromium
npm run e2e
```

No production identity provider, cloud deployment, multitenancy, SIEM, approvals, or exactly-once execution guarantee is included. This dashboard is a local Development showcase, not a production console.
