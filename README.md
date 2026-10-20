# MCP Access Control Studio

This is an **early .NET 10 reference implementation, not production ready**. M1 enforces validated JWT identity and the M0 role/argument policy inside real MCP `tools/call` requests. It is distinct from [MCP Sentinel](https://github.com/DarkExpert/mcp-sentinel); Sentinel's SDK transport, timeout and protocol tests informed this implementation without copying its gateway.

## Architecture

An SDK MCP client connects to authenticated `/mcp` over Streamable HTTP. The API validates the JWT, then the SDK call handler evaluates the exact tool name and decoded arguments with the existing `AccessControlStudio.Core.AuthorizationPolicy`. Only an explicit allow for a tool in the startup-validated CRM catalog is forwarded through an SDK client to the seeded CRM server. The CRM server listens on an ephemeral loopback port inside the API process and has no public management or counter endpoint. `/api/authorization/evaluate` remains a policy-only endpoint.

The five demo tools are `crm.get_customer`, `crm.list_orders`, `crm.update_order`, `crm.delete_customer`, and `crm.export_customers`. See [architecture](docs/architecture.md) for the role matrix, trust boundaries, and result behavior.

## One-command real MCP demo

Install .NET 10 and PowerShell 7.2+. From the repository root:

```powershell
pwsh -File ./scripts/run-demo.ps1
```

The command builds Release, launches only its own loopback API process, obtains short-lived demo JWTs for Viewer, Operator and Admin, runs real SDK discovery and tool calls, checks allow/deny outcomes, and stops its process. It generates a fresh signing key and prints no token or tool response. The first run needs NuGet access.

## Manual local API

Supply a unique **cryptographically random** signing key of at least 32 UTF-8 bytes through `Jwt__SigningKey` or user secrets. Length cannot prove entropy. Never commit the key. The demo token issuer is unauthenticated, restricted to loopback transport peers in Development, and absent outside Development. Do not expose the API or the demo route through a reverse proxy: a local proxy appears as a loopback peer even for remote users.

```powershell
$env:ASPNETCORE_ENVIRONMENT = "Development"
$env:ASPNETCORE_URLS = "http://127.0.0.1:5077"
$env:Jwt__SigningKey = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(64))
dotnet run --no-launch-profile --project src/AccessControlStudio.Api
```

Seeded demo identities are `viewer`, `operator`, and `admin`. `POST /api/demo/token` with `{"identity":"viewer"}` issues a ten-minute token to a loopback client. The token response necessarily contains the requested token; keep it private. The sample SDK client shows the MCP connection and role scenarios.

## Verify

```text
dotnet restore
dotnet build -c Release
dotnet test -c Release
pwsh -File ./scripts/run-demo.ps1
```

No React dashboard, SQLite audit, production identity provider, cloud deployment, multitenancy, approvals, or exactly-once execution guarantee is included.
