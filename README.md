# MCP Access Control Studio

This is an **early reference implementation, not production ready**. Milestone M0 provides identity-aware policy evaluation. It does not execute MCP tools or protect an MCP server. Authentication happens only at the API boundary; the next milestone must enforce identity and decisions in the actual MCP gateway. This project is separate from [MCP Sentinel](https://github.com/DarkExpert/mcp-sentinel), whose fail-closed and exact-name policy patterns informed this foundation.

## Architecture

- `AccessControlStudio.Core`: framework-independent, immutable role and tool policy. Unknown tools default to deny. Tool names use exact, case-sensitive ordinal matching.
- `AccessControlStudio.Api`: validates signed HS256 JWTs and derives subject and role exclusively from validated claims. `POST /api/authorization/evaluate` evaluates a request; it never executes a tool.
- `AccessControlStudio.Tests`: role matrix, argument constraints and HTTP authentication regression tests.

See [architecture](docs/architecture.md) for trust boundaries and the complete policy matrix.

## Local demo

Install .NET 10. Supply a unique, random signing key of at least 32 UTF-8 bytes through `Jwt__SigningKey` (environment variable) or ASP.NET user secrets. Never commit this key. Run only on loopback in Development. The demo identity endpoint is unauthenticated by design and exists only in Development.

```powershell
$env:ASPNETCORE_ENVIRONMENT = "Development"
$env:ASPNETCORE_URLS = "http://127.0.0.1:5077"
$env:Jwt__SigningKey = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
dotnet run --no-launch-profile --project src/AccessControlStudio.Api
```

In another shell:

```powershell
$token = (Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5077/api/demo/token -ContentType application/json -Body '{"identity":"operator"}').accessToken
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5077/api/authorization/evaluate -Headers @{Authorization="Bearer $token"} -ContentType application/json -Body '{"toolName":"crm.update_order","arguments":{"amount":50}}'
```

Valid demo identities are `viewer`, `operator`, and `admin`. Tokens expire after ten minutes. The token response necessarily contains the requested demo token; evaluation responses contain only an allow flag and stable reason code. Do not use the demo issuer as an identity provider.

## Verify

```text
dotnet restore
dotnet build -c Release
dotnet test -c Release
```

No dashboard, database, MCP gateway, tool forwarding, approval workflow, or production identity integration exists in this milestone.
