# Draft release notes — v0.1.0

**Status: review draft. Do not publish, tag or describe this as a production security certification.**

MCP Access Control Studio is a local showcase of identity-aware MCP tool authorization. An authenticated client calls the real .NET 10 Streamable HTTP gateway. JWT validation, default-deny RBAC and argument rules decide whether five seeded CRM tools can be forwarded. The React Playground displays the gateway's actual decision and correlation ID. Admin-only reporting reads sanitized SQLite records; overview statistics count persisted Terminal events.

The release candidate includes a one-command local startup, a real MCP SDK demo, frontend and backend security regressions, Playwright browser E2E coverage, five genuine screenshots and an unedited source recording. [README](../README.md) provides startup and verification commands; [threat model](threat-model.md) describes the trust boundary.

### Known limitations

The unauthenticated demo token issuer is restricted to loopback peers in Development. A reverse proxy can defeat that boundary by connecting locally. The CRM upstream also listens on loopback and can be reached by local processes. Tokens are short lived and held in browser memory, but there is no production identity provider, rotation or cloud deployment. SQLite audit is best effort and unencrypted; persisted counts can be incomplete. Cancellation or SDK continuation after forwarding can leave the upstream outcome uncertain. Permitted operations have no exactly-once guarantee.

### Release gate

Review [the checklist](release-checklist.md), repeat verification on the intended release commit, inspect every screenshot and recording for sensitive content, review dependency and security posture, and explicitly approve any future tag or GitHub Release. This PR does not perform those publication steps.
