# v0.1.0 release candidate verification checklist

This checklist records the Issue #9 branch verification. A green PR is a review gate, not a production security certification. Do not tag, publish a GitHub Release, or publish commercial listings from this checklist alone.

## Automated commands

| Check | Command | Result |
| --- | --- | --- |
| .NET restore | `dotnet restore` | Passed locally |
| .NET Release build | `dotnet build -c Release --no-restore -m:1` | Passed locally; 0 warnings, 0 errors |
| .NET full suite | `dotnet test -c Release --no-build -m:1` | Passed locally; 80 passed, 0 failed, 0 skipped |
| Real MCP + SQLite restart | `pwsh -File ./scripts/run-demo.ps1` | Passed locally; 10 MCP calls reported, Admin reporting enforced, records survived restart |
| Frontend install | `npm ci` in `apps/studio-web` | Passed locally; 194 packages audited, 0 vulnerabilities reported |
| Frontend unit suite | `npm test` | Passed locally; 12 passed, 0 failed |
| TypeScript + production build | `npm run build` | Passed locally |
| Chromium browser E2E | `npm run e2e` | Passed locally; 7 real MCP calls, direct audit lookup, role isolation, Admin reporting, keyboard and narrow-screen checks |
| One-command startup | `node scripts/run-studio.mjs` | Reached `Studio ready: http://127.0.0.1:5173/` locally; stopped with Ctrl+C and confirmed no workspace demo services remained |
| Linux CI | PR workflow in `.github/workflows/dotnet.yml` | Check the linked workflow on the PR for the current head commit; this file records local results |

The changed backend tests cover Admin-only direct Terminal lookup, malformed ID rejection, allowlisted response metadata, real correlation and denied zero-upstream behavior. Frontend tests cover stale audit pages, identity switches, direct lookup and token URL exclusion. The browser E2E checks selected JWT identity and separate Admin correlation lookups. Existing suites cover default-deny policy, upstream errors, timeout/cancellation, CORS, SQLite retention and persistence.

## Showcase evidence

- `npm run capture:showcase` passed locally. It started a real loopback gateway and Chromium and asserted Viewer Deny, Admin Allow, two persisted Terminal events, real audit rows and the five-tool backend permission matrix.
- Five PNGs and the WebM under `docs/assets/` were visually reviewed for readable text and absence of tokens, developer tools and personal data.
- The unedited Playwright WebM source recording was measured in Chromium at **81 seconds**.

## Manual release review

- [ ] Review README claims against the implementation and [threat model](threat-model.md).
- [ ] Review the [MIT license](../LICENSE), dependency versions, and third-party notices as appropriate.
- [ ] Run `node scripts/run-studio.mjs` and manually inspect desktop and narrow-screen layouts, keyboard focus, loading and empty states. Automated E2E covers navigation, mobile overflow, and audit states but is not a full accessibility review.
- [ ] Confirm no reverse proxy or public listener exposes the Development demo issuer or CRM upstream.
- [ ] Confirm the SQLite path and its WAL/SHM files are private on any demonstration host.
- [ ] Inspect exact PR diff and CI logs; approve future release publication separately.

## Environment note

Windows Application Control previously rejected execution of rebuilt .NET assemblies with `0x800711C7` even when compilation succeeded. Do not disable or weaken it. If that recurs, distinguish `dotnet build` from assembly execution, record the failing command/error, and use the Linux GitHub Actions workflow for verification. A separate local build attempt on this branch encountered `MSB3027` because a stale loopback demo API process held output DLLs open; stopping that identified workspace process let the 80-test backend suite pass. The first `npm ci` attempt failed with `EPERM` on a native module held by a stale workspace Vite process; after stopping that process, the install passed.

One local `npm run e2e` run ended in a Playwright `TimeoutError` without a stage in the original harness; two immediate reruns passed. The harness now reports only its safe test stage on failure, without JWTs or arguments. Linux CI is the independent check for this intermittent Windows result.
