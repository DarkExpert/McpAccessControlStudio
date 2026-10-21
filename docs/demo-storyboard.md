# Genuine demo recording storyboard

Run `dotnet build -c Release` and `npm ci`, then from `apps/studio-web` run `npm run capture:showcase`. The script starts a loopback API and Vite with a fresh random key and temporary SQLite database, uses Playwright Chromium, captures five PNGs under `docs/assets` and saves an unedited WebM source recording. It asserts the real gateway decisions, correlation IDs, persisted overview total, audit rows and backend-derived five-tool matrix before saving assets. No credentials, developer tools or CRM response payloads appear on screen.

| Approx. time | Visible action | Evidence |
| --- | --- | --- |
| 0–5 s | Introduce the Security Playground | Local running browser and seeded identity selector |
| 5–18 s | Viewer calls Delete customer | Real `tools/call` returns Deny, `RoleDenied`, Blocked and a correlation ID |
| 18–31 s | Switch to Admin and call Export customers | Separate Admin JWT; real Allow and Forwarded metadata |
| 31–45 s | Open Security Overview and enable Admin reporting | Persisted Terminal totals from SQLite; reporting credential stays separate |
| 45–59 s | Show Audit History | Decision/Pending and Terminal outcomes with correlation IDs |
| 59–73 s | Show Tool Permissions | Five descriptors read from the enforcing backend policy |
| 73–83 s | Return to Playground | End on the real Admin result and security path |

The pauses make the source capture roughly 80 seconds; exact duration varies with startup and browser timing. To narrate or edit the source for public use, record voiceover separately and review the final cut manually. Do not replace outcomes with mocked UI or publish the video automatically.
