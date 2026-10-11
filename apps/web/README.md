# NOC UI

The WetechiNetMon NOC UI: React, TypeScript and Vite
([ADR 0044](../../docs/architecture/decisions/0044-phase6d-noc-ui.md)).
It talks only to the [REST API](../api/README.md), from the same origin,
with a session cookie
([ADR 0043](../../docs/architecture/decisions/0043-phase6c-browser-sessions.md)).

**Status:** Phase 6D, in progress. Built so far: signing in and out, the
incident list, an incident's page with its notes, timeline and actions,
and the NOC overview. End-to-end tests run the UI in a real browser
against the real API in CI.

The overview shows active incidents by severity, and, for the traffic
tenant only (ADR 0042), traffic over the last hour, the top hosts and
every exporter, with silent ones called out. It refreshes every 30
seconds and keeps the last data if the API cannot be reached.

On an incident's page an operator sees only the actions their role
allows. Each action sends the version they saw, so a change someone else
made first is refused and the page reloads. Closing, reopening, lowering
severity and redacting a note ask first, as the CLI does.

## Building and serving

```sh
cd apps/web
npm ci --ignore-scripts
npm run build
```

Then point the API at the build:

```sh
WETECHINETMON_API_WEB_ROOT=/path/to/apps/web/dist wetechinetmon-api
```

Sign in with an API token (`wetechinetmon-api token create ...`). The page
exchanges it for a session once and keeps no copy.

For development, `npm run dev` serves the UI on Vite's port and proxies
`/api` to an API on `127.0.0.1:8080`.

## Checks

| Command | What it proves |
|---|---|
| `npm run lint` | ESLint, including the T-08 rule: no code may hand HTML to the DOM |
| `npm run typecheck` | TypeScript in strict mode |
| `npm test` | Vitest: the API client, hostile text rendered as text, and the lint rule itself |
| `npm run build` | A production build with no inline script or style |
| `npm audit` | No known high or critical vulnerability |
| `npm run licences` | Every licence is on the allowlist, stricter for what ships |
| `npm run e2e` | Playwright, against a running stack: `E2E_BASE_URL` and `E2E_TOKEN` (a noc_lead token) |

CI runs all of them in the **Web UI** job.

## Rules

- Never render HTML. Untrusted text, such as titles, notes, targets and
  assignees, is shown as text (T-08).
- No inline scripts or styles: the Content-Security-Policy forbids them.
- No severity or state by colour alone: always the word, and a shape
  where it helps (FR-10.2).
- Exact versions, the lockfile committed, and no install scripts.
