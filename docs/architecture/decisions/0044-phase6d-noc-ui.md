# 0044. Phase 6D NOC UI: Build, Serving and Supply Chain

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner (BQ-11, 2026-10-11); the details under the
delegation of 2026-10-05 to industry practice

## Context

BQ-11 chose React, TypeScript and Vite for the NOC UI in `apps/web`
([Phase 6 plan](../phase6-dashboards-ui-notifications-plan.md), 6D). Three
things remained open:

- how the page reaches the API without weakening the session cookie
  ([ADR 0043](0043-phase6c-browser-sessions.md));
- how to make T-08, stored cross-site scripting, a tested control rather
  than a hope;
- how to keep the npm supply chain, far larger than the Rust one, under
  control (R22).

## Decision

### Serving: same origin

The API serves the built UI (`apps/web/dist`) from
`WETECHINETMON_API_WEB_ROOT`. Page and API share one origin, so there is
no CORS to configure, and the cookie stays `SameSite=Strict`.

- `GET` or `HEAD` on any path outside `/api/` answers `index.html`. The
  single-page app routes in the browser.
- Under `assets/`, only a single file name of letters, digits, `-`, `_`
  and `.` is served, with an extension from a short list (`js`, `css`,
  `woff2`, `png`, `ico`). No other file under the root is ever served,
  and no path can leave it.
- Assets are content-hashed by Vite and cached as immutable. The page is
  never cached.

### Headers

- **The page:** `Content-Security-Policy: default-src 'none';
  script-src 'self'; style-src 'self'; img-src 'self' data:;
  font-src 'self'; connect-src 'self'; manifest-src 'self';
  base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. No inline
  script or style is allowed, and CI checks the build has none.
- **Every response,** page and API alike: a deny-all CSP for API answers,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy:
  same-origin`, a restrictive `Permissions-Policy`, and HSTS whenever the
  API serves TLS.

### T-08 as a tested control

Four layers, each tested:

1. React renders strings as text.
2. **A lint rule refuses every way of handing HTML to the DOM:**
   `dangerouslySetInnerHTML`, `innerHTML` and `outerHTML` assignment,
   `insertAdjacentHTML`, and `document.write`. A test runs the linter
   against each, so the rule cannot be weakened unnoticed.
3. A component test renders hostile titles, targets and assignees and
   checks that they appear as text and create no element.
4. The CSP refuses inline script, so an injection that got past the
   other three still would not run.

### Supply chain (R22)

- **Exact versions** in `package.json` and a committed
  `package-lock.json`. CI installs with `npm ci`.
- **No install scripts:** `ignore-scripts=true` in `.npmrc` and
  `--ignore-scripts` in CI. A dependency cannot run code when it is
  installed.
- `npm audit --audit-level=high` on every pull request.
- **A licence check** reads the lockfile. What ships in the bundle must be
  permissive (MIT, ISC, Apache-2.0, BSD, 0BSD and the like). Build tools
  that never ship may also be MPL-2.0, which today is Vite's CSS
  minifier, `lightningcss`.
- Dependabot watches `apps/web` weekly, and every update passes the same
  job.
- `node_modules` never enters the repository.

### Versions

React 19.3, React Router 7.18, Vite 8.3, TypeScript 6.0 (typescript-eslint
8.70 does not support 7.0 yet), Vitest 5.0, ESLint 10.11. Each was at
least two weeks old when chosen.

## Consequences

- Seven packages ship in the bundle: React, React DOM, React Router and
  their own dependencies. About 245 more are build tools.
- A deployment that wants the UI builds `apps/web` and points
  `WETECHINETMON_API_WEB_ROOT` at `dist/`.
- The UI cannot use inline styles or scripts, nor load anything from
  another origin, including fonts and analytics.

## Alternatives considered

- **A separate web server or CDN for the UI.** It needs CORS and either a
  relaxed `SameSite` or a proxy, and it is one more thing to deploy.
- **Embedding the UI in the API binary.** That needs a new crate and ties
  every UI change to a Rust release.
- **No lint rule, relying on React alone.** One
  `dangerouslySetInnerHTML` in a future change would reopen T-08 without
  failing anything.
