# AUDIT — Permit Matrix

## Scope and threat model

**Asset:** a static single-page app that evaluates a user-supplied contract (native JSON or OpenAPI 3.x JSON with `x-permitmatrix` extensions) with an in-memory mock server. There is no backend, no account, no persistent storage and no network call initiated by application code.

**Trust boundaries**

| Boundary | Input | Control |
|---|---|---|
| Pasted / uploaded contract → engine | Arbitrary text up to the browser's ability to hold it | `importAny` rejects >64 KB (UTF-8 bytes) and invalid JSON before format detection; `validateContract` rejects nesting >6, lists >1000, >50 000 values, non-finite numbers, then enforces schema, id patterns, duplicate ids and routes, cross-references and per-list caps, and returns every error addressed to its location. Validation is iterative (no recursion, no argument spreading), verified by a 50 000-endpoint / 200 000-element regression test. The OpenAPI converter pre-scans iteratively with its own caps (≤1000 paths, ≤50 000 values, nesting ≤24) and refuses `$ref`. |
| Contract `servers` / OpenAPI `servers[].url` | Any URL | Only `mock://host` or `http(s)://localhost|127.0.0.1|[::1]` accepted; everything else fails with `External target refused`. Characterisation tests cover userinfo (`localhost@evil.example`), fragment and subdomain look-alikes. There is no request-issuing code path at all. |
| Reserved identifiers | Role/principal ids, record owners, field names, build keys | `anonymous` (any letter case) is reserved for the synthetic unauthenticated caller; `__proto__`, `constructor` and `prototype` are refused as field names, field-list entries and build keys so contract data can never alias object internals. |
| Engine output → DOM | Case ids, paths, field names, rationale strings, lint messages, import notes | Rendered through React text nodes only; no `dangerouslySetInnerHTML`, no `eval`, no `new Function` — enforced by ESLint `no-restricted-syntax` on `src/`. |
| Report export | JSON / Markdown / SARIF file | Authorization header redacted; anonymous cases carry no header at all; SARIF carries findings only (no bodies); no CSV (so no formula-injection surface). Download via `Blob` + object URL, revoked after click. |

**Threats considered**

* *Malicious contract causing denial of service in the tab* — bounded by the structural scan and caps; the mock server is instantiated per case so cost is O(cases × records) with cases ≤ 40 endpoints × (24 principals + 1 anonymous) × (3 + fields). Worst case is seconds of CPU, not a crash.
* *Misuse as a scanner against third parties* — impossible by construction; the "server" is a function. Three independent controls assert this: the validator's loopback rule, ESLint `no-restricted-globals/properties` on `src/` (fetch, XMLHttpRequest, WebSocket, EventSource, sendBeacon, cookies, storage APIs), and `scripts/verify-dist.mjs`, which scans the built bundle for the same identifiers and for any `https?://` host outside a justified allow-list.
* *Leaking a real token through an exported report* — tokens are symbolic (`mock-token-<principal>`) and still redacted on export, so the redaction path is tested even though no real secret exists.
* *XSS through contract content* — all strings are text nodes; CSP in `vercel.json` disallows inline scripts and remote origins.
* *False findings against a correct server* — "zero findings on the remediated build" is asserted for both shipped fixtures and for the OpenAPI rendition of Ledgerly; the contract linter flags policy shapes that would otherwise silently reduce or distort coverage.

## Data flow

`fixture JSON | user paste/file → importAny (byte limit, JSON.parse, format detection, optional OpenAPI conversion) → validateContract → lintContract (advisory) → generateCases → runSuite(createMockServer per case) → React state → optional diffRuns against the previous run → (optional) buildReport → reportToMarkdown | reportToSarif → Blob download`. Nothing is written to `localStorage`, `sessionStorage`, IndexedDB, cookies or any remote host.

## Dependency review (4 Oct 2026)

* Runtime (ships in `dist/`): `react`, `react-dom` 19.3.0 (MIT); `@radix-ui/react-dialog` 1.1.23 and `@radix-ui/react-switch` 1.3.7 (MIT); `@fontsource/ibm-plex-sans`, `@fontsource/ibm-plex-mono` 5.3.0 (fonts under SIL OFL 1.1, package MIT). Unchanged by this cycle, so `public/THIRD_PARTY_LICENSES.txt` is unchanged.
* Development only: `vite` 7.3.6, `vitest` 4.1.11, `@vitest/coverage-v8` 4.1.11, `typescript` 5.9.3, `@vitejs/plugin-react` 5.2.0, `eslint` 9.39.5 + `@eslint/js`, `typescript-eslint` 8.71.0, `eslint-plugin-react-hooks` 7.1.1, `eslint-plugin-jsx-a11y` 6.10.2, `globals` 17.13.0, `prettier` 3.9.9, `jsdom` 29.1.1, Testing Library (`react` 16.3.3, `dom` 10.4.2, `user-event` 14.6.7, `jest-dom` 6.9.1), `axe-core` 4.13.0 (MPL-2.0), `ajv` 8.20.0. All pinned exactly. ESLint stays on 9.x because `eslint-plugin-jsx-a11y` 6.10.2 does not support ESLint 10; `npm` prints a deprecation notice for 9.x. Dependabot is configured for npm and GitHub Actions.
* `npm audit --audit-level=high`: 0 vulnerabilities at the pinned versions (see `EVIDENCE.md`).

## Security headers

`vercel.json` sets CSP (`default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, COOP, and — new this cycle — `Strict-Transport-Security: max-age=63072000; includeSubDomains` and `Cross-Origin-Resource-Policy: same-origin`. `style-src 'unsafe-inline'` remains because Radix primitives (via `react-remove-scroll`) inject a style element; script execution is not affected. The CSP string itself is unchanged.

The policy is exercised, not just declared: release QA serves the built bundle with exactly these headers and runs every workflow under the enforced CSP, recording `securitypolicyviolation` events, CSP console reports and any request to a foreign origin (`EVIDENCE.md`). The application produced none; two positive controls (an inline script and a cross-origin fetch) were blocked as the policy requires. This verifies the headers as declared in `vercel.json`; whether the deployed site actually sends them is a property of the deployment, which this repository does not test.

## Build verification

`npm run check` runs typecheck, lint, tests with coverage, build and `scripts/verify-dist.mjs`. The verifier walks `dist/**/*.{js,css,html}` and fails on `fetch(`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `localStorage`, `sessionStorage`, `indexedDB`, `sendBeacon`, `document.cookie`, on any cross-origin `<script src>`/`<link href>` or inline `<script>` in `index.html`, and on any URL host outside its inline allow-list (each entry justified in the script: React's error-decoder host, the SARIF schema URL, OWASP reference links, the tool's `informationUri`, XML namespaces). The first bundle it scanned contained exactly one `fetch(` — Vite's module-preload polyfill, dead code in this single-chunk app — which is now disabled in `vite.config.ts` (`build.modulePreload.polyfill: false`), so the "no network API in `dist/`" claim is literal. CI runs the same steps on Node 20 and 22 with SHA-pinned actions, `permissions: contents: read` and cancelled superseded runs.

## Accessibility

axe-core (WCAG 2.0 A/AA + 2.1 AA) runs in two places: in jsdom as part of `npm test` (initial render and after a run; `color-contrast` is disabled there because jsdom has no layout) and in headless Chromium against the built bundle during release QA (initial, after a run, on the Helpdesk fixture and with the import dialog open; `EVIDENCE.md`). In the browser, axe is loaded from a same-origin path in a separately labelled instrumentation context so the production CSP stays enforced; the workflow run itself injects no script. The matrix is keyboard-navigable (roving tabindex, arrow keys, Home/End). Two pre-existing defects found by this cycle's automated checks were fixed: the import dialog's error list carried `role="alert"` on the `<ul>` itself, orphaning its `<li>` children (axe `listitem`, serious) — the live region is now a persistent wrapper around a plain list; and closing the import dialog dropped focus to `<body>` because the opener is not a Radix `Dialog.Trigger` — the dialog now returns focus to the button by id. No screen-reader session has been recorded.

## Unresolved limitations

* The mock server's semantics are the engine author's reading of the contract; a real backend may differ in ways the contract cannot express (query filters, pagination, ABAC conditions).
* No fuzzing of path parameters beyond the record ids in the fixture; path-traversal style ids are rejected by the id pattern rather than exercised.
* Severity is a transparent rubric, not CVSS. Findings are diffed across runs by endpoint and kind; they are not de-duplicated across different contracts.
* The OpenAPI importer handles the subset needed to express permit-matrix contracts (JSON input, inline schemas, one path parameter, five methods); it is not a general OpenAPI validator.
* `isLocalTarget` is deliberately over-strict: IPv4-mapped loopback (`[::ffff:127.0.0.1]`) and a trailing-dot `localhost.` are refused.
