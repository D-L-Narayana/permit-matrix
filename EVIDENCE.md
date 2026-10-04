# EVIDENCE — Permit Matrix

Measured facts only. Nothing below is estimated. Counts come from the commands shown.

## Environment

Node v20.20.1, npm 10.8.2, Linux sandbox, 1 October 2026. Browser checks used Playwright 1.63.0 (parent's internal QA install) driving Chromium headless shell 1217 at 1440×1000, 768×1024 and 375×900 with `prefers-reduced-motion: reduce`. All commands below were actually executed; outputs are copied, not paraphrased. Raw logs: `qa/red-run.txt`, `qa/green-run.txt`, `qa/verify-run.txt`, `qa/screens/qa-log.json`; axe results for all five apps in `../_qa/axe-results.json`.

## Test-first record

**RED — src/engine/__tests__/engine.test.ts written before any engine code.** First run (`qa/red-run.txt`):

```
FAIL  src/engine/__tests__/engine.test.ts
Error: Cannot find module '../contract' imported from .../src/engine/__tests__/engine.test.ts
Tests  no tests
```

**Second RED (after the parent's early source review), 1 Oct 2026 ~13:02 UTC** — five regression tests were added *before* the fixes and failed as expected (`qa/red-run-review1.txt`):

```
× measures the byte limit in UTF-8 bytes, not UTF-16 code units
× rejects duplicate record ids within a resource
× rejects non-finite numeric field values such as 1e999
× caps servers, builds and flaws per build
× does not throw on absurdly large lists passed as objects
    → expected [Function] to not throw an error but 'RangeError: Maximum call stack size e…' was thrown
Failed Tests 5 | 18 passed (23)
```

The `RangeError` was real: the original depth check spread a 200 000-element array into `Math.max`. It was replaced by an iterative scan.

**GREEN** (`qa/green-run.txt`): 18 passed (18) — first GREEN before the review regressions; 23 passed (23) after them.

## Clean-checkout verification (node_modules and dist deleted first)

```
$ npm ci
added 124 packages in 4s
$ npm run build
✓ built in 1.49s
$ npm test
 Test Files  1 passed (1)
      Tests  23 passed (23)
$ npm audit
found 0 vulnerabilities
```

Total: **23 tests, 1 file**, build succeeds with `tsc --noEmit` + `vite build` (`base: './'`), 0 npm audit findings at pinned versions.

## Browser verification

Main flow replayed with Playwright against `vite preview` (`qa/screens/`, `qa/screens/qa-log.json`): 0 page errors, 0 console errors, 0 failed requests and no horizontal overflow at 1440, 768 and 375 px.

| Screenshot | What it shows |
|---|---|
| `desktop-01-initial.png` | Start view with demo contract, not yet run |
| `desktop-02-vulnerable-run.png` | 83 cases run against 1.4.0; matrix pins; 4 findings |
| `desktop-03-cell-detail.png` | `GET /invoices/{id}` as Member: case ledger with redacted request/response |
| `desktop-04-fixed-run.png` | Same suite on 1.4.1: no findings |
| `desktop-05-import-refused.png` | Import of a contract naming `https://api.victim.example` refused |
| `tablet-01-initial.png`, `mobile-01-initial.png` | Full-page captures at 768 and 375 px |

axe-core (WCAG 2.0 A/AA + 2.1 AA tags) at 1440 and 375 px after the main action: **0 violations** (`../_qa/axe-results.json`). Earlier passes found muted-text contrast, a scrollable region without keyboard focus and (in other apps) ARIA attribute issues; all were fixed and re-measured. This is an automated check, not a screen-reader session.

## Measured facts that may support resume bullets

* 83 authorization cases are generated from the 6-endpoint / 3-role / 4-principal synthetic contract (`generateCases`).
* Vulnerable build `release/1.4.0`: 52 pass, 15 bypass, 12 mass-assignment, 4 exposure → 4 findings (API1, API5, API3 ×2). Remediated build: 83 pass, 0 findings.
* Contract limits: 64 KB UTF-8, 40 endpoints, 8 roles, 24 principals, 12 resources, 100 records/resource, depth 6, list length 1000, 4 servers, 8 builds, 40 flaws/build.
* `npm audit` moved from 2 moderate (vitest 3.2.7 / @vitest/mocker, dev-only) to 0 by pinning vitest 4.1.11; no `--force`.

## What was not measured

No performance benchmarks, no user studies, no cross-browser matrix beyond Chromium, no production deployment. Do not quote numbers that are not in this file.

## Second review cycle (1 Oct 2026, ~14:30 UTC)

**RED** (`qa/red-run-review2.txt`) — five regression tests added before fixes, all failing at assertion level:

```
× rejects two endpoints with the same method and path template          expected true to be false
× rejects parameter names other than {id} …                             expected true to be false
× routes a literal path to its own endpoint … after a {id} sibling      expected false to be true
× keeps the demo contract self-consistent: list and item scope agree    expected 'same-tenant' to be 'own'
× states in the export that response bodies carry fictional values      .toMatch() … got undefined
Tests  5 failed | 23 passed (28)
```

**GREEN** (`qa/green-run-review2.txt`): `Tests 28 passed (28)` after: duplicate-route rejection, `{id}`-only paths, literal-first routing, `list-invoices` scope `own`, `dataNote` in the report. Case count remains 83.

Clean checkout re-run (`qa/verify-run.txt`): 28/28, build ok, 0 vulnerabilities. Browser flow re-shot, including `desktop-06-duplicate-route-refused.png`; axe 0 violations.

## Upgrade cycle (4 Oct 2026)

Environment: Node v20.20.1, npm 10.8.2, Linux sandbox. Browser checks used Playwright 1.63.0 (a QA harness outside the repository) driving headless Chromium at 1440×1000, 768×1024 and 375×900 with `prefers-reduced-motion: reduce`, against the production bundle served from loopback static servers that apply the `vercel.json` response headers. All commands below were executed; outputs are copied, not paraphrased. Raw logs: `qa/upgrade-baseline.txt` (before any change), `qa/upgrade-run.txt` (clean checkout after integration, including the header-enforced browser run), `qa/screens-upgrade/qa-log.json` and screenshots.

### Baseline before any change

```
$ npm test            Tests  28 passed (28)
$ npm run build       dist/assets/index-C6VjWrtn.js  303.69 kB │ gzip: 95.56 kB
$ npm audit           found 0 vulnerabilities
```

Browser baseline: 14 workflow steps, 0 page errors, 0 console errors, 0 failed requests, no horizontal overflow at 1440/768/375, axe 0 violations on the initial view and after a run, **1 violation with import errors displayed** — `listitem` (serious): the dialog's `<ul class="errors" role="alert">` overrode the list role and orphaned its `<li>` children. The first scan of the baseline bundle by the new verifier also reported exactly one `fetch(`: Vite's module-preload polyfill, dead code in this single-chunk app.

### Test-first record per module

Each module's tests were written against a stub that exported the final signatures, so every RED below is an assertion failure on missing behaviour, not an import or compile error. Counts are the `Tests` summary lines of the recorded runs.

| Module (file) | RED against stub | GREEN after implementation |
|---|---|---|
| contract validation (`contract.test.ts`) | 36 failed \| 17 passed (53) | 53 passed; 58 passed after 5 more loopback cases |
| contract lint (`lint.test.ts`) | 16 failed \| 13 passed (29) | 29 passed |
| case generation (`cases.test.ts`) | 12 failed \| 7 passed (19) | 19 passed; 21 passed after count assertions |
| mock server (`mockServer.test.ts`) | 9 failed \| 3 passed (12) | 13 passed |
| runner (`runner.test.ts`) | 13 failed \| 8 passed (21) | 25 passed |
| run diff (`diff.test.ts`) | 10 failed (10) | 10 passed |
| report + memo (`report.test.ts`) | 12 failed \| 12 passed (24) | 24 passed |
| SARIF (`sarif.test.ts`) | 9 failed \| 2 passed (11) | 11 passed |
| OpenAPI import (`openapi.test.ts`) | 39 failed \| 4 passed (43) | 48 passed; 49 passed in the final file (clean run) |
| JSON Schema (`schema.test.ts`, against an empty `{}` schema) | 17 failed \| 6 passed (23) | 23 passed |
| UI components (`src/ui/__tests__`, seven files) | 36 failed \| 2 passed (38); focus-return addition 2 failed \| 7 passed (9) | 41 passed |
| App harness (`src/__tests__`) | export capture 2 failed \| 1 passed (3); flow and import files are characterisation tests and passed first time (2, 5) | 13 passed |
| ESLint invariant rules (private self-test over virtual files) | 3 failed \| 7 passed (10) | 10 passed |
| `scripts/verify-dist.mjs` (private fixture self-test) | 7 failed \| 2 passed (9) | 9 passed |

The passing tests at RED were, in every case, pre-existing behaviour the new tests also pin (frozen wordings, `isLocalTarget`, Ledgerly fixed/vulnerable results). The frozen `engine.test.ts` kept passing throughout; its single edit is the measured case count (83 → 89) after the anonymous row became part of the default matrix.

Two defects in the pre-upgrade app were found by the new checks and fixed with tests written first: the `listitem` violation above, and the import dialog returning focus to `<body>` on close (the opener is not a Radix `Dialog.Trigger`; RED `expected <body> to be <button id="import-contract">`).

### Clean-checkout verification after integration (node_modules, dist and coverage deleted first)

```
$ npm ci --ignore-scripts --no-fund --no-audit
added 414 packages in 60s
$ npm run typecheck      (tsc -p tsconfig.json --noEmit)        exit 0
$ npm run lint           (eslint . --max-warnings 0)           exit 0
$ npm test
 Test Files  24 passed (24)
      Tests  358 passed (358)
$ npm run test:coverage  (src/engine, v8; thresholds 90 / 85 / 90 / 90)
All files      |   93.48 |    90.41 |     100 |   98.74 |
$ npm run build
dist/assets/index-DD5h4aQ0.js   345.62 kB │ gzip: 109.62 kB
✓ built in 2.57s
$ npm run verify:dist
verify-dist: scanning 3 file(s) under dist/ (.js, .css, .html)
  allow-listed hosts seen: github.com x1 (SARIF tool.driver.informationUri), json.schemastore.org x1 (SARIF 2.1.0 $schema identifier), owasp.org x1 (OWASP API Security Top 10 reference links), react.dev x2 (react-dom production error-decoder URL), www.w3.org x18 (XML/SVG/MathML namespace identifiers)
verify-dist: OK — 3 file(s), no network/storage API tokens, no cross-origin references.
$ npm audit --audit-level=high
found 0 vulnerabilities
```

Total: **358 tests, 24 files** (28 original + 330 new), engine coverage statements 93.48 % · branches 90.41 % · functions 100 % · lines 98.74 %, bundle 345.62 kB (109.62 kB gzip; was 303.69 kB / 95.56 kB), 0 npm audit findings at pinned versions.

### Browser verification of the built bundle under the production security headers

The production bundle was served from loopback static servers that apply the response headers declared in `vercel.json` to every response — the Content-Security-Policy and the seven other security headers — so headless Chromium enforced the deployed policy while the workflows ran (`qa/screens-upgrade/qa-log.json`). An earlier run of the same workflows on a server that sent only `Content-Type` is superseded by this one and is not cited.

* **Header verification:** 14 responses (`/`, the 12 files under `dist/assets/`, the published JSON Schema) each carried all 8 headers with the exact declared values, the CSP string compared byte for byte.
* **Production-policy context** (no injected script of any kind): **19 workflow steps passed** — run 89 cases → 4 findings, redacted request in the ledger, evidence chip, anonymous cell without an `Authorization` header, remediated re-run with the comparison panel, Helpdesk 114 cases → 4 findings including API2:2023, contract health, external-target refusal — with 0 page errors, 0 console errors, 0 CSP reports, 0 failed requests, **0 requests to any origin other than the served one** (24 same-origin requests), no horizontal overflow at 1440, 768 and 375 px. Two downloads were produced and read back: `permitmatrix-1.4.0-fixed.json` (73 520 bytes, schema `permitmatrix.report/1`) and `permitmatrix-1.4.0-fixed.sarif.json` (1 430 bytes, SARIF 2.1.0); neither contains `mock-token-`.
* **Instrumentation context** (same headers; axe-core loaded from a same-origin path, which `script-src 'self'` admits without any policy change; a `securitypolicyviolation` listener installed before page scripts): axe-core WCAG 2.0 A/AA + 2.1 AA, colour contrast included, **0 violations** on the initial view, after a run, on the Helpdesk fixture after a run and with the import dialog open; **0 CSP violations from the application**. Two positive controls proved the policy was enforced: an injected inline `<script>` was blocked (`script-src-elem`) and a cross-origin `fetch` was blocked (`connect-src`), producing exactly those two violation events and three "Refused to …" console reports.

| Screenshot | What it shows |
|---|---|
| `desktop-01-initial.png` | Start view with the Ledgerly contract, demo-contract picker, contract health, not yet run |
| `desktop-02-vulnerable-run.png` | 89 cases run against 1.4.0; matrix with the anonymous column; 4 findings |
| `desktop-03-cell-detail.png` | `GET /invoices/{id}` as Member: case ledger with redacted request and response |
| `desktop-04-anonymous-cell.png` | `GET /invoices/{id}` as the anonymous caller: request without an `Authorization` header, 401, pass |
| `desktop-05-fixed-run-with-diff.png` | Same suite on 1.4.1: no findings; "Changes since previous run" — 4 findings fixed, 31 cases improved |
| `desktop-06-helpdesk-run.png` | Helpdesk 2.3.0: 114 cases, 4 findings including API2:2023 on `GET /tickets/export` |
| `desktop-07-import-refused.png` | Import of a contract naming `https://api.victim.example` refused, dialog stays open |
| `tablet-01-initial.png`, `mobile-01-initial.png` | Full-page captures at 768 and 375 px |

### Measured facts that may support resume bullets

* Ledgerly: 89 cases (83 + one no-credentials case per endpoint). Vulnerable build: 4 findings (API1, API5, API3 ×2), 31 non-pass verdicts; remediated build: 0 findings, 89 pass. Diff vulnerable → fixed: 4 findings fixed, 0 introduced, 31 cases improved, 0 regressed.
* Helpdesk: 114 cases (108 + 6). Vulnerable build: 4 findings — `list-tickets` object bypass (API1, high), `list-tickets` sensitive exposure of `internalNotes` (API3, medium), `create-ticket` mass assignment (API3, high), `export-tickets` reachable without credentials (API2, high); remediated build: 0 findings, 114 pass.
* The OpenAPI 3.1 rendition of Ledgerly converts to a contract that generates exactly the same 89 cases; both shipped fixtures validate against the published JSON Schema and produce no lint warnings.
* 358 tests in 24 files; engine coverage 93.48 / 90.41 / 100 / 98.74 (statements / branches / functions / lines).
* Bundle verification: 0 network or storage API tokens in `dist/`; the only URL hosts are the five justified literals above. The baseline bundle had 1 `fetch(` (Vite polyfill).
* Production policy: all 8 `vercel.json` headers exact on 14 responses; every upgraded workflow completed under the enforced CSP with 0 violations and 0 foreign-origin requests; enforcement proven by two positive controls.
* Dependencies: 15 development-only packages added, all pinned exactly; production bundle dependencies unchanged; `npm audit` 0 findings.

### What was not measured

No performance benchmarks, no user studies, no cross-browser matrix beyond Chromium, no production deployment (the headers were verified as served by a local server configured from `vercel.json`, not as served by the deployed site), no screen-reader session. Do not quote numbers that are not in this file.
