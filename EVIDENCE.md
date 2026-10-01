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

## Sixth-Fable review cycle (1 Oct 2026, ~14:30 UTC)

**RED** (`qa/red-run-sixth.txt`) — five regression tests added before fixes, all failing at assertion level:

```
× rejects two endpoints with the same method and path template          expected true to be false
× rejects parameter names other than {id} …                             expected true to be false
× routes a literal path to its own endpoint … after a {id} sibling      expected false to be true
× keeps the demo contract self-consistent: list and item scope agree    expected 'same-tenant' to be 'own'
× states in the export that response bodies carry fictional values      .toMatch() … got undefined
Tests  5 failed | 23 passed (28)
```

**GREEN** (`qa/green-run-sixth.txt`): `Tests 28 passed (28)` after: duplicate-route rejection, `{id}`-only paths, literal-first routing, `list-invoices` scope `own`, `dataNote` in the report. Case count remains 83.

Clean checkout re-run (`qa/verify-run.txt`): 28/28, build ok, 0 vulnerabilities. Browser flow re-shot, including `desktop-06-duplicate-route-refused.png`; axe 0 violations.
