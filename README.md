# Permit Matrix — API authorization contract tester

[Open the public educational demo](https://dln-permit-matrix.vercel.app). It runs only against an in-browser synthetic mock, not a real API.

**Educational prototype (October 2026).** Permit Matrix turns a small, local API contract into a complete set of authorization test cases — every role against every endpoint against *own*, *peer* and *cross-tenant* records, an *unauthenticated* caller against every endpoint, plus property-level probes on reads, writes and creates — and runs them against a deterministic mock server that lives entirely inside the browser tab. It is a teaching and portfolio tool for reasoning about OWASP API Security Top 10 (2023) authentication and authorization classes. It is **not** a penetration-testing tool, it never contacts a network host, and nothing here is a security certification or compliance opinion.

## What problem it addresses

Object-level (API1:2023), property-level (API3:2023) and function-level (API5:2023) authorization bugs — and the missing-authentication bug (API2:2023) that makes all of them moot — are usually found one endpoint at a time, by hand. The repeatable way to check them is a matrix: *who* may do *what* to *whose* data, with a negative case for every cell, and a "nobody" row to prove every route demands credentials. Permit Matrix makes that matrix explicit, generates the negative cases automatically, shows precisely which contract rule each verdict rests on, and tells you what changed between two runs so a remediation can be verified rather than assumed.

## Key workflows

1. **Pick a demo contract.** *Ledgerly* (3 roles, 4 principals across 2 tenants, 2 resources, 6 endpoints; vulnerable build `release/1.4.0` seeds four flaws) or *Helpdesk* (3 roles, 5 principals across 2 tenants, 6 endpoints including a `POST` create and a literal `/tickets/export` route; vulnerable build `release/2.3.0` seeds a route that skips authentication, create-time mass assignment, and a listing that both leaks other tenants' tickets and returns the sensitive `internalNotes` field).
2. **Run the suite.** 89 cases are generated for Ledgerly (114 for Helpdesk). Each matrix cell shows pins per target (own · peer · cross-tenant, or a single pin for collection/create calls) and a dot per property probe; the last column is the anonymous caller. Cells are keyboard-navigable (arrow keys, Home/End).
3. **Inspect a cell.** The case ledger lists each case with its expectation and rationale, the redacted request (anonymous cases carry no `Authorization` header at all), the response, and the verdict explanation. Finding evidence chips jump straight to the case.
4. **Toggle individual server flaws** or switch to the remediated build and re-run. The **Changes since previous run** panel lists findings fixed or introduced and every case whose verdict moved, so a fix can be shown to be a fix. The `deny-everything` flaw demonstrates that over-denial is reported as a functional regression, not a security pass.
5. **Read the contract's health.** The linter flags policies that cannot be tested well — a listing scoped wider than its item route, a principal with no records, a flaw that cannot change behaviour, a single-tenant contract that can produce no cross-tenant case — as advisory warnings next to the contract outline (`docs/LINT.md`).
6. **Import your own contract** (synthetic data only) as native `permitmatrix.contract/1` JSON or as an **OpenAPI 3.x** JSON document carrying `x-permitmatrix` extensions (`docs/CONTRACT.md`). Validation errors are addressed to the offending location (`endpoints[2].access.roles[1]: …`), bounded sizes are enforced, and `servers` may contain only `mock://` or loopback targets — anything else is refused with `External target refused`. A machine-readable JSON Schema is published at `/schema/permitmatrix.contract-1.schema.json`.
7. **Export** a JSON report (`permitmatrix.report/1`), a Markdown memo with findings, evidence, remediation guidance and the coverage table, or a **SARIF 2.1.0** log of the findings for security tooling (`docs/REPORT.md`).

## Quickstart

```bash
npm ci
npm test          # vitest: 24 files, 358 tests (engine + jsdom UI and accessibility tests)
npm run check     # typecheck + lint + tests with coverage + build + bundle verification
npm run dev       # http://localhost:6110
```

Node 20 or newer (CI runs 20 and 22; `.nvmrc` says 22). No environment variables, no backend, no storage APIs: session state lives in memory and resets on refresh (export the report to keep it).

## Algorithm

**Case generation** (`src/engine/cases.ts`) — for every endpoint × principal:

* If the endpoint has no `{id}`: a `GET` gets one *collection* case (expected `allow` iff the principal's role is in `access.roles`), plus one read probe per `sensitiveFields` entry when allowed; a `POST` gets one *create* case, plus — when `writableFields` is declared — one write probe per field that exists on the resource's records but is not writable.
* Otherwise pick up to three target records from the endpoint's resource: one owned by the principal, one owned by someone else in the same tenant, one in another tenant. Expectation:
  * role not allowed → `deny`, category **function**;
  * `ownership: any` → `allow`;
  * `ownership: own` → `allow` only for the principal's own record;
  * `ownership: same-tenant` → `allow` only for records in the principal's tenant.
* For each expected-`allow` case on a `PATCH`/`PUT` endpoint with `writableFields`, add one **property** probe per non-writable field in the target record. For each expected-`allow` `GET` case with `sensitiveFields`, add one probe per sensitive field.
* For every endpoint, one **authentication** case from the synthetic `anonymous` principal (no credentials, expected `deny`).

**Mock server** (`src/engine/mockServer.ts`) — implements the contract literally: route → authenticate → role check → body validation → record lookup → ownership check → method semantics. Literal routes are matched before parameterised ones, so `/tickets/export` is never swallowed by `/tickets/{id}`; a path that matches another method's template answers `405`; validation rejects duplicate method + path templates and any parameter other than `{id}`. Each flaw switches off exactly one check for exactly one endpoint — including `skip-authentication`, which lets an unauthenticated request through to the handler. Responses strip every field marked sensitive anywhere on that resource unless the `return-sensitive-fields` flaw is on.

**Runner** (`src/engine/runner.ts`) — one fresh server per case so destructive cases cannot influence each other. Verdicts:

| Verdict | Meaning |
|---|---|
| `pass` | Behaviour matched the contract (for authentication cases: a `401` or `403`) |
| `bypass` | Expected deny, got 2xx (or a listing leaked out-of-scope records, or an anonymous call succeeded) |
| `over-deny` | Expected allow, got 403 — reported as a functional regression, not as safety |
| `mass-assignment` | Server state shows a non-writable field changed or was accepted at create time (the oracle inspects state after the write, like an integration test querying the database) |
| `exposure` | A sensitive field appeared in an item response or in any listed item |
| `error` | 400/401/404/405/5xx where none was expected — the case could not be evaluated |

Findings are aggregated per endpoint and kind, mapped to API1/API2/API3/API5:2023, with a documented severity rubric exported as `SEVERITY_RUBRIC` (object, function and authentication bypasses are high; mass assignment is high when the probed field looks like `role`, `status`, `owner`, `tenant`, `price` or `amount`; exposure is high when the field looks like a credential or hash; over-deny is low). Coverage counts cases per endpoint × role, including the anonymous column.

**Diff** (`src/engine/diff.ts`) — matches two runs case by case and finding by finding: improved / regressed / changed cases, fixed / introduced / persisting findings.

## Architecture

```
src/engine/     pure TypeScript, no DOM: types, contract validation, lint, case generation, mock server,
                runner, diff, report, SARIF, OpenAPI import
src/fixtures/   synthetic Ledgerly and Helpdesk contracts (+ Ledgerly as OpenAPI 3.1); .example domains, fictional people
src/ui/         React components: toolbar, contract rail, keyboard-navigable matrix, findings, case ledger, import dialog
src/features/   lint panel and run-comparison panel
src/App.tsx     composition and state (React state only)
public/schema/  JSON Schema for permitmatrix.contract/1
scripts/        verify-dist.mjs — proves the built bundle contains no network or storage API calls
docs/           CONTRACT.md, LINT.md, REPORT.md
```

Engine code has no React imports and is exercised directly by the tests.

## Tests

358 tests in 24 files. `src/engine/__tests__/engine.test.ts` is the original suite (validation, generation, mock, runner, report, two review cycles of regressions); `contract`, `lint`, `cases`, `mockServer`, `runner`, `diff`, `report`, `sarif`, `openapi`, `schema` and `integration` test files cover each module and the cross-module invariants (zero findings on every remediated build; exactly the seeded findings on every vulnerable build; the OpenAPI rendition generates identical cases; both fixtures validate against the JSON Schema and lint clean). `src/ui/__tests__`, `src/features/diff/__tests__` and `src/__tests__` run the components and the whole app in jsdom with Testing Library, including keyboard navigation of the matrix, focus return from the import dialog, real export capture, and axe-core WCAG 2.x A/AA checks before and after a run. Coverage thresholds for `src/engine` (lines 90 / branches 85 / functions 90 / statements 90) are enforced in CI (`vitest.config.ts`). New behaviour was written test-first; `EVIDENCE.md` records the failing and passing runs.

## Data handling and safety

* Browser-local only. There is no `fetch`, no WebSocket, no storage API, no analytics. This is enforced three ways: ESLint `no-restricted-*` rules on `src/`, `scripts/verify-dist.mjs` scanning the built bundle for network and storage API tokens and for any URL host outside a justified allow-list, and the mock being a plain function.
* Contracts are bounded: 64 KB (UTF-8 bytes), 40 endpoints, 8 roles, 24 principals, 12 resources, 100 records each, nesting depth 6, list length 1000. Oversized or malformed input is rejected with a visible, location-addressed message. Identifiers `anonymous`, `__proto__`, `constructor` and `prototype` are reserved and refused.
* `servers` must be `mock://…` or `localhost`/`127.0.0.1`/`[::1]`; the app has no code path that would send a request anywhere even if it were not. OpenAPI `servers[].url` go through the same rule.
* Exported reports redact the `Authorization` header to `Bearer [redacted:<principal>]`. **Response bodies are not redacted** — they are the evidence of what the mock returned, including fields the contract marks sensitive (e.g. the fictional `passwordHash` values). The report carries a `dataNote` saying so; never load a contract containing real records. SARIF exports contain findings only — no requests or responses.
* All fixture identities and domains are fictional (`acme.example`, `globex.example`).

## Limitations and unsupported cases

* The mock server is an idealised implementation of the contract. Findings describe the mock's behaviour under seeded flaws, not any real system. Running the tool proves nothing about production software.
* Expectations come from the contract. If the contract is wrong, the matrix is wrong; the linter catches some inconsistencies but cannot discover undocumented authorization rules.
* Only one path parameter, spelled `{id}` (OpenAPI parameters of any name are renamed on import), is supported per route; no query parameters, pagination, nested resources, attribute-based conditions, rate limits or time-based rules.
* Create-time probes cover fields that already exist on some record of the resource; injection of previously unknown fields is not probed.
* OpenAPI import needs the `x-permitmatrix` extensions (OpenAPI cannot express principals, records or ownership), accepts JSON only and refuses `$ref`; it is a convenience path onto the same bounded validator, not a general OpenAPI tool.
* Severity is a transparent rubric, not CVSS. Findings are compared across runs by endpoint and kind, not de-duplicated across contracts.
* Reset-on-refresh is deliberate (no storage APIs), so imported contracts must be re-imported.
* ESLint is pinned to 9.x because `eslint-plugin-jsx-a11y` does not yet support ESLint 10.

## JD evidence (truthful framing)

This project demonstrates: API/web application-security assessment reasoning (authentication and authorization matrices, negative testing, OWASP API Security Top 10:2023 mapping), API integration concepts (contract-driven request generation, OpenAPI extension design, SARIF interchange), analytical write-ups (per-case rationale, findings with remediation, run-to-run diffs), test-first TypeScript engineering with accessibility checks, and secure-by-default input handling. It does **not** constitute professional penetration-testing experience, a security certification or any client engagement.

## AI-assistance disclosure

Built in October 2026 with AI assistance for code drafting under a human-directed plan. The author is expected to be able to explain every engine decision without assistance; `INTERVIEW_GUIDE.md` lists the questions that should be answerable.

## References

* OWASP API Security Top 10 — 2023 edition: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
* OWASP Top 10:2021 (A01 Broken Access Control): https://owasp.org/Top10/A01_2021-Broken_Access_Control/
* SARIF 2.1.0 (OASIS): https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

License: MIT (see `LICENSE`). Third-party notices in `THIRD_PARTY_NOTICES.md`.
