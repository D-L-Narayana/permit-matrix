# Permit Matrix — API authorization contract tester

[Open the public educational demo](https://dln-permit-matrix.vercel.app). It runs only against an in-browser synthetic mock, not a real API.

**Educational prototype (October 2026).** Permit Matrix turns a small, local API contract into a complete set of authorization test cases — every role against every endpoint against *own*, *peer* and *cross-tenant* records, plus property-level probes — and runs them against a deterministic mock server that lives entirely inside the browser tab. It is a teaching and portfolio tool for reasoning about OWASP API Security Top 10 (2023) authorization classes. It is **not** a penetration-testing tool, it never contacts a network host, and nothing here is a security certification or compliance opinion.

## What problem it addresses

Object-level (API1:2023), property-level (API3:2023) and function-level (API5:2023) authorization bugs are usually found one endpoint at a time, by hand. The repeatable way to check them is a matrix: *who* may do *what* to *whose* data, with a negative case for every cell. Permit Matrix makes that matrix explicit, generates the negative cases automatically, and shows precisely which contract rule each verdict rests on.

## Key workflows

1. **Start with the synthetic Ledgerly contract** (3 roles, 4 principals across 2 tenants, 2 resources, 6 endpoints). The vulnerable build `release/1.4.0` has four seeded flaws; `release/1.4.1` has none. The list route and the item route for invoices share the same `own` scope on purpose: a member sees only their own invoices in the listing, so the item-route BOLA is the only way to reach a peer's record.
2. **Run the suite.** 83 cases are generated and executed. Each matrix cell shows three pins (own · peer · cross-tenant) and a dot per property probe.
3. **Inspect a cell.** The case ledger lists each case with its expectation and rationale, the redacted request, the response, and the verdict explanation.
4. **Toggle individual server flaws** or switch to the remediated build and re-run; findings disappear or change accordingly. The `deny-everything` style flaw demonstrates that over-denial is reported as a functional regression, not a security pass.
5. **Import your own contract** (synthetic data only). Validation enforces the schema, bounded sizes and a hard rule that `servers` contains only `mock://` or loopback targets — anything else is refused with `External target refused`.
6. **Export** a JSON report (`permitmatrix.report/1`) or a Markdown memo with findings, remediation guidance and the coverage table.

## Quickstart

```bash
npm ci
npm test        # vitest, 23 engine tests
npm run build   # tsc --noEmit + vite build → dist/
npm run dev     # http://localhost:6110
```

Node 20 or newer. No environment variables, no backend, no storage APIs: session state lives in memory and resets on refresh (export the report to keep it).

## Algorithm

**Case generation** (`src/engine/cases.ts`) — for every endpoint × principal:

* If the endpoint has no `{id}`, one *collection* case. Expected `allow` iff the principal's role is in `access.roles`.
* Otherwise pick up to three target records from the endpoint's resource: one owned by the principal, one owned by someone else in the same tenant, one in another tenant. Expectation:
  * role not allowed → `deny`, category **function**;
  * `ownership: any` → `allow`;
  * `ownership: own` → `allow` only for the principal's own record;
  * `ownership: same-tenant` → `allow` only for records in the principal's tenant.
* For each expected-`allow` case on a `PATCH`/`PUT` endpoint with `writableFields`, add one **property** probe per non-writable field in the target record. For each expected-`allow` `GET` case with `sensitiveFields`, add one probe per sensitive field.

**Mock server** (`src/engine/mockServer.ts`) — implements the contract literally: authenticate principal → route → role check → body validation → record lookup → ownership check → method semantics. **Routing:** validation rejects two endpoints with the same method and path template (otherwise one policy would silently judge another endpoint's cases), allows only `{id}` as a parameter name and at most once, and the router tries literal routes before parameterised ones, so `/invoices/export` is matched before `/invoices/{id}` regardless of declaration order. Each flaw switches off exactly one check for exactly one endpoint. Responses strip every field marked sensitive anywhere on that resource unless the `return-sensitive-fields` flaw is on.

**Runner** (`src/engine/runner.ts`) — one fresh server per case so destructive cases cannot influence each other. Verdicts:

| Verdict | Meaning |
|---|---|
| `pass` | Behaviour matched the contract |
| `bypass` | Expected deny, got 2xx (or a listing leaked out-of-scope records) |
| `over-deny` | Expected allow, got 403 — reported as a functional regression, not as safety |
| `mass-assignment` | Server state shows a non-writable field changed (the oracle inspects state after the write, like an integration test querying the database) |
| `exposure` | A sensitive field appeared in the response body |
| `error` | 400/401/404/405/5xx — the case could not be evaluated |

Findings are aggregated per endpoint and kind, mapped to API1/API3/API5:2023, with a documented severity rubric (object and function bypasses are high; mass assignment is high when the probed field looks like `role`, `status`, `owner`, `tenant`, `price` or `amount`; exposure is high when the field looks like a credential or hash). Coverage counts cases per endpoint × role.

## Architecture

```
src/engine/   pure TypeScript, no DOM: types, contract validation, case generation, mock server, runner, report
src/fixtures/ synthetic Ledgerly contract (.example domains, fictional people)
src/App.tsx   single-view React UI (matrix, case ledger, findings, import dialog)
```

Engine code has no React imports and is exercised directly by the tests. The UI holds state in React only.

## Tests

`src/engine/__tests__/engine.test.ts` — 28 tests across validation (including the sixth-Fable regressions: duplicate method+path refused, only `{id}` parameters, literal-before-parameter routing, list/item scope consistency, export data note), (including refusal of external targets, limits, duplicate ids, non-finite numbers, hostile list sizes), case generation (expectations, categories, determinism), the mock server (fixed vs vulnerable behaviour, 401/404), the runner (zero findings on the remediated build, the four seeded flaws classified with OWASP ids, over-deny, coverage) and report redaction. Tests were written before the engine; see `EVIDENCE.md` for the recorded failing and passing runs.

## Data handling and safety

* Browser-local only. There is no `fetch`, no WebSocket, no storage API, no analytics.
* Contracts are bounded: 64 KB (UTF-8 bytes), 40 endpoints, 8 roles, 24 principals, 12 resources, 100 records each, nesting depth 6, list length 1000. Oversized or malformed input is rejected with a visible message.
* `servers` must be `mock://…` or `localhost`/`127.0.0.1`/`[::1]`; the app has no code path that would send a request anywhere even if it were not.
* Exported reports redact the `Authorization` header to `Bearer [redacted:<principal>]`. **Response bodies are not redacted** — they are the evidence of what the mock returned, including fields the contract marks sensitive (e.g. the fictional `passwordHash` values). The report carries a `dataNote` saying so; never load a contract containing real records.
* All fixture identities and domains are fictional (`acme.example`, `globex.example`).

## Limitations and unsupported cases

* The mock server is an idealised implementation of the contract. Findings describe the mock's behaviour under seeded flaws, not any real system. Running the tool proves nothing about production software.
* Expectations come from the contract. If the contract is wrong, the matrix is wrong; the tool cannot discover undocumented authorization rules.
* Only one path parameter, spelled `{id}`, is supported per route; no query parameters, pagination, nested resources, attribute-based conditions, rate limits or time-based rules.
* Property-write probes cover PATCH/PUT fields already present on a target record. POST/create mass assignment and injection of previously unknown fields are not probed; the shipped fixture has no POST endpoint.
* No OpenAPI import. The contract is a purpose-built JSON schema (`permitmatrix.contract/1`), documented by the fixture.
* Severity is a transparent rubric, not CVSS.
* Reset-on-refresh is deliberate (no storage APIs), so imported contracts must be re-imported.

## JD evidence (truthful framing)

This project demonstrates: API/web application-security assessment reasoning (authorization matrices, negative testing, OWASP API Security Top 10:2023 mapping), API integration concepts (contract-driven request generation), analytical write-ups (per-case rationale, findings with remediation), test-first TypeScript engineering, and secure-by-default input handling. It does **not** constitute professional penetration-testing experience, a security certification or any client engagement.

## AI-assistance disclosure

Built in October 2026 with AI assistance for code drafting under a human-directed plan. The author is expected to be able to explain every engine decision without assistance; `INTERVIEW_GUIDE.md` lists the questions that should be answerable.

## References

* OWASP API Security Top 10 — 2023 edition: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
* OWASP Top 10:2021 (A01 Broken Access Control): https://owasp.org/Top10/A01_2021-Broken_Access_Control/

License: MIT (see `LICENSE`). Third-party notices in `THIRD_PARTY_NOTICES.md`.
