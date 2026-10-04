# INTERVIEW GUIDE — Permit Matrix

## The core engine in two minutes

The contract declares, per endpoint, which roles may call it and how the target object must relate to the caller (`any`, `own`, `same-tenant`), plus which fields may be written and which must never be returned. `generateCases` walks endpoint × principal × target (own / peer / cross-tenant), adds a synthetic *anonymous* caller for every endpoint, and derives an expectation from those rules, so every expectation is traceable to one sentence of policy. The mock server implements the same contract literally, with named flaws that switch off one check on one endpoint. The runner executes each case on a fresh server, compares outcome to expectation, and for property probes inspects server state the way an integration test would query the database. Findings are grouped per endpoint and mapped to OWASP API1/API2/API3/API5:2023; a second run can be diffed against the first.

## One failure case to walk through

`PATCH /users/{id}` with `writableFields: ["displayName"]` and the `accept-all-fields` flaw. Riley (member) sends `{displayName: "Riley-tampered", role: "member-tampered"}`. Response is 200 either way, so the response alone proves nothing; the oracle reads the record after the write and sees `role` changed → verdict `mass-assignment`, severity high because `role` matches the privilege-bearing field pattern. On the fixed build the body is bound to the allow-list and `role` is unchanged → `pass`. Explain why checking the response is insufficient and why inspecting state is the honest oracle.

## A second failure case: the route nobody authenticates

Helpdesk's `GET /tickets/export` is admin-only, `ownership: any`. Under `skip-authentication` the anonymous case — a request with **no** `Authorization` header — gets `200` and the verdict is `bypass`, reported as API2:2023 *Broken Authentication*, not as an authorization finding. Be ready to explain why the anonymous row is generated for every endpoint rather than only for sensitive ones (the bug class is "this route was never wired to the auth middleware", which has nothing to do with how sensitive the route looks), why `401` and `403` both count as a pass for that row (either proves the request was stopped before the handler), and why the mock must *route before it authenticates* for this flaw to be expressible per endpoint.

## Why the tests are shaped this way

* The first RED run failed because the engine modules did not exist; the second RED (after an external source review) failed on five concrete gaps: UTF-16 vs UTF-8 byte limit, duplicate record ids, `1e999` → `Infinity`, uncapped builds/flaws/servers, and a real `RangeError` from spreading a 200 000-element array. Each got a regression test before the fix.
* "Zero findings on the remediated build" is the most important test and is now asserted for **both** fixtures and for the OpenAPI rendition: it proves the generator does not manufacture false positives from the contract itself — including the new anonymous, create and listing probes.
* "Over-deny is not a pass" encodes the view that an authorization tester must distinguish *secure* from *broken*.
* The upgrade's new behaviour was also written test-first: each module's tests were run against a stub exposing the final signatures, so the recorded RED runs are assertion failures on missing behaviour, not import errors (see `EVIDENCE.md`).

## A reviewer-found bug worth telling

An independent reviewer added a second `GET /invoices/{id}` endpoint (admin, `any`) to the fixture. Validation accepted it, the router sent every request to the first registration, and the *remediated* build reported false `function-bypass` and `over-deny` findings against the new endpoint. The fix was to reject duplicate method + path templates at validation (plus only-`{id}` parameters and literal-before-parameter routing), with regression tests written before the change. Lesson: an authorization tester that can produce findings against a flawless server is worse than none. The contract linter generalises the same lesson: it warns about a listing scoped wider than its item route, a flaw that cannot change behaviour, or a principal with no record to own — policies that silently produce fewer or misleading cases.

## A defect the upgrade found in its own baseline

Two automated checks caught real problems in the version that shipped before this cycle. A headless-browser axe pass showed the import dialog's error list carried `role="alert"` on the `<ul>` itself, orphaning its `<li>` children (axe `listitem`, serious); the live region is now a persistent wrapper around a plain list. And the app-level keyboard test showed that closing the import dialog dropped focus to `<body>`, because the opener is a toolbar button rather than a Radix `Dialog.Trigger`; the dialog now returns focus by id. Both are small, both were invisible to the unit tests that existed, and both are the reason the UI tests run in jsdom with axe and the release QA runs in a real browser.

## Why a diff, and why not store it

Toggling a flaw and re-running answers "is it fixed?" only if you can see what moved. `diffRuns` matches cases by id and findings by endpoint + kind and reports fixed / introduced / persisting findings and improved / regressed cases. It is kept in memory only: the project's rule is no storage APIs, so a retest that must be *provable* belongs with the signed-provenance idea below, not with `localStorage`.

## Why SARIF and OpenAPI, and where they stop

SARIF 2.1.0 is the interchange format security tooling already ingests; the export carries findings, rules and the OWASP mapping but deliberately no request or response bodies. The OpenAPI importer exists because contracts are usually born as OpenAPI documents, but OpenAPI cannot express principals, records or ownership — so the `x-permitmatrix` extensions carry exactly that and nothing else, `$ref` is refused rather than resolved, and the converted document goes through the same bounded validator as native JSON. Be ready to say why the importer renames any single path parameter to `{id}` instead of supporting arbitrary names (one router, one proven routing rule).

## Why the bundle is verified, not just the source

The README promises "no network, no storage". Three independent checks make that promise falsifiable: ESLint forbids the APIs in `src/`, the mock is a function, and `scripts/verify-dist.mjs` scans the built bundle. The third check paid for itself immediately: the first bundle it scanned contained one `fetch(` — Vite's module-preload polyfill, dead code in a single-chunk app — which is now switched off in the build config. Explain why scanning `dist/` catches things a source lint cannot (dependencies and build tooling), and why the verifier's host allow-list carries a justification per entry instead of a wildcard.

## Production next steps

1. Replace the mock with an adapter that records and replays real HTTP exchanges from an **authorised** staging environment, keeping the same case generator and verdict logic.
2. Attribute-based conditions (time, status, delegated access) and multi-parameter paths.
3. Persist runs with signed provenance so a retest can prove which build was tested.
4. Create-time probes for fields that exist on no record yet (unknown-field injection).

## Honest boundaries

This is an educational simulator. It does not make anyone a penetration tester; it demonstrates that the candidate can model authentication and authorization, generate negative tests, verify a remediation, and explain findings to engineers and managers.
