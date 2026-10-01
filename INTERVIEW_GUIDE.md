# INTERVIEW GUIDE — Permit Matrix

## The core engine in two minutes

The contract declares, per endpoint, which roles may call it and how the target object must relate to the caller (`any`, `own`, `same-tenant`), plus which fields may be written and which must never be returned. `generateCases` walks endpoint × principal × target (own / peer / cross-tenant) and derives an expectation from those rules, so every expectation is traceable to one sentence of policy. The mock server implements the same contract literally, with named flaws that switch off one check on one endpoint. The runner executes each case on a fresh server, compares outcome to expectation, and for property probes inspects server state the way an integration test would query the database. Findings are grouped per endpoint and mapped to OWASP API1/API3/API5:2023.

## One failure case to walk through

`PATCH /users/{id}` with `writableFields: ["displayName"]` and the `accept-all-fields` flaw. Riley (member) sends `{displayName: "Riley-tampered", role: "member-tampered"}`. Response is 200 either way, so the response alone proves nothing; the oracle reads the record after the write and sees `role` changed → verdict `mass-assignment`, severity high because `role` matches the privilege-bearing field pattern. On the fixed build the body is bound to the allow-list and `role` is unchanged → `pass`. Explain why checking the response is insufficient and why inspecting state is the honest oracle.

## Why the tests are shaped this way

* The first RED run failed because the engine modules did not exist; the second RED (after an external source review) failed on five concrete gaps: UTF-16 vs UTF-8 byte limit, duplicate record ids, `1e999` → `Infinity`, uncapped builds/flaws/servers, and a real `RangeError` from spreading a 200 000-element array. Each got a regression test before the fix.
* "Zero findings on the remediated build" is the most important test: it proves the generator does not manufacture false positives from the contract itself.
* "Over-deny is not a pass" encodes the view that an authorization tester must distinguish *secure* from *broken*.

## A reviewer-found bug worth telling

An independent reviewer added a second `GET /invoices/{id}` endpoint (admin, `any`) to the fixture. Validation accepted it, the router sent every request to the first registration, and the *remediated* build reported false `function-bypass` and `over-deny` findings against the new endpoint. The fix was to reject duplicate method + path templates at validation (plus only-`{id}` parameters and literal-before-parameter routing), with regression tests written before the change. Lesson: an authorization tester that can produce findings against a flawless server is worse than none.

## Production next steps

1. Replace the mock with an adapter that records and replays real HTTP exchanges from an **authorised** staging environment, keeping the same case generator and verdict logic.
2. Import OpenAPI 3.1 with a vendor extension for ownership rules, instead of the bespoke schema.
3. Add attribute-based conditions (time, status, delegated access) and multi-parameter paths.
4. Persist runs with signed provenance so a retest can prove which build was tested.

## Honest boundaries

This is an educational simulator. It does not make anyone a penetration tester; it demonstrates that the candidate can model authorization, generate negative tests, and explain findings to engineers and managers.
