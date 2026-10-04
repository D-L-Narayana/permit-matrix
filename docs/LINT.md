# Contract lint (policy health)

`lintContract(contract)` in `src/engine/lint.ts` inspects an already **valid** contract and reports places
where the policy is inconsistent or where the generated suite could not exercise what the contract claims.
Validation (`validateContract`) answers "is this a contract?"; lint answers "will testing this contract
actually prove anything?".

Lint is **advisory**. It never blocks an import or a run, it changes no case and no verdict, and a contract
with warnings runs exactly like one without. Warnings are shown in the **Contract health** panel and can be
carried into the exported report.

```ts
import { lintContract, LINT_RULES } from './engine/lint';
import type { LintCode } from './engine/lint';

const warnings = lintContract(contract); // ContractWarning[] with code: LintCode
```

Each warning is `{ code, severity, path, message }`:

- `code` — one of the ten codes below.
- `severity` — `warn` (a probable mistake, or a hole that silently weakens a run: a flaw the suite cannot
  catch, a matrix column that can never contain a case) or `info` (a limitation worth knowing about that
  may well be intended).
- `path` — the location in the contract document, e.g. `endpoints[2].writableFields[1]` or
  `builds.vulnerable.flaws[0]`. Indices follow the order of the source JSON (validation preserves order).
- `message` — a plain sentence saying what was found, why it matters and how to fix it.

The list is sorted by `path` (array indices compared numerically, so `records[2]` precedes `records[10]`),
then by `code`, then by `message`. The same contract always produces the same list.

## Codes

| Code | Severity | Fires when |
|---|---|---|
| `unused-role` | warn | A role that no principal carries. |
| `principal-without-records` | warn | A principal may call an `own`-scoped `{id}` endpoint of a resource but owns no record in it. |
| `single-tenant` | info | Every principal shares one tenant. |
| `field-not-on-records` | warn | A writable or sensitive field name appears on no record of the resource. |
| `writable-on-read-endpoint` | warn | `writableFields` on a GET or DELETE endpoint. |
| `sensitive-on-write-endpoint` | info | `sensitiveFields` on a POST, PUT, PATCH or DELETE endpoint. |
| `list-item-scope-mismatch` | warn | `GET <path>` and `GET <path>/{id}` on the same resource disagree on ownership. |
| `record-tenant-mismatch` | warn | A record's tenant differs from its owner's tenant. |
| `no-negative-cases` | info | Every role allowed, ownership `any`, and no property probe possible. |
| `noop-flaw` | warn | A seeded flaw that no generated case could observe. |

### `unused-role` (warn) — path `roles[i]`

**Detects** a role in `roles` that no entry in `principals` uses.

**Why it matters.** Cases are generated per principal, so the matrix column for this role is empty. Any
endpoint that lists the role in `access.roles` is never exercised as that role: an over-broad allow-list
entry would pass unnoticed.

**Fix.** Add a principal with the role (ideally one per tenant) or remove the role from `roles` and from
every `access.roles`.

### `principal-without-records` (warn) — path `resources[i].records`

**Detects** a principal whose role is allowed on at least one `own`-scoped endpoint with `{id}` in its path
for resource `i`, but who owns no record in that resource.

**Why it matters.** The generator derives the *own* target from a record the principal owns. Without one,
the principal's allowed path through that endpoint is never exercised: an over-deny against this principal
is invisible and the own pin in its cell is simply absent. Principals whose role the endpoint does not
allow are not reported — they would only produce role denials, for which any record will do. Collection
endpoints are not considered: a list scoped to the caller may legitimately be empty.

**Fix.** Add a record owned by the principal to the resource, or change the endpoint's `ownership`.

### `single-tenant` (info) — path `principals`

**Detects** that all principals share one tenant.

**Why it matters.** Cross-tenant targets are records whose tenant differs from the caller's; with a single
tenant none exist, so `same-tenant` rules are never tested across a boundary and every cross-tenant pin is
absent. This is a coverage limitation rather than an error.

**Fix.** Add at least one principal, and records it owns, in a second tenant.

### `field-not-on-records` (warn) — path `endpoints[i].writableFields[j]` or `endpoints[i].sensitiveFields[j]`

**Detects** a field name in `writableFields` or `sensitiveFields` that appears on no record of the
endpoint's resource.

**Why it matters.** Mass-assignment probes are built from the fields a record actually has that are *not*
writable, and sensitive-read probes look for the named field in responses. A name that exists on no record
is usually a typo: the sensitive probe can never fail (the field is never there to leak), and the writable
entry quietly protects nothing.

**Fix.** Correct the spelling, or add the field to the resource's records so the probe is real.

### `writable-on-read-endpoint` (warn) — path `endpoints[i].writableFields`

**Detects** `writableFields` on a GET or DELETE endpoint.

**Why it matters.** Those methods carry no request body, so no mass-assignment probe is generated and the
list is dead configuration. It usually belongs to the PATCH, PUT or POST route of the same resource.

**Fix.** Move the list to the write endpoint or remove it.

### `sensitive-on-write-endpoint` (info) — path `endpoints[i].sensitiveFields`

**Detects** `sensitiveFields` on a POST, PUT, PATCH or DELETE endpoint.

**Why it matters.** Sensitive-read probes are generated only from a GET endpoint's own `sensitiveFields`.
Declaring the list on a write endpoint does make the mock strip the field, but no case checks that a write
response (or the corresponding read) stays clean, so the protection is untested.

**Fix.** Declare the same `sensitiveFields` on the GET endpoint(s) of the resource; keep or drop the write
endpoint's copy as documentation.

### `list-item-scope-mismatch` (warn) — path `endpoints[i].access.ownership` (the collection endpoint)

**Detects** a GET collection endpoint and the GET item endpoint whose path is exactly
`<collection path>/{id}` on the same resource whose `access.ownership` values differ.

**Why it matters.** The two routes describe the same objects. If the listing is wider than the item route,
it enumerates records (and their ids) the item route would refuse — an information leak that is the usual
first step of a BOLA attack. If it is narrower, the item route allows records the user can never discover.
Each route is self-consistent, so no single case fails; only a cross-route comparison reveals the
contradiction. Literal siblings such as `GET /tickets/export` are separate operations and are *not*
compared with `GET /tickets/{id}`.

**Fix.** Give both routes the same `ownership`.

### `record-tenant-mismatch` (warn) — path `resources[i].records[j].tenant`

**Detects** a record whose `tenant` differs from the `tenant` of the principal named in `owner`.

**Why it matters.** Targets are picked by owner and tenant: *own* means owned by the caller, *peer* means
same tenant but another owner, *cross-tenant* means another tenant. A record owned by a caller but filed in
a foreign tenant is simultaneously *own* and *cross-tenant*, so an `own` endpoint expects allow while a
`same-tenant` endpoint expects deny for the very same record — the expectations become contradictory.

**Fix.** Set the record's `tenant` to the owner's tenant, or change the `owner`.

### `no-negative-cases` (info) — path `endpoints[i].access`

**Detects** an endpoint where every role in `roles` is allowed, `ownership` is `any`, and no property probe
can be generated: a GET without `sensitiveFields`; a POST, PUT or PATCH without `writableFields` (or whose
`writableFields` already cover every field found on the resource's records); any DELETE.

**Why it matters.** Apart from the anonymous row (which always expects a 401), every generated case for
this endpoint expects success, so the endpoint can only pass or over-deny — it can never reveal a bypass.
That may be intended for an endpoint that is genuinely open to every authenticated user, which is why this
is informational.

**Fix.** If the openness is unintended, narrow `access.roles` or the `ownership`, or declare
`writableFields` / `sensitiveFields` so property probes exist.

### `noop-flaw` (warn) — path `builds.<key>.flaws[j]`

**Detects** a seeded flaw that no generated case could observe:

- `skip-ownership-check` on an endpoint whose ownership is already `any`, or on a POST collection
  endpoint (creating a record performs no ownership check);
- `accept-all-fields` on a GET or DELETE endpoint (no request body), or on a write endpoint without
  `writableFields` (or whose list already covers every known field), so no mass-assignment probe exists;
- `return-sensitive-fields` on a non-GET endpoint (write responses are not checked for leaks), or on a GET
  endpoint that declares no `sensitiveFields` of its own — including the case where the resource has no
  sensitive fields on any endpoint;
- `skip-role-check` on an endpoint that already allows every role.

`deny-everything` and `skip-authentication` always change at least one verdict and are never reported.

**Why it matters.** A "vulnerable" build that the suite reports clean teaches the wrong lesson: the flaw
list claims a weakness the demo cannot demonstrate, and a reader may conclude the check is unnecessary.

**Fix.** Remove the flaw, or change the endpoint (narrow its scope or roles, declare the fields) so that a
case exists which the flaw would flip.

## Why the shipped fixtures lint clean

Both demo contracts produce an empty list by design, and the test suite asserts it:

- **Ledgerly**: two tenants; every principal owns an invoice and a user record; `GET /invoices` and
  `GET /invoices/{id}` are both `own`; every writable and sensitive field exists on the records; every
  seeded flaw flips at least one case.
- **Helpdesk**: `GET /tickets` and `GET /tickets/{id}` are both `same-tenant`; `GET /tickets/export` is a
  literal sibling and is not compared with the item route; `POST /tickets` is open to every role with
  ownership `any` but declares `writableFields`, so create probes exist and `no-negative-cases` stays
  silent; `tickets` has no `own`-scoped endpoint, so `principal-without-records` does not apply.

## Contract health panel

`LintPanel({ warnings, compact? })` in `src/features/lint/LintPanel.tsx` renders
`<section aria-label="Contract health">` with the heading "Contract health", a one-line "No warnings" state
or a list with a severity badge, the code and path in `<code>`, and the message. Everything is rendered as
text nodes. Severity colours stay away from the security verdicts: `warn` borrows the amber attention tone
that also marks over-deny (itself a functional, not a security, signal) and `info` uses a neutral ink; the
pass, bypass and exposure colours are never used, so a contract-authoring note is not mistaken for a
security verdict.

## Not covered

Lint reasons about the contract alone. It does not run the mock, does not inspect responses and does not
replace validation errors: a contract that fails `validateContract` is never linted. Rules are tuned so
that a well-formed contract is quiet; when a rule misfires on a legitimate design, treat the warning as a
prompt to document the decision rather than as a defect in the contract.
