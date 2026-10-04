# Contract reference — `permitmatrix.contract/1`

A contract is the single input to Permit Matrix. It declares *who* can call the API (roles and
principals with tenants), *what* exists (resources with seed records and their owners), *which
operations* are under test (endpoints with an access rule) and *which server builds* seed flaws into
the in-browser mock. Everything the tool does — case generation, the mock server, verdicts, findings —
is derived from it, so a wrong contract yields a wrong matrix.

Two input formats are accepted (`importAny` in `src/engine/openapi.ts` detects which one was pasted):

| Format | Detected by | Handled by |
|---|---|---|
| Permit Matrix contract | top-level `"schema": "permitmatrix.contract/1"` | `validateContract` |
| OpenAPI 3.x (JSON) with the `x-permitmatrix` extension | top-level `"openapi": "3.…"` | `openapiToContract`, then `validateContract` |

Anything else is refused with a message naming both formats. YAML is not accepted; convert it to JSON
first. All data must be synthetic — the mock returns record fields verbatim in evidence, and exported
reports do not redact response bodies.

## 1. Document layout

```json
{
  "schema": "permitmatrix.contract/1",
  "name": "Ledgerly Billing API (synthetic demo)",
  "version": "1.4.0",
  "servers": ["mock://ledgerly.example"],
  "roles": [ { "id": "admin", "label": "Admin" } ],
  "principals": [ { "id": "p-admin-1", "role": "admin", "tenant": "acme.example", "label": "Avery (admin)" } ],
  "resources": [ { "id": "invoices", "label": "Invoices", "records": [ … ] } ],
  "endpoints": [ { "id": "get-invoice", "method": "GET", "path": "/invoices/{id}", "resource": "invoices",
                   "access": { "roles": ["admin"], "ownership": "own" } } ],
  "builds": { "vulnerable": { "label": "release/1.4.0 (vulnerable)", "flaws": [ … ] } }
}
```

Unknown **top-level** keys (for example `$schema` or editor metadata) are ignored. Unknown keys inside a
known section are not an error either, but they are dropped on load: `validateContract` returns a
normalised copy containing only the fields below. Normalisation is a fixpoint — validating an accepted
contract again yields a deep-equal result.

### Top level

| Field | Type | Rules |
|---|---|---|
| `schema` | string | Must be exactly `"permitmatrix.contract/1"`. |
| `name` | string | 1–200 characters. Shown in the header and in reports. |
| `version` | string | 1–200 characters. Part of the exported file names. |
| `servers` | string[] | 1–4 entries. Each must be `mock://<host>` or an `http(s)://` URL whose host is `localhost`, `127.0.0.1` or `[::1]`. Any other target is refused with **`External target refused`**. The tool has no code path that sends traffic anywhere; the rule exists so a contract can never even *describe* a real host. |
| `roles` | Role[] | 1–8 entries, unique ids. |
| `principals` | Principal[] | 1–24 entries, unique ids. |
| `resources` | Resource[] | 1–12 entries, unique ids. |
| `endpoints` | Endpoint[] | 1–40 entries, unique ids, unique `method + path`. |
| `builds` | object | Optional. 0–8 builds keyed by build id. A `fixed` build with no flaws is added when absent. |

### Role

| Field | Type | Rules |
|---|---|---|
| `id` | id | Identifier (see §2). `anonymous` in any letter case is **reserved** for the synthetic unauthenticated caller. |
| `label` | string | ≤ 200 characters; the matrix column header. |

### Principal

| Field | Type | Rules |
|---|---|---|
| `id` | id | Unique; `anonymous` (any case) is reserved. |
| `role` | id | Must be the id of a declared role. |
| `tenant` | string | ≤ 200 characters. Compared with record tenants for `same-tenant` scopes and to pick cross-tenant targets. |
| `label` | string | ≤ 200 characters. |

### Resource and records

| Field | Type | Rules |
|---|---|---|
| `id` | id | Unique across resources. |
| `label` | string | ≤ 200 characters. |
| `records` | Record[] | 0–100 seed rows. Case generation picks, per principal, one record it owns, one owned by someone else in its tenant and one in another tenant; a resource with no records yields no object-level cases. |
| `records[].id` | id | Unique within the resource. Used as the `{id}` path value. |
| `records[].owner` | id | Must be the id of a declared principal; `anonymous` is reserved. |
| `records[].tenant` | string | ≤ 200 characters. Normally equal to the owner's tenant. |
| `records[].fields` | object | 0–24 scalar values (string, finite number, boolean or `null`) keyed by field name. Field names follow the id pattern; `__proto__`, `constructor` and `prototype` are reserved. Nested objects and arrays are refused. |

### Endpoint

| Field | Type | Rules |
|---|---|---|
| `id` | id | Unique. Case ids are `<endpoint id>|<principal>|<target>[|probe]`. |
| `method` | enum | `GET`, `POST`, `PUT`, `PATCH` or `DELETE` (upper case). |
| `path` | string | `/` followed by literal segments (`[A-Za-z0-9_-]+`) and **at most one** parameter, which must be spelled `{id}`. Empty segments, trailing slashes, other parameter names and two parameters are refused. Max 121 characters. Each `method + path` pair may appear once so every request maps to exactly one policy; literal routes are matched before parameterised ones, so `/invoices/export` is safe next to `/invoices/{id}`. |
| `resource` | id | Must be the id of a declared resource. |
| `access.roles` | id[] | 1–8 **distinct** ids of declared roles. A missing or empty list is an error (an endpoint nobody may call would silently test nothing). |
| `access.ownership` | enum | `any` (role check only), `own` (only records whose `owner` is the caller) or `same-tenant` (only records in the caller's tenant). |
| `writableFields` | id[] | Optional, distinct. For `PATCH`/`PUT` on `{id}` routes: every other field present on the target record gets a write probe that must leave it unchanged. For `POST` collection routes: every field known on the resource's records that is not writable gets a probe that must not land on the created record. |
| `sensitiveFields` | id[] | Optional, distinct. For `GET`: a probe per field that must never appear in the response body — on item routes and on collection listings. |

### Build and flaw

| Field | Type | Rules |
|---|---|---|
| build key | id | Unique object key; `__proto__`, `constructor`, `prototype` are reserved. |
| `label` | string | ≤ 200 characters; shown in the "Server build" selector. |
| `flaws` | Flaw[] | 0–40 entries. |
| `flaws[].endpoint` | id | Must be the id of a declared endpoint. |
| `flaws[].kind` | enum | `skip-ownership-check`, `skip-role-check`, `accept-all-fields`, `return-sensitive-fields`, `deny-everything`, `skip-authentication`. Each flaw switches off exactly one check for exactly one endpoint in the mock. |

## 2. Identifiers, paths and strings

| Rule | Definition |
|---|---|
| id | `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` — 1–64 characters, starts with a letter or digit. |
| reserved ids | `anonymous`, matched case-insensitively, for role ids, principal ids and record owners. |
| reserved names | `__proto__`, `constructor`, `prototype` for record field names, writable/sensitive entries and build keys. |
| path | `/` + segments of `[A-Za-z0-9_-]+` or exactly one `{id}`; ≤ 121 characters. |
| string | every string the validator reads as a name, version, label, tenant, server or id is ≤ 200 characters (`LIMITS.maxStringLength`); `name` and `version` must also be non-empty. Record field *values* are only required to be scalars. |

## 3. Limits

All limits live in `LIMITS` (`src/engine/contract.ts`) and are enforced before any content is read, by an
iterative structural scan that cannot be made to recurse.

| Limit | Value | Applies to |
|---|---|---|
| `maxBytes` | 65 536 (64 KB, UTF-8 bytes) | Pasted or uploaded text, measured in bytes, not characters. |
| `maxEndpoints` | 40 | `endpoints` |
| `maxRoles` | 8 | `roles`, and therefore `access.roles` |
| `maxPrincipals` | 24 | `principals` |
| `maxResources` | 12 | `resources` |
| `maxRecordsPerResource` | 100 | `resources[].records` |
| `maxFieldsPerRecord` | 24 | keys of `records[].fields` |
| `maxStringLength` | 200 | every validated string (ids, labels, tenants, servers, name, version); record field values are only required to be scalars |
| `maxDepth` | 6 | nesting of the whole document (`resources[i].records[j].fields.<key>` is depth 6) |
| `maxServers` | 4 | `servers` |
| `maxBuilds` | 8 | keys of `builds` |
| `maxFlawsPerBuild` | 40 | `builds[].flaws` |
| `maxListLength` | 1 000 | any array or object encountered while scanning; longer lists are rejected without being walked |
| (fixed) | 50 000 | total number of values in the document |

## 4. Validation errors

`validateContract` reports **every** problem it finds, not just the first, as `errors: string[]` in the
form `<path>: <message>` (or the bare message when the problem concerns the whole document), together
with the same list as `issues: { path, message }[]`. Paths address the offending value:
`endpoints[2].access.roles[1]`, `resources[0].records[3].fields.role`, `builds.vulnerable.flaws[0].kind`.

Messages are plain sentences and some are stable regex targets used by the tests:
`External target refused`, `duplicate record id …`, `duplicate route GET /invoices/{id}`, `only {id}`,
`… bytes (UTF-8)`, `finite`, `reserved`.

## 5. JSON Schema

`public/schema/permitmatrix.contract-1.schema.json` is a JSON Schema (draft 2020-12) for the format,
published with the app at

```
https://dln-permit-matrix.vercel.app/schema/permitmatrix.contract-1.schema.json
```

Point an editor at it with `"$schema": "https://dln-permit-matrix.vercel.app/schema/permitmatrix.contract-1.schema.json"`
(the validator ignores that top-level key), or validate programmatically:

```ts
import Ajv2020 from 'ajv/dist/2020';
import schema from './permitmatrix.contract-1.schema.json';

const validate = new Ajv2020({ strict: true, allowUnionTypes: true, allErrors: true }).compile(schema);
if (!validate(document)) console.log(validate.errors);
```

The schema mirrors `LIMITS` (array `minItems`/`maxItems`, `maxProperties`, string `maxLength` 200), the
id and path patterns, the `method`, `ownership` and flaw-kind enumerations, the scalar union for record
field values, the reserved `anonymous` id and the reserved field names, and `builds` as pattern
properties keyed by the id pattern.

**Passing the schema is necessary, not sufficient.** JSON Schema cannot express the cross-document rules,
so the following are checked only by `validateContract`:

* cross-references by id — principal → role, record owner → principal, endpoint → resource, `access.roles`
  → roles, flaw → endpoint;
* uniqueness of role, principal, resource, endpoint and record ids, and of `method + path` routes;
* the `mock://` / loopback-only rule for `servers`;
* the 64 KB UTF-8 byte limit, the 50 000-value ceiling and the depth limit of the raw text;
* normalisation (adding the `fixed` build, dropping unknown keys).

Conversely the schema never rejects a document the validator accepts: `src/engine/__tests__/schema.test.ts`
checks the shipped fixtures, the validator's own normalised output and the OpenAPI conversion against it,
and checks that every `LIMITS` value the schema can express (all but the byte, depth and value-count
limits of the raw text) appears in it unchanged.

## 6. OpenAPI 3.x import

Permit Matrix can import an OpenAPI 3.x document **as JSON** when it carries the `x-permitmatrix`
extension. OpenAPI describes operations; it has no notion of the principals who call them, the tenants
they belong to or the records they own, and it does not say who may call what. The extension supplies
exactly that, and nothing is guessed: an operation without its access rule is an error, not a default.

Conversion is pure and offline. No `$ref` is ever resolved, nothing is fetched, server URLs are passed to
the same loopback rule as hand-written contracts, and the result is handed to `validateContract`, so every
rule in §1–§3 applies. Problems reading the document are reported first (all of them, up to 40); validator
errors are then re-addressed to the document — `DELETE /users/{id} x-permitmatrix-resource: …`,
`x-permitmatrix.principals: …`, `servers[1].url: …`, `info.title: …`.

### Mapping

| OpenAPI | Contract | Notes |
|---|---|---|
| `openapi` | — | Must be a string starting with `3.`; `swagger: "2.0"` is not recognised. |
| `info.title` | `name` | Required. |
| `info.version` | `version` | Required. |
| `servers[].url` | `servers` | Required (OpenAPI's implicit default server `/` is not a target the tool can use). Server variables (`{…}`) are not expanded and are refused. Path- and operation-level `servers` are ignored with a note. |
| `x-permitmatrix.roles` | `roles` | Required. Same shape as the contract. |
| `x-permitmatrix.principals` | `principals` | Required. |
| `x-permitmatrix.resources` | `resources` | Required, including `records`. |
| `x-permitmatrix.builds` | `builds` | Optional. Flaw `endpoint` values are operation ids. |
| `paths./template.<method>.operationId` | `endpoints[].id` | Required and must satisfy the id rule (§2); the error names the operation (`GET /invoices: operationId is required …`, `GET /invoices: operationId "list invoices" must be …`). |
| `<method>` | `endpoints[].method` | `get`, `post`, `put`, `patch`, `delete`. `head`, `options`, `trace` and `query` operations are **skipped with a note**; path-item fields (`summary`, `description`, `parameters`, `servers`, `x-…`) are not operations and produce no note; upper-case method keys and unknown keys are ignored **with a note**. |
| `/template` | `endpoints[].path` | Zero or **one** path parameter of any name; the parameter is renamed to `{id}` with a note (`GET /invoices/{invoiceId}: parameter renamed to {id}`). Two or more parameters are an error. Templates that differ only by parameter name collapse to the same route and are refused as duplicates. |
| `x-permitmatrix-resource` | `endpoints[].resource` | Required per operation. |
| `x-permitmatrix-access` | `endpoints[].access` | Required per operation: `{ "roles": [...], "ownership": "any" \| "own" \| "same-tenant" }`. |
| `x-permitmatrix-writable` | `writableFields` | Optional list. When absent on `post`/`put`/`patch`, derived from the inline `requestBody.content.application/json.schema.properties` keys (any `…+json` media type such as `application/merge-patch+json` is accepted when there is no `application/json` entry); a note records the derived list. |
| `x-permitmatrix-sensitive` | `sensitiveFields` | Optional list, merged (list first, no duplicates) with every property flagged `"x-permitmatrix-sensitive": true` in the operation's request or response schemas. When only flags are present, a note records the derived list. |
| `$ref` anywhere used | error | Path items, operations, request bodies, responses and schemas must be inline: `… inline the schema (… uses $ref; $ref is not supported)`. Unused `components` are not read. |

Endpoint order follows the document: paths in declaration order, operations in key order within each
path item. Case ids and matrix rows therefore follow the OpenAPI document exactly.

### Structural caps

Before anything is read the whole document is scanned iteratively: at most 1 000 `paths`, at most 1 000
entries in any array or object, at most 50 000 values, nesting at most 40 levels (a response property
schema already sits about ten levels down), and only finite numbers. The converted contract is then subject to the
ordinary `LIMITS`. A document with five thousand paths or a fifty-thousand-level schema is refused with
a message, never with a stack overflow.

### Minimal example

```json
{
  "openapi": "3.1.0",
  "info": { "title": "Notes API (synthetic)", "version": "0.1.0" },
  "servers": [{ "url": "mock://notes.example" }],
  "x-permitmatrix": {
    "roles": [{ "id": "member", "label": "Member" }],
    "principals": [
      { "id": "p-1", "role": "member", "tenant": "acme.example", "label": "Ana" },
      { "id": "p-2", "role": "member", "tenant": "globex.example", "label": "Bo" }
    ],
    "resources": [{
      "id": "notes", "label": "Notes",
      "records": [
        { "id": "n-1", "owner": "p-1", "tenant": "acme.example", "fields": { "title": "Plan", "secret": "s1" } },
        { "id": "n-2", "owner": "p-2", "tenant": "globex.example", "fields": { "title": "Draft", "secret": "s2" } }
      ]
    }],
    "builds": { "leaky": { "label": "build 7 (leaky)", "flaws": [{ "endpoint": "get-note", "kind": "skip-ownership-check" }] } }
  },
  "paths": {
    "/notes/{noteId}": {
      "get": {
        "operationId": "get-note",
        "x-permitmatrix-resource": "notes",
        "x-permitmatrix-access": { "roles": ["member"], "ownership": "own" },
        "responses": { "200": { "description": "The note", "content": { "application/json": { "schema": {
          "type": "object",
          "properties": { "title": { "type": "string" }, "secret": { "type": "string", "x-permitmatrix-sensitive": true } }
        } } } } }
      },
      "patch": {
        "operationId": "patch-note",
        "x-permitmatrix-resource": "notes",
        "x-permitmatrix-access": { "roles": ["member"], "ownership": "own" },
        "requestBody": { "content": { "application/json": { "schema": {
          "type": "object", "properties": { "title": { "type": "string" } }
        } } } },
        "responses": { "200": { "description": "Updated" } }
      }
    }
  }
}
```

Importing it produces two endpoints (`GET /notes/{id}` with `sensitiveFields: ["secret"]`, `PATCH
/notes/{id}` with `writableFields: ["title"]`), the implicit `fixed` build, and four notes:

```
GET /notes/{noteId}: parameter renamed to {id}
GET /notes/{noteId}: sensitiveFields derived from schema properties flagged x-permitmatrix-sensitive [secret]
PATCH /notes/{noteId}: parameter renamed to {id}
PATCH /notes/{noteId}: writableFields derived from the request body schema [title]
```

(`src/engine/__tests__/openapi.test.ts` converts this exact document and asserts these outputs.)

The shipped `src/fixtures/ledgerly-openapi.json` is the OpenAPI twin of `ledgerly-contract.json`; the
tests assert that it converts to an identical contract and therefore to identical cases.

### Not supported

* YAML input, `components`/`$ref`, server variables, callbacks, webhooks, links.
* `security` / `securitySchemes` — authentication is modelled by the mock's bearer principals; Permit
  Matrix generates its own unauthenticated case per endpoint regardless of what the document declares.
* Query parameters, headers, cookies, multiple path parameters, nested resources.
* Deriving roles or principals from the document: there is nothing in OpenAPI to derive them from.
