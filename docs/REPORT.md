# Report formats

Permit Matrix exports one run in three shapes, all derived from the same `Report` object built by
`buildReport()` in `src/engine/report.ts`:

| Export | Function | File name | MIME type |
|---|---|---|---|
| JSON report | `buildReport()` → `JSON.stringify` | `permitmatrix-<version>-<build>.json` | `application/json` |
| Markdown memo | `reportToMarkdown(report)` | `permitmatrix-<version>-<build>.md` | `text/markdown` |
| SARIF 2.1.0 | `reportToSarif(report)` (`src/engine/sarif.ts`) | `permitmatrix-<version>-<build>.sarif.json` | `application/sarif+json` |

Everything is computed in the browser tab from the in-memory run. Nothing is fetched or stored; the
exports are plain `Blob` downloads. There is deliberately no CSV export (spreadsheet formula injection).

## `buildReport(contract, run, options)`

```ts
buildReport(contract: Contract, run: SuiteRun, options: {
  build: string;                 // build id selected in the UI (key of contract.builds)
  generatedAt?: string;          // ISO-8601; defaults to now. Pass a fixed value for reproducible output.
  flaws?: Flaw[];                // the flaws that were ACTIVE for this run (toggle switches), if known
  warnings?: ContractWarning[];  // linter output for the contract, if the linter ran
}): Report
```

- `build.flaws` lists the **active** flaws when `options.flaws` is given. Without it the report falls back to
  the build definition in the contract. Callers that let the user toggle individual flaws should always pass
  the active list, otherwise the report describes a build that was not the one actually exercised.
- `warnings` appears in the report only when `options.warnings` is provided (an empty array is kept, meaning
  "the linter ran and found nothing"; an absent key means "no linter output was supplied").
- With a fixed `generatedAt` every export is byte-for-byte deterministic for the same contract, cases and flaws.

## `permitmatrix.report/1` field reference

The schema id has not changed; the fields added in this version (`warnings`, the meaning of `build.flaws`,
the `anonymous` coverage column) are additive, so existing consumers keep working.

| Field | Type | Meaning |
|---|---|---|
| `schema` | `'permitmatrix.report/1'` | Report format id. |
| `generatedAt` | string (ISO-8601) | When the report was built (or the value supplied by the caller). |
| `tool.name` | `'permitmatrix'` | Producer. |
| `tool.mode` | `'browser-local deterministic simulation'` | Reminder that no live system was tested. |
| `contract.name`, `contract.version` | string | From the contract. |
| `contract.servers` | string[] | The contract's `mock://` or loopback targets (copied). |
| `build.id` | string | Build key selected in the UI. |
| `build.label` | string | Build label from the contract, or the id when the build is not declared. |
| `build.flaws[]` | `{ endpoint, kind }[]` | Flaws active for the run when `options.flaws` was given; otherwise the build definition. |
| `summary.cases` | number | Number of executed cases (`run.results.length`). |
| `summary.findings` | number | Number of findings. |
| `summary.byVerdict` | `Record<Verdict, number>` | Counts for `pass`, `bypass`, `over-deny`, `exposure`, `mass-assignment`, `error` (every key present, zero when unused). |
| `summary.bySeverity` | `Record<Severity, number>` | Counts for `high`, `medium`, `low`. |
| `findings[]` | `Finding[]` | `id` (`<endpoint>:<kind>`), `endpoint`, `kind`, `owaspApi`, `title`, `severity`, `evidenceCases` (case ids), `remediation`. |
| `coverage` | `Record<endpointId, Record<columnId, { total, pass, failed }>>` | One column per role id, plus `anonymous` when the run included the unauthenticated row. Column order follows the runner (contract roles, then `anonymous`). |
| `cases[]` | `CaseResult[]` | Every executed case: `caseId`, `endpoint`, `role`, `principal`, `targetKind`, `expected`, `verdict`, `request` (method, path, principal, optional body, **redacted** headers), `response` (status, body), `explanation`. |
| `warnings[]` | `ContractWarning[]` (optional) | `{ code, severity: 'info' \| 'warn', path, message }` from the contract linter. Present only when supplied. |
| `dataNote` | string | States that headers are redacted, response bodies are not, and all values are fictional. |
| `disclaimer` | string | Educational-prototype disclaimer; not a penetration test or compliance opinion. |

`Verdict`, `Severity`, `Finding`, `CaseResult` and `ContractWarning` are the types in `src/engine/types.ts`.

## Markdown memo (`reportToMarkdown`)

Sections appear in this order:

1. **Title line** — `# Authorization contract test — <name> <version>`.
2. **Run line** — `Generated <generatedAt> · build: <label> · <n> cases · <m> findings`.
3. **Disclaimer** and **data note** as two blockquotes.
4. `## Summary` — a `| Verdict | Cases |` table with one row per verdict, then
   `Findings by severity: high <n> · medium <n> · low <n>`.
5. `## Active seeded flaws` — one bullet per active flaw as `- <endpoint> · <kind>`, or `None`.
6. `## Findings` — `No authorization findings. …` when the run is clean; otherwise, per finding, a
   `### <SEVERITY> · <title> (<owaspApi>) — `<endpoint>`` heading, the line
   `Evidence cases: <n>. <remediation>`, and up to 8 evidence bullets rendered as
   `- <principal> · <targetKind>[ · <probeField>]: <explanation>` (looked up in `report.cases` by case id),
   followed by `+<k> more evidence case(s) are listed in the JSON report.` when the list was truncated.
7. `## Contract warnings` — only when `report.warnings` is non-empty; one bullet per warning as
   `- <severity> · <code> · <path> · <message>`.
8. `## Severity rubric` — a short note explaining how severities are assigned (see below) and that the
   scale is not CVSS.
9. `## Coverage (cases per endpoint × role: passed / total)` — a table with one column per coverage key.
   The `anonymous` column appears automatically when the run carries one; an endpoint with no entry for a
   column shows `–`.

### Severity rubric

Severities are an editorial triage scale, not CVSS scores:

| Finding kind | Severity |
|---|---|
| `object-bypass`, `function-bypass`, `auth-bypass` | high |
| `mass-assignment` | high when a probed field name looks privilege- or money-bearing (role, admin, status, owner, tenant, price, amount); otherwise medium |
| `sensitive-exposure` | high when a probed field name looks credential-like (password, secret, token, hash, ssn, key); otherwise medium |
| `over-deny` | low — a functional regression, never a security pass |

## SARIF 2.1.0 (`reportToSarif`)

`reportToSarif(report)` returns a `SarifLog` typed to exactly the subset emitted:

- `$schema`: `https://json.schemastore.org/sarif-2.1.0.json`, `version`: `2.1.0`, exactly one entry in `runs`.
- `runs[0].tool.driver`: `name: 'permitmatrix'`, `semanticVersion: '0.1.0'`,
  `informationUri: 'https://github.com/D-L-Narayana/permit-matrix'`, and `rules` — one rule per finding kind
  present in the report, in first-seen order.
- `runs[0].results`: one result per finding, in report order.
- `runs[0].invocations[0]`: `{ executionSuccessful: true, endTimeUtc: report.generatedAt }`.
- `runs[0].properties`: `{ disclaimer, dataNote, contract, build, generatedAt }` copied from the report, so
  the SARIF file carries the same framing and the same active-flaw list as the JSON report.

### Rule mapping (finding kind → rule)

| Finding kind | `rule.id` | `rule.name` | `properties.owaspApi` |
|---|---|---|---|
| `object-bypass` | `object-bypass` | `ObjectBypass` | `API1:2023` |
| `auth-bypass` | `auth-bypass` | `AuthBypass` | `API2:2023` |
| `mass-assignment` | `mass-assignment` | `MassAssignment` | `API3:2023` |
| `sensitive-exposure` | `sensitive-exposure` | `SensitiveExposure` | `API3:2023` |
| `function-bypass` | `function-bypass` | `FunctionBypass` | `API5:2023` |
| `over-deny` | `over-deny` | `OverDeny` | `n/a` |

Each rule carries `shortDescription.text` = finding title, `fullDescription.text` and `help.text` =
remediation, `helpUri` = `https://owasp.org/API-Security/editions/2023/en/0x11-t10/`, and
`properties.tags` = `['security', 'authorization', <owaspApi>]`. The OWASP id is taken from the finding
itself, so the table above reflects the runner's classification rather than a second copy of it.

### Result mapping (finding → result)

| Result field | Value |
|---|---|
| `ruleId` / `ruleIndex` | The finding's kind and the index of that rule in `tool.driver.rules`. |
| `level` | `high` → `error`, `medium` → `warning`, `low` → `note`. |
| `message.text` | `<title> on <endpoint> (<owaspApi>); <n> evidence case(s).` |
| `locations[0].logicalLocations[0]` | `{ fullyQualifiedName: <endpoint id>, kind: 'endpoint' }` — endpoints are logical, there is no source file. |
| `properties` | `{ endpoint, severity, evidenceCases }` — the case ids, so a reader can cross-reference the JSON report. |

SARIF carries **findings only**: no cases, requests, headers or response bodies are included.

## Redaction statement

- Every `Authorization` header in `report.cases[].request.headers` is rewritten to
  `Bearer [redacted:<principal>]` (header name matched case-insensitively; unrecognised bearer formats become
  `Bearer [redacted:unknown]`). Anonymous cases carry no `Authorization` header, and none is invented for them.
- Response bodies are **not** redacted in the JSON report: they are the evidence of what the mock returned,
  including fields the contract marks sensitive. The memo quotes only verdict explanations, which may name a
  field and its before/after values from the mock's state.
- The SARIF export contains neither headers nor bodies.
- All values originate from the contract loaded in the browser. Load synthetic data only; never a contract
  containing real records.
