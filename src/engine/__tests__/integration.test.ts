import { describe, expect, it } from 'vitest';
import Ajv2020 from 'ajv/dist/2020';
import ledgerly from '../../fixtures/ledgerly-contract.json';
import helpdesk from '../../fixtures/helpdesk-contract.json';
import ledgerlyOpenapi from '../../fixtures/ledgerly-openapi.json';
import schema from '../../../public/schema/permitmatrix.contract-1.schema.json';
import { validateContract } from '../contract';
import { generateCases } from '../cases';
import { runSuite } from '../runner';
import { lintContract } from '../lint';
import { openapiToContract } from '../openapi';
import { diffRuns } from '../diff';
import { buildReport } from '../report';
import { reportToSarif } from '../sarif';
import type { Contract, Flaw } from '../types';

// Cross-module integration: every shipped fixture through validation → lint → schema → generation → runner →
// diff → report → SARIF. Module-level behaviour is covered by the per-module test files.

const load = (raw: unknown): Contract => {
  const result = validateContract(raw);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
};
const seeded = (raw: { builds: Record<string, { flaws: unknown[] }> }): Flaw[] => raw.builds.vulnerable.flaws as Flaw[];
const findingIds = (ids: Iterable<string>) => [...ids].sort();

describe('integration — Ledgerly (frozen fixture) with the anonymous row enabled by default', () => {
  it('generates an authentication case for every endpoint and still zero findings on the remediated build', () => {
    const c = load(ledgerly);
    const cases = generateCases(c);
    const anonymous = cases.filter((x) => x.category === 'authentication');
    expect(anonymous).toHaveLength(c.endpoints.length);
    expect(cases).toHaveLength(89);
    const run = runSuite(c, cases, []);
    expect(run.findings).toEqual([]);
    expect(run.results.every((r) => r.verdict === 'pass')).toBe(true);
  });

  it('vulnerable build yields exactly the four seeded findings, unchanged by the new case kinds', () => {
    const c = load(ledgerly);
    const run = runSuite(c, generateCases(c), seeded(ledgerly));
    expect(findingIds(run.findings.map((f) => f.id))).toEqual([
      'delete-user:function-bypass',
      'get-invoice:object-bypass',
      'get-user:sensitive-exposure',
      'patch-user:mass-assignment',
    ]);
  });
});

describe('integration — Helpdesk fixture (authentication, create and listing probes)', () => {
  it('generates 114 cases and the remediated build has zero findings', () => {
    const c = load(helpdesk);
    const cases = generateCases(c);
    expect(cases).toHaveLength(114);
    const run = runSuite(c, cases, []);
    expect(run.findings).toEqual([]);
    expect(run.results.every((r) => r.verdict === 'pass')).toBe(true);
  });

  it('vulnerable build yields exactly the four seeded findings with their OWASP ids', () => {
    const c = load(helpdesk);
    const run = runSuite(c, generateCases(c), seeded(helpdesk));
    const byId = new Map(run.findings.map((f) => [f.id, f]));
    expect(findingIds(byId.keys())).toEqual([
      'create-ticket:mass-assignment',
      'export-tickets:auth-bypass',
      'list-tickets:object-bypass',
      'list-tickets:sensitive-exposure',
    ]);
    expect(byId.get('export-tickets:auth-bypass')?.owaspApi).toBe('API2:2023');
    expect(byId.get('export-tickets:auth-bypass')?.severity).toBe('high');
    expect(byId.get('create-ticket:mass-assignment')?.owaspApi).toBe('API3:2023');
    expect(byId.get('list-tickets:sensitive-exposure')?.owaspApi).toBe('API3:2023');
    // "internalNotes" is sensitive but not credential-like, so the rubric rates its exposure medium.
    expect(byId.get('list-tickets:sensitive-exposure')?.severity).toBe('medium');
    expect(byId.get('list-tickets:object-bypass')?.owaspApi).toBe('API1:2023');
  });

  it('anonymous requests carry no Authorization header and the bypass is explained', () => {
    const c = load(helpdesk);
    const run = runSuite(c, generateCases(c), seeded(helpdesk));
    const anonymous = run.results.filter((r) => r.principal === 'anonymous');
    expect(anonymous).toHaveLength(c.endpoints.length);
    for (const r of anonymous) expect(Object.keys(r.request.headers).map((k) => k.toLowerCase())).not.toContain('authorization');
    const bypass = anonymous.find((r) => r.endpoint === 'export-tickets');
    expect(bypass?.verdict).toBe('bypass');
    expect(bypass?.response.status).toBe(200);
    expect(anonymous.filter((r) => r.endpoint !== 'export-tickets').every((r) => r.verdict === 'pass' && r.response.status === 401)).toBe(true);
  });
});

describe('integration — contract health, schema and OpenAPI parity', () => {
  it('both shipped fixtures lint clean', () => {
    expect(lintContract(load(ledgerly))).toEqual([]);
    expect(lintContract(load(helpdesk))).toEqual([]);
  });

  it('both shipped fixtures validate against the published JSON Schema, and the schema is not vacuous', () => {
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const validate = ajv.compile(schema);
    for (const fixture of [ledgerly, helpdesk]) {
      const ok = validate(fixture);
      expect(validate.errors ?? []).toEqual([]);
      expect(ok).toBe(true);
    }
    expect(validate({ ...ledgerly, schema: 'permitmatrix.contract/2' })).toBe(false);
  });

  it('the OpenAPI rendition of Ledgerly generates exactly the same cases as the native contract', () => {
    const converted = openapiToContract(ledgerlyOpenapi);
    expect(converted.ok).toBe(true);
    if (!converted.ok) return;
    expect(generateCases(converted.contract)).toEqual(generateCases(load(ledgerly)));
  });
});

describe('integration — remediation loop and exports', () => {
  it('diffing Helpdesk vulnerable → fixed reports four fixed findings and no regressions', () => {
    const c = load(helpdesk);
    const cases = generateCases(c);
    const before = runSuite(c, cases, seeded(helpdesk));
    const after = runSuite(c, cases, []);
    const diff = diffRuns(before, after, {
      before: { label: 'release/2.3.0 (vulnerable)', build: 'vulnerable', flaws: seeded(helpdesk) },
      after: { label: 'release/2.3.1 (remediated)', build: 'fixed', flaws: [] },
    });
    expect(diff.findings.fixed).toHaveLength(4);
    expect(diff.findings.introduced).toEqual([]);
    expect(diff.summary.regressed).toBe(0);
    expect(diff.summary.improved).toBe(before.results.filter((r) => r.verdict !== 'pass').length);
    expect(diff.summary.improved).toBeGreaterThan(0);
    expect(diff.added).toEqual([]);
    expect(diff.removed).toEqual([]);
  });

  it('the SARIF export of Helpdesk vulnerable has one result per finding and an API2 rule, without bodies', () => {
    const c = load(helpdesk);
    const run = runSuite(c, generateCases(c), seeded(helpdesk));
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: '2026-10-04T00:00:00.000Z', flaws: seeded(helpdesk), warnings: lintContract(c) });
    const sarif = reportToSarif(report);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(4);
    const rule = sarif.runs[0].tool.driver.rules.find((r) => r.id === 'auth-bypass');
    expect(rule?.properties.owaspApi).toBe('API2:2023');
    const text = JSON.stringify(sarif);
    expect(text).not.toMatch(/mock-token-/);
    expect(text).not.toContain('Clock skew suspected'); // an internalNotes value: response bodies never reach SARIF
    expect(report.warnings).toEqual([]);
  });

  it('the report records the flaws that were actually active, not the build definition', () => {
    const c = load(ledgerly);
    const active: Flaw[] = [{ endpoint: 'get-invoice', kind: 'skip-ownership-check' }];
    const run = runSuite(c, generateCases(c), active);
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: '2026-10-04T00:00:00.000Z', flaws: active });
    expect(report.build.flaws).toEqual(active);
    expect(report.summary.findings).toBe(1);
    expect(Object.keys(report.coverage['get-invoice'])).toEqual(['admin', 'manager', 'member', 'anonymous']);
  });
});
