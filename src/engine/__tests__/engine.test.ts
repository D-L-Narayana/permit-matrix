import { describe, expect, it } from 'vitest';
import fixture from '../../fixtures/ledgerly-contract.json';
import { parseContract, validateContract, LIMITS } from '../contract';
import { generateCases } from '../cases';
import { createMockServer } from '../mockServer';
import { runSuite } from '../runner';
import { buildReport } from '../report';
import type { Contract, Flaw } from '../types';

const contract = (): Contract => {
  const result = validateContract(fixture);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
};
const vulnerableFlaws = (): Flaw[] => fixture.builds.vulnerable.flaws as Flaw[];

describe('contract validation', () => {
  it('accepts the synthetic Ledgerly contract', () => {
    const result = validateContract(fixture);
    expect(result.ok).toBe(true);
  });

  it('refuses any server that is not a mock:// or localhost target', () => {
    const tampered = { ...fixture, servers: ['https://api.victim.example'] };
    const result = validateContract(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join(' ')).toMatch(/External target refused/);
  });

  it('rejects contracts above the endpoint limit', () => {
    const endpoints = Array.from({ length: LIMITS.maxEndpoints + 1 }, (_, i) => ({
      ...fixture.endpoints[0], id: `ep-${i}`,
    }));
    const result = validateContract({ ...fixture, endpoints });
    expect(result.ok).toBe(false);
  });

  it('rejects endpoints that reference unknown roles or resources', () => {
    const bad = {
      ...fixture,
      endpoints: [{ ...fixture.endpoints[0], access: { roles: ['superuser'], ownership: 'any' } }],
    };
    const result = validateContract(bad);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join(' ')).toMatch(/superuser/);
  });

  it('rejects malformed JSON and oversized text', () => {
    expect(parseContract('{ not json').ok).toBe(false);
    const huge = JSON.stringify(fixture) + ' '.repeat(LIMITS.maxBytes);
    expect(parseContract(huge).ok).toBe(false);
  });
});

describe('case generation', () => {
  it('derives own / peer / cross-tenant expectations for an owner-scoped endpoint', () => {
    const cases = generateCases(contract()).filter(
      (c) => c.endpoint === 'get-invoice' && c.principal === 'p-mem-1',
    );
    const byTarget = Object.fromEntries(cases.map((c) => [c.targetKind, c.expected]));
    expect(byTarget.own).toBe('allow');
    expect(byTarget.peer).toBe('deny');
    expect(byTarget['cross-tenant']).toBe('deny');
  });

  it('marks role-excluded calls as function-level denials', () => {
    const cases = generateCases(contract()).filter(
      (c) => c.endpoint === 'delete-user' && c.principal === 'p-mem-1',
    );
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      expect(c.expected).toBe('deny');
      expect(c.category).toBe('function');
    }
  });

  it('adds property-level cases for writable and sensitive field rules', () => {
    const cases = generateCases(contract());
    expect(cases.some((c) => c.endpoint === 'patch-user' && c.category === 'property' && c.probeField === 'role')).toBe(true);
    expect(cases.some((c) => c.endpoint === 'get-user' && c.category === 'property' && c.probeField === 'passwordHash')).toBe(true);
  });

  it('is deterministic', () => {
    expect(generateCases(contract())).toEqual(generateCases(contract()));
  });
});

describe('mock server', () => {
  it('fixed build denies a member reading a peer invoice', () => {
    const server = createMockServer(contract(), []);
    const res = server.handle({ method: 'GET', path: '/invoices/inv-1002', principal: 'p-mem-1' });
    expect(res.status).toBe(403);
  });

  it('vulnerable build leaks the peer invoice (BOLA)', () => {
    const server = createMockServer(contract(), vulnerableFlaws());
    const res = server.handle({ method: 'GET', path: '/invoices/inv-1002', principal: 'p-mem-1' });
    expect(res.status).toBe(200);
  });

  it('fixed build ignores non-writable fields and strips sensitive fields', () => {
    const server = createMockServer(contract(), []);
    const patched = server.handle({ method: 'PATCH', path: '/users/p-mem-1', principal: 'p-mem-1', body: { role: 'admin', displayName: 'R.' } });
    expect(patched.status).toBe(200);
    expect(patched.body?.fields?.role).toBe('member');
    expect(patched.body?.fields?.displayName).toBe('R.');
    const read = server.handle({ method: 'GET', path: '/users/p-mem-1', principal: 'p-mem-1' });
    expect(read.body?.fields).not.toHaveProperty('passwordHash');
  });

  it('returns 401 for unknown principals and 404 for unknown routes', () => {
    const server = createMockServer(contract(), []);
    expect(server.handle({ method: 'GET', path: '/invoices/inv-1001', principal: 'nobody' }).status).toBe(401);
    expect(server.handle({ method: 'GET', path: '/nope', principal: 'p-admin-1' }).status).toBe(404);
  });
});

describe('suite runner and findings', () => {
  it('reports no findings against the remediated build', () => {
    const c = contract();
    const run = runSuite(c, generateCases(c), []);
    expect(run.findings).toEqual([]);
    expect(run.results.every((r) => r.verdict === 'pass')).toBe(true);
  });

  it('classifies the four seeded flaws with OWASP API Security Top 10 (2023) ids', () => {
    const c = contract();
    const run = runSuite(c, generateCases(c), vulnerableFlaws());
    const kinds = new Map(run.findings.map((f) => [`${f.endpoint}:${f.kind}`, f.owaspApi]));
    expect(kinds.get('get-invoice:object-bypass')).toBe('API1:2023');
    expect(kinds.get('delete-user:function-bypass')).toBe('API5:2023');
    expect(kinds.get('patch-user:mass-assignment')).toBe('API3:2023');
    expect(kinds.get('get-user:sensitive-exposure')).toBe('API3:2023');
    expect(run.findings).toHaveLength(4);
  });

  it('flags over-denial as a functional regression rather than a security pass', () => {
    const c = contract();
    const run = runSuite(c, generateCases(c), [{ endpoint: 'get-invoice', kind: 'deny-everything' }]);
    expect(run.results.some((r) => r.endpoint === 'get-invoice' && r.verdict === 'over-deny')).toBe(true);
  });

  it('builds a coverage matrix of endpoints by roles', () => {
    const c = contract();
    const run = runSuite(c, generateCases(c), []);
    expect(run.coverage['get-invoice'].member.total).toBeGreaterThanOrEqual(3);
    expect(Object.keys(run.coverage)).toHaveLength(c.endpoints.length);
  });
});

describe('report export', () => {
  it('produces a stable schema and never includes raw bearer tokens', () => {
    const c = contract();
    const run = runSuite(c, generateCases(c), vulnerableFlaws());
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: '2026-10-01T00:00:00.000Z' });
    expect(report.schema).toBe('permitmatrix.report/1');
    expect(report.summary.findings).toBe(4);
    const text = JSON.stringify(report);
    expect(text).not.toMatch(/mock-token-/);
    expect(text).toMatch(/Bearer \[redacted:/);
  });
});

describe('contract validation — review regressions', () => {
  it('measures the byte limit in UTF-8 bytes, not UTF-16 code units', () => {
    // 20 000 four-byte characters = 80 000 bytes but only 40 000 code units.
    const padded = JSON.stringify({ ...fixture, name: '\u{1F512}'.repeat(20000) });
    expect(padded.length).toBeLessThan(LIMITS.maxBytes);
    expect(new TextEncoder().encode(padded).length).toBeGreaterThan(LIMITS.maxBytes);
    const result = parseContract(padded);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join(' ')).toMatch(/bytes/);
  });

  it('rejects duplicate record ids within a resource', () => {
    const invoices = fixture.resources[0];
    const dup = { ...fixture, resources: [{ ...invoices, records: [invoices.records[0], { ...invoices.records[1], id: invoices.records[0].id }] }, fixture.resources[1]] };
    const result = validateContract(dup);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join(' ')).toMatch(/duplicate record id inv-1001/);
  });

  it('rejects non-finite numeric field values such as 1e999', () => {
    const text = JSON.stringify(fixture).replace('"amount": 120.5', '"amount": 1e999').replace('"amount":120.5', '"amount":1e999');
    expect(text).toMatch(/1e999/);
    const result = parseContract(text);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join(' ')).toMatch(/finite/);
  });

  it('caps servers, builds and flaws per build', () => {
    const manyServers = validateContract({ ...fixture, servers: Array.from({ length: LIMITS.maxServers + 1 }, (_, i) => `mock://s${i}.example`) });
    expect(manyServers.ok).toBe(false);
    const builds = Object.fromEntries(Array.from({ length: LIMITS.maxBuilds + 1 }, (_, i) => [`b${i}`, { label: 'x', flaws: [] }]));
    expect(validateContract({ ...fixture, builds }).ok).toBe(false);
    const flaws = Array.from({ length: LIMITS.maxFlawsPerBuild + 1 }, () => ({ endpoint: 'get-invoice', kind: 'skip-role-check' }));
    expect(validateContract({ ...fixture, builds: { vulnerable: { label: 'x', flaws } } }).ok).toBe(false);
  });

  it('does not throw on absurdly large lists passed as objects', () => {
    const endpoints = Array.from({ length: 50_000 }, (_, i) => ({ ...fixture.endpoints[0], id: `ep-${i}` }));
    const deep = Array.from({ length: 200_000 }, () => 1);
    let result: ReturnType<typeof validateContract> | undefined;
    expect(() => { result = validateContract({ ...fixture, endpoints, extra: deep }); }).not.toThrow();
    expect(result?.ok).toBe(false);
  });
});

describe('sixth-Fable regressions — routing ambiguity and export labelling', () => {
  it('rejects two endpoints with the same method and path template', () => {
    const dup = { ...fixture, endpoints: [...fixture.endpoints, { id: 'get-invoice-admin', method: 'GET', path: '/invoices/{id}', resource: 'invoices', access: { roles: ['admin'], ownership: 'any' } }] };
    const r = validateContract(dup);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join(' ')).toMatch(/duplicate route GET \/invoices\/\{id\}/);
  });
  it('rejects parameter names other than {id}, more than one parameter, and templates that differ only by parameter name', () => {
    const renamed = { ...fixture, endpoints: [...fixture.endpoints, { id: 'get-invoice-2', method: 'GET', path: '/invoices/{invoiceId}', resource: 'invoices', access: { roles: ['admin'], ownership: 'any' } }] };
    const r1 = validateContract(renamed);
    expect(r1.ok).toBe(false);
    if (!r1.ok) expect(r1.errors.join(' ')).toMatch(/only \{id\}/);
    const two = { ...fixture, endpoints: [{ ...fixture.endpoints[1], path: '/tenants/{id}/invoices/{id}' }] };
    expect(validateContract(two).ok).toBe(false);
  });
  it('routes a literal path to its own endpoint even when registered after a {id} sibling', () => {
    const col = { ...fixture, endpoints: [...fixture.endpoints, { id: 'export-invoices', method: 'GET', path: '/invoices/export', resource: 'invoices', access: { roles: ['admin'], ownership: 'any' } }] };
    const r = validateContract(col);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const run = runSuite(r.contract, generateCases(r.contract), []);
    const exportResults = run.results.filter((x) => x.endpoint === 'export-invoices');
    expect(exportResults.length).toBeGreaterThan(0);
    expect(exportResults.every((x) => x.verdict === 'pass')).toBe(true);
    expect(run.findings).toEqual([]);
  });
  it('keeps the demo contract self-consistent: list and item scope agree, and the remediated build never lists a record the item route would deny', () => {
    const c = contract();
    const list = c.endpoints.find((e) => e.id === 'list-invoices')!;
    const item = c.endpoints.find((e) => e.id === 'get-invoice')!;
    expect(list.access.ownership).toBe(item.access.ownership);
    const server = createMockServer(c, []);
    const listed = server.handle({ method: 'GET', path: '/invoices', principal: 'p-mem-1' }).body?.items ?? [];
    for (const row of listed) expect(server.handle({ method: 'GET', path: `/invoices/${row.id}`, principal: 'p-mem-1' }).status).toBe(200);
    expect(generateCases(c)).toHaveLength(83);
  });
  it('states in the export that response bodies carry fictional field values even though headers are redacted', () => {
    const c = contract();
    const report = buildReport(c, runSuite(c, generateCases(c), vulnerableFlaws()), { build: 'vulnerable', generatedAt: '2026-10-01T00:00:00.000Z' });
    expect(report.dataNote).toMatch(/response bodies are not redacted/i);
    expect(report.dataNote).toMatch(/fictional/i);
  });
});
