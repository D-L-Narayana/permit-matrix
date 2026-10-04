import { describe, expect, it } from 'vitest';
import fixture from '../../fixtures/ledgerly-contract.json';
import helpdesk from '../../fixtures/helpdesk-contract.json';
import { generateCases } from '../cases';
import { validateContract } from '../contract';
import { runSuite, severityFor, SEVERITY_RUBRIC } from '../runner';
import { ANONYMOUS_PRINCIPAL, ANONYMOUS_ROLE } from '../types';
import type { Contract, Endpoint, FindingKind, Flaw, FlawKind, Severity, TargetKind, TestCase } from '../types';

const ledgerly = (): Contract => {
  const result = validateContract(fixture);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
};
const vulnerableFlaws = (): Flaw[] => fixture.builds.vulnerable.flaws as Flaw[];
const flaw = (endpoint: string, kind: FlawKind): Flaw => ({ endpoint, kind });

const ALL_ROLES = ['admin', 'manager', 'member'];
// Ledgerly has no collection endpoint with sensitive fields and no POST endpoint; these two are added by
// mutation so the new oracles can be exercised against the frozen fixture.
const LIST_USERS: Endpoint = {
  id: 'list-users', method: 'GET', path: '/users', resource: 'users',
  access: { roles: ALL_ROLES, ownership: 'any' }, sensitiveFields: ['passwordHash'],
};
const CREATE_INVOICE: Endpoint = {
  id: 'create-invoice', method: 'POST', path: '/invoices', resource: 'invoices',
  access: { roles: ['admin', 'manager'], ownership: 'any' }, writableFields: ['memo'],
};
const withEndpoints = (contract: Contract, ...extra: Endpoint[]): Contract => ({ ...contract, endpoints: [...contract.endpoints, ...extra] });

// Hand-built cases mirror the shapes the generator produces, without depending on it.
const ANONYMOUS_RATIONALE = 'No credentials are presented; the endpoint must reject the request (401) before any policy is evaluated.';
function anonymousCase(endpoint: string, targetKind: TargetKind, targetRecord?: string): TestCase {
  return {
    id: `${endpoint}|anonymous|${targetKind}`, endpoint, principal: ANONYMOUS_PRINCIPAL, role: ANONYMOUS_ROLE.id,
    targetKind, ...(targetRecord ? { targetRecord } : {}), category: 'authentication', expected: 'deny', rationale: ANONYMOUS_RATIONALE,
  };
}
const listUsersProbe = (): TestCase => ({
  id: 'list-users|p-admin-1|collection|read:passwordHash', endpoint: 'list-users', principal: 'p-admin-1', role: 'admin',
  targetKind: 'collection', category: 'property', expected: 'allow', probeField: 'passwordHash',
  rationale: '"passwordHash" is marked sensitive; it must never appear in the response body.',
});
const createProbe = (field: string): TestCase => ({
  id: `create-invoice|p-admin-1|create|write:${field}`, endpoint: 'create-invoice', principal: 'p-admin-1', role: 'admin',
  targetKind: 'create', category: 'property', expected: 'allow', probeField: field,
  rationale: `"${field}" is not in writableFields [memo]; a create must not persist it.`,
});
const createAllowed = (): TestCase => ({
  id: 'create-invoice|p-admin-1|create', endpoint: 'create-invoice', principal: 'p-admin-1', role: 'admin',
  targetKind: 'create', category: 'object', expected: 'allow', rationale: 'Role is allowed and the endpoint is not object-scoped.',
});
const createDenied = (): TestCase => ({
  id: 'create-invoice|p-mem-1|create', endpoint: 'create-invoice', principal: 'p-mem-1', role: 'member',
  targetKind: 'create', category: 'function', expected: 'deny', rationale: 'Role "member" is not in the endpoint\'s allowed roles [admin, manager].',
});

describe('runner — anonymous (authentication) cases', () => {
  it('passes when the fixed build answers 401 and the request carries no Authorization header', () => {
    const run = runSuite(ledgerly(), [anonymousCase('list-invoices', 'collection'), anonymousCase('get-invoice', 'cross-tenant', 'inv-1001')], []);
    expect(run.results).toHaveLength(2);
    for (const r of run.results) {
      expect(r.verdict).toBe('pass');
      expect(r.response.status).toBe(401);
      expect(r.explanation).toMatch(/401/);
      expect(r.request.headers).toEqual({ 'Content-Type': 'application/json' });
      expect(r.request.principal).toBe(ANONYMOUS_PRINCIPAL);
      expect(r.role).toBe('anonymous');
    }
    expect(run.results[1].request.path).toBe('/invoices/inv-1001');
    expect(run.findings).toEqual([]);
  });

  it('reports a bypass and exactly one auth-bypass finding when skip-authentication lets the request through', () => {
    // list-invoices is owner-scoped: the verdict must come from the authentication rule, never from a scope
    // oracle that would need a principal the anonymous caller does not have.
    const run = runSuite(ledgerly(), [anonymousCase('list-invoices', 'collection')], [flaw('list-invoices', 'skip-authentication')]);
    const [r] = run.results;
    expect(r.verdict).toBe('bypass');
    expect(r.response.status).toBe(200);
    expect(r.explanation).toMatch(/without authentication/);
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]).toMatchObject({
      id: 'list-invoices:auth-bypass', endpoint: 'list-invoices', kind: 'auth-bypass', owaspApi: 'API2:2023', severity: 'high',
      evidenceCases: ['list-invoices|anonymous|collection'],
    });
    expect(run.findings[0].title).toMatch(/Broken Authentication/);
    expect(run.findings[0].remediation).toMatch(/middleware/);
  });

  it('treats a 403 as a pass while noting that 401 is the precise status', () => {
    const run = runSuite(ledgerly(), [anonymousCase('list-invoices', 'collection')], [flaw('list-invoices', 'skip-authentication'), flaw('list-invoices', 'deny-everything')]);
    expect(run.results[0].response.status).toBe(403);
    expect(run.results[0].verdict).toBe('pass');
    expect(run.results[0].explanation).toMatch(/403/);
    expect(run.results[0].explanation).toMatch(/401/);
  });

  it('marks any other status as an error rather than a pass', () => {
    const run = runSuite(ledgerly(), [anonymousCase('get-invoice', 'cross-tenant', 'inv-9999')], [flaw('get-invoice', 'skip-authentication')]);
    expect(run.results[0].response.status).toBe(404);
    expect(run.results[0].verdict).toBe('error');
    expect(run.findings).toEqual([]);
  });

  it('sends only the first writable field in an anonymous create body and flags a 201 as an auth bypass', () => {
    const contract = withEndpoints(ledgerly(), CREATE_INVOICE);
    const fixed = runSuite(contract, [anonymousCase('create-invoice', 'collection')], []);
    expect(fixed.results[0].request.body).toEqual({ memo: 'tampered' });
    expect(fixed.results[0].verdict).toBe('pass');
    const vulnerable = runSuite(contract, [anonymousCase('create-invoice', 'collection')], [flaw('create-invoice', 'skip-authentication')]);
    expect(vulnerable.results[0].response.status).toBe(201);
    expect(vulnerable.results[0].verdict).toBe('bypass');
    expect(vulnerable.findings.map((f) => f.kind)).toEqual(['auth-bypass']);
  });

  it('produces exactly these ledger strings for anonymous cases (pinned for the UI and the memo)', () => {
    const contract = withEndpoints(ledgerly(), CREATE_INVOICE);
    const list = anonymousCase('list-invoices', 'collection');
    const headers = { 'Content-Type': 'application/json' };

    const denied = runSuite(contract, [list], []).results[0];
    expect(denied.request).toEqual({ method: 'GET', path: '/invoices', principal: 'anonymous', headers });
    expect(denied.response).toEqual({ status: 401, body: { error: 'unauthenticated' } });
    expect(denied.explanation).toBe('Rejected with 401 before any policy ran, as required for a caller without credentials.');

    const forbidden = runSuite(contract, [list], [flaw('list-invoices', 'skip-authentication'), flaw('list-invoices', 'deny-everything')]).results[0];
    expect(forbidden.response).toEqual({ status: 403, body: { error: 'forbidden' } });
    expect(forbidden.explanation).toBe('Rejected with 403, so the request was refused; 401 is the precise status for a caller without credentials.');

    const listed = runSuite(contract, [list], [flaw('list-invoices', 'skip-authentication')]).results[0];
    expect(listed.response.status).toBe(200);
    expect(listed.response.body?.items?.map((i) => i.id)).toEqual(['inv-1001', 'inv-1002', 'inv-2001', 'inv-0001']);
    expect(listed.explanation).toBe('Expected 401 but the server answered 200 without authentication; the endpoint is reachable with no credentials.');

    const created = runSuite(contract, [anonymousCase('create-invoice', 'collection')], [flaw('create-invoice', 'skip-authentication')]).results[0];
    expect(created.request).toEqual({ method: 'POST', path: '/invoices', principal: 'anonymous', body: { memo: 'tampered' }, headers });
    expect(created.response).toEqual({ status: 201, body: { id: 'invoices-new-1', fields: { memo: 'tampered' } } });
    expect(created.explanation).toBe('Expected 401 but the server answered 201 without authentication; the endpoint is reachable with no credentials.');

    const missing = runSuite(contract, [anonymousCase('get-invoice', 'cross-tenant', 'inv-9999')], [flaw('get-invoice', 'skip-authentication')]).results[0];
    expect(missing.response).toEqual({ status: 404, body: { error: 'not found' } });
    expect(missing.explanation).toBe('Unexpected 404; the case could not be evaluated.');

    const patched = runSuite(contract, [anonymousCase('patch-invoice', 'cross-tenant', 'inv-1001')], []).results[0];
    expect(patched.request).toEqual({ method: 'PATCH', path: '/invoices/inv-1001', principal: 'anonymous', body: { memo: 'Design retainer-tampered' }, headers });
    expect(patched.response.status).toBe(401);
  });

  it('keeps the bearer token header for authenticated cases', () => {
    const authenticated: TestCase = {
      id: 'list-invoices|p-admin-1|collection', endpoint: 'list-invoices', principal: 'p-admin-1', role: 'admin',
      targetKind: 'collection', category: 'object', expected: 'allow', rationale: 'Role is allowed and the endpoint is not object-scoped.',
    };
    const run = runSuite(ledgerly(), [authenticated], []);
    expect(run.results[0].request.headers).toEqual({ Authorization: 'Bearer mock-token-p-admin-1', 'Content-Type': 'application/json' });
    expect(run.results[0].verdict).toBe('pass');
  });
});

describe('runner — collection exposure oracle', () => {
  it('passes when no listed item carries the probed sensitive field', () => {
    const run = runSuite(withEndpoints(ledgerly(), LIST_USERS), [listUsersProbe()], []);
    expect(run.results[0].response.status).toBe(200);
    expect(run.results[0].verdict).toBe('pass');
    expect(run.results[0].explanation).toMatch(/passwordHash/);
    expect(run.findings).toEqual([]);
  });

  it('reports exposure when any listed item carries the probed field', () => {
    const run = runSuite(withEndpoints(ledgerly(), LIST_USERS), [listUsersProbe()], [flaw('list-users', 'return-sensitive-fields')]);
    expect(run.results[0].verdict).toBe('exposure');
    expect(run.results[0].explanation).toMatch(/passwordHash/);
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]).toMatchObject({ id: 'list-users:sensitive-exposure', kind: 'sensitive-exposure', owaspApi: 'API3:2023', severity: 'high' });
  });
});

describe('runner — create oracle', () => {
  it('passes when the fixed build ignores a non-writable field on create', () => {
    const run = runSuite(withEndpoints(ledgerly(), CREATE_INVOICE), [createProbe('status')], []);
    const [r] = run.results;
    expect(r.request.path).toBe('/invoices');
    // First writable field is always 'tampered'; the probe is typed from the first record that has the field.
    expect(r.request.body).toEqual({ memo: 'tampered', status: 'open-tampered' });
    expect(r.response.status).toBe(201);
    expect(r.verdict).toBe('pass');
    expect(run.findings).toEqual([]);
  });

  it('reports mass assignment when accept-all-fields persists the probed field on the created record', () => {
    const run = runSuite(withEndpoints(ledgerly(), CREATE_INVOICE), [createProbe('status'), createProbe('note')], [flaw('create-invoice', 'accept-all-fields')]);
    expect(run.results.map((r) => r.verdict)).toEqual(['mass-assignment', 'mass-assignment']);
    expect(run.results[0].explanation).toMatch(/status/);
    expect(run.results[1].request.body).toEqual({ memo: 'tampered', note: 'tampered' });
    expect(run.findings).toHaveLength(1);
    expect(run.findings[0]).toMatchObject({ id: 'create-invoice:mass-assignment', kind: 'mass-assignment', owaspApi: 'API3:2023', severity: 'high' });
    expect(run.findings[0].evidenceCases).toEqual(['create-invoice|p-admin-1|create|write:status', 'create-invoice|p-admin-1|create|write:note']);
  });

  it('rates mass assignment of a non-privilege field as medium', () => {
    const run = runSuite(withEndpoints(ledgerly(), CREATE_INVOICE), [createProbe('note')], [flaw('create-invoice', 'accept-all-fields')]);
    expect(run.findings.map((f) => f.severity)).toEqual(['medium']);
  });

  it('passes a plain create with 201 and types numeric probes from the records', () => {
    const run = runSuite(withEndpoints(ledgerly(), CREATE_INVOICE), [createAllowed(), createProbe('amount')], []);
    expect(run.results[0].verdict).toBe('pass');
    expect(run.results[0].explanation).toMatch(/201/);
    expect(run.results[1].request.body).toEqual({ memo: 'tampered', amount: 121.5 });
    expect(run.results[1].verdict).toBe('pass');
  });

  it('treats a create by a role outside the allow-list as a function-level case', () => {
    const contract = withEndpoints(ledgerly(), CREATE_INVOICE);
    const fixed = runSuite(contract, [createDenied()], []);
    expect(fixed.results[0].response.status).toBe(403);
    expect(fixed.results[0].verdict).toBe('pass');
    const vulnerable = runSuite(contract, [createDenied()], [flaw('create-invoice', 'skip-role-check')]);
    expect(vulnerable.results[0].verdict).toBe('bypass');
    expect(vulnerable.findings.map((f) => `${f.kind}:${f.owaspApi}`)).toEqual(['function-bypass:API5:2023']);
  });
});

describe('runner — coverage', () => {
  it('adds an anonymous column to every endpoint and counts anonymous results in it', () => {
    const c = ledgerly();
    const run = runSuite(c, [anonymousCase('list-invoices', 'collection')], []);
    for (const e of c.endpoints) expect(Object.keys(run.coverage[e.id])).toEqual(['admin', 'manager', 'member', ANONYMOUS_ROLE.id]);
    expect(run.coverage['list-invoices'][ANONYMOUS_ROLE.id]).toEqual({ total: 1, pass: 1, failed: 0 });
    expect(run.coverage['get-invoice'][ANONYMOUS_ROLE.id]).toEqual({ total: 0, pass: 0, failed: 0 });
  });

  it('counts an anonymous bypass as failed', () => {
    const run = runSuite(ledgerly(), [anonymousCase('list-invoices', 'collection')], [flaw('list-invoices', 'skip-authentication')]);
    expect(run.coverage['list-invoices'][ANONYMOUS_ROLE.id]).toEqual({ total: 1, pass: 0, failed: 1 });
  });
});

describe('runner — severity rubric', () => {
  // A Record over FindingKind forces this table to stay complete when a kind is added.
  const EXPECTED: Record<FindingKind, Severity[]> = {
    'object-bypass': ['high'],
    'function-bypass': ['high'],
    'auth-bypass': ['high'],
    'mass-assignment': ['high', 'medium'],
    'sensitive-exposure': ['high', 'medium'],
    'over-deny': ['low'],
  };

  it('covers every finding kind with plain-sentence rules', () => {
    for (const kind of Object.keys(EXPECTED) as FindingKind[]) {
      const entries = SEVERITY_RUBRIC.filter((r) => r.kind === kind);
      expect(entries.map((r) => r.severity).sort()).toEqual([...EXPECTED[kind]].sort());
      for (const entry of entries) expect(entry.when).toMatch(/^[A-Z].*\.$/);
    }
    expect(SEVERITY_RUBRIC).toHaveLength(8);
    expect(SEVERITY_RUBRIC.find((r) => r.kind === 'mass-assignment' && r.severity === 'high')?.when).toMatch(/role/);
    expect(SEVERITY_RUBRIC.find((r) => r.kind === 'sensitive-exposure' && r.severity === 'high')?.when).toMatch(/password/);
  });

  it('agrees with severityFor', () => {
    expect(severityFor('object-bypass')).toBe('high');
    expect(severityFor('function-bypass')).toBe('high');
    expect(severityFor('auth-bypass')).toBe('high');
    expect(severityFor('over-deny')).toBe('low');
    expect(severityFor('mass-assignment', ['role'])).toBe('high');
    expect(severityFor('mass-assignment', ['memo'])).toBe('medium');
    expect(severityFor('sensitive-exposure', ['passwordHash'])).toBe('high');
    expect(severityFor('sensitive-exposure', ['email'])).toBe('medium');
  });
});

describe('runner — Ledgerly regression', () => {
  it('fixed build: zero findings and every verdict passes', () => {
    const c = ledgerly();
    const run = runSuite(c, generateCases(c), []);
    expect(run.findings).toEqual([]);
    expect(run.results.every((r) => r.verdict === 'pass')).toBe(true);
  });

  it('vulnerable build: exactly the four seeded findings with the same ids and OWASP classes as before', () => {
    const c = ledgerly();
    const run = runSuite(c, generateCases(c), vulnerableFlaws());
    expect(run.findings.map((f) => f.id).sort()).toEqual([
      'delete-user:function-bypass', 'get-invoice:object-bypass', 'get-user:sensitive-exposure', 'patch-user:mass-assignment',
    ]);
    const byId = new Map(run.findings.map((f) => [f.id, f]));
    expect(byId.get('get-invoice:object-bypass')).toMatchObject({ owaspApi: 'API1:2023', severity: 'high' });
    expect(byId.get('delete-user:function-bypass')).toMatchObject({ owaspApi: 'API5:2023', severity: 'high' });
    expect(byId.get('patch-user:mass-assignment')).toMatchObject({ owaspApi: 'API3:2023', severity: 'high' });
    expect(byId.get('get-user:sensitive-exposure')).toMatchObject({ owaspApi: 'API3:2023', severity: 'high' });
  });

  it('over-deny is never a pass and is reported as a low-severity functional finding', () => {
    const c = ledgerly();
    const run = runSuite(c, generateCases(c), [flaw('get-invoice', 'deny-everything')]);
    expect(run.results.some((r) => r.endpoint === 'get-invoice' && r.verdict === 'over-deny')).toBe(true);
    expect(run.findings.map((f) => `${f.id}:${f.severity}:${f.owaspApi}`)).toEqual(['get-invoice:over-deny:low:n/a']);
  });

  it('keeps fixed all-pass and vulnerable at exactly four findings once an anonymous row is added per endpoint', () => {
    // Mirrors the generator's anonymous row (collection for paths without {id}, else the first record) on top of the
    // base matrix (generated without the row) so the frozen Ledgerly expectations are known to survive that row.
    const c = ledgerly();
    const anonymousRows = c.endpoints.map((e) => {
      const first = c.resources.find((r) => r.id === e.resource)?.records[0];
      return e.path.includes('{id}') ? anonymousCase(e.id, 'cross-tenant', first?.id) : anonymousCase(e.id, 'collection');
    });
    expect(anonymousRows).toHaveLength(6);
    const fixed = runSuite(c, [...generateCases(c, { anonymous: false }), ...anonymousRows], []);
    expect(fixed.findings).toEqual([]);
    expect(fixed.results.every((r) => r.verdict === 'pass')).toBe(true);
    expect(fixed.results.filter((r) => r.principal === ANONYMOUS_PRINCIPAL).every((r) => r.response.status === 401)).toBe(true);
    const vulnerable = runSuite(c, [...generateCases(c, { anonymous: false }), ...anonymousRows], vulnerableFlaws());
    expect(vulnerable.findings.map((f) => f.id).sort()).toEqual([
      'delete-user:function-bypass', 'get-invoice:object-bypass', 'get-user:sensitive-exposure', 'patch-user:mass-assignment',
    ]);
    for (const e of c.endpoints) expect(vulnerable.coverage[e.id][ANONYMOUS_ROLE.id]).toEqual({ total: 1, pass: 1, failed: 0 });
  });

  it('marks a case whose target record is missing as an error', () => {
    const missing: TestCase = {
      id: 'get-invoice|p-admin-1|own', endpoint: 'get-invoice', principal: 'p-admin-1', role: 'admin',
      targetKind: 'own', targetRecord: 'inv-9999', category: 'object', expected: 'allow', rationale: 'Caller owns the target record.',
    };
    const run = runSuite(ledgerly(), [missing], []);
    expect(run.results[0].verdict).toBe('error');
    expect(run.findings).toEqual([]);
  });
});

describe('runner — Helpdesk fixture with hand-built cases', () => {
  // Mirrors the shapes the generator will produce for Helpdesk without depending on the generator, so the
  // four seeded flaws are proven end to end against the shipped fixture.
  const helpdeskContract = (): Contract => {
    const result = validateContract(helpdesk);
    if (!result.ok) throw new Error(result.errors.join('\n'));
    return result.contract;
  };
  const helpdeskFlaws = (): Flaw[] => helpdesk.builds.vulnerable.flaws as Flaw[];
  const customer = (id: string, endpoint: string, targetKind: TargetKind, category: TestCase['category'], probeField?: string): TestCase => ({
    id, endpoint, principal: 'p-cust-1', role: 'customer', targetKind, category, expected: 'allow',
    ...(probeField ? { probeField } : {}), rationale: 'Role is allowed and the endpoint is not object-scoped.',
  });
  const cases = (): TestCase[] => [
    anonymousCase('list-tickets', 'collection'),
    anonymousCase('create-ticket', 'collection'),
    anonymousCase('get-ticket', 'cross-tenant', 'tkt-1001'),
    anonymousCase('patch-ticket', 'cross-tenant', 'tkt-1001'),
    anonymousCase('delete-ticket', 'cross-tenant', 'tkt-1001'),
    anonymousCase('export-tickets', 'collection'),
    customer('list-tickets|p-cust-1|collection', 'list-tickets', 'collection', 'object'),
    customer('list-tickets|p-cust-1|collection|read:internalNotes', 'list-tickets', 'collection', 'property', 'internalNotes'),
    customer('create-ticket|p-cust-1|create', 'create-ticket', 'create', 'object'),
    customer('create-ticket|p-cust-1|create|write:status', 'create-ticket', 'create', 'property', 'status'),
    customer('create-ticket|p-cust-1|create|write:internalNotes', 'create-ticket', 'create', 'property', 'internalNotes'),
  ];

  it('fixed build: every case passes and there are no findings', () => {
    const run = runSuite(helpdeskContract(), cases(), []);
    expect(run.results).toHaveLength(11);
    expect(run.results.map((r) => r.verdict)).toEqual(Array(11).fill('pass'));
    expect(run.findings).toEqual([]);
    for (const r of run.results.filter((x) => x.principal === ANONYMOUS_PRINCIPAL)) {
      expect(r.response.status).toBe(401);
      expect(r.request.headers).not.toHaveProperty('Authorization');
    }
  });

  it('vulnerable build: exactly the four seeded findings with their OWASP API classes', () => {
    const run = runSuite(helpdeskContract(), cases(), helpdeskFlaws());
    expect(run.findings.map((f) => `${f.id}:${f.owaspApi}:${f.severity}`).sort()).toEqual([
      'create-ticket:mass-assignment:API3:2023:high',
      'export-tickets:auth-bypass:API2:2023:high',
      'list-tickets:object-bypass:API1:2023:high',
      'list-tickets:sensitive-exposure:API3:2023:medium',
    ]);
    const verdicts = new Map(run.results.map((r) => [r.caseId, r.verdict]));
    expect(verdicts.get('export-tickets|anonymous|collection')).toBe('bypass');
    expect(verdicts.get('list-tickets|anonymous|collection')).toBe('pass');
    expect(verdicts.get('get-ticket|anonymous|cross-tenant')).toBe('pass');
    expect(verdicts.get('list-tickets|p-cust-1|collection')).toBe('bypass');
    expect(verdicts.get('list-tickets|p-cust-1|collection|read:internalNotes')).toBe('exposure');
    expect(verdicts.get('create-ticket|p-cust-1|create')).toBe('pass');
    expect(verdicts.get('create-ticket|p-cust-1|create|write:status')).toBe('mass-assignment');
    expect(verdicts.get('create-ticket|p-cust-1|create|write:internalNotes')).toBe('mass-assignment');
    expect(run.coverage['export-tickets'][ANONYMOUS_ROLE.id]).toEqual({ total: 1, pass: 0, failed: 1 });
    expect(run.coverage['list-tickets'][ANONYMOUS_ROLE.id]).toEqual({ total: 1, pass: 1, failed: 0 });
  });
});
