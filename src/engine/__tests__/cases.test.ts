import { describe, expect, it } from 'vitest';
import ledgerlyFixture from '../../fixtures/ledgerly-contract.json';
import helpdeskFixture from '../../fixtures/helpdesk-contract.json';
import { validateContract } from '../contract';
import { ANONYMOUS_RATIONALE, generateCases, hasPathParam, resourceFieldNames } from '../cases';
import type { GenerateOptions } from '../cases';
import { runSuite } from '../runner';
import { ANONYMOUS_PRINCIPAL, ANONYMOUS_ROLE } from '../types';
import type { Contract, Endpoint, Resource, TestCase } from '../types';

// Every call passes `anonymous` explicitly: the option's default is owned by integration and pinned there, not here.
const WITHOUT_ANONYMOUS: GenerateOptions = { anonymous: false };
const WITH_ANONYMOUS: GenerateOptions = { anonymous: true };

const load = (fixture: unknown): Contract => {
  const result = validateContract(fixture);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
};
const ledgerly = (): Contract => load(ledgerlyFixture);
const helpdesk = (): Contract => load(helpdeskFixture);
/** Helpdesk with one endpoint's fields overridden, re-validated so the generator sees a normalised contract. */
const helpdeskWith = (endpointId: string, patch: Record<string, unknown>): Contract =>
  load({ ...helpdeskFixture, endpoints: helpdeskFixture.endpoints.map((e) => (e.id === endpointId ? { ...e, ...patch } : e)) });

const ids = (cases: TestCase[]): string[] => cases.map((c) => c.id);
const isAnonymous = (c: TestCase): boolean => c.principal === ANONYMOUS_PRINCIPAL;
const caseOf = (cases: TestCase[], id: string): TestCase => {
  const found = cases.find((c) => c.id === id);
  expect(found, `case ${id} should be generated`).toBeDefined();
  return found as TestCase;
};
const endpointOf = (c: Contract, id: string): Endpoint => {
  const found = c.endpoints.find((e) => e.id === id);
  if (!found) throw new Error(`no endpoint ${id}`);
  return found;
};
const HELPDESK_FIELDS = ['subject', 'body', 'status', 'priority', 'internalNotes'];

/** Every Ledgerly case id exactly as generated before this upgrade, in generation order. Disabling the anonymous row must reproduce it. */
const LEDGERLY_IDS: readonly string[] = [
  'list-invoices|p-admin-1|collection',
  'list-invoices|p-mgr-1|collection',
  'list-invoices|p-mem-1|collection',
  'list-invoices|p-mem-2|collection',
  'get-invoice|p-admin-1|own',
  'get-invoice|p-admin-1|peer',
  'get-invoice|p-admin-1|cross-tenant',
  'get-invoice|p-mgr-1|own',
  'get-invoice|p-mgr-1|peer',
  'get-invoice|p-mgr-1|cross-tenant',
  'get-invoice|p-mem-1|own',
  'get-invoice|p-mem-1|peer',
  'get-invoice|p-mem-1|cross-tenant',
  'get-invoice|p-mem-2|own',
  'get-invoice|p-mem-2|cross-tenant',
  'patch-invoice|p-admin-1|own',
  'patch-invoice|p-admin-1|own|write:amount',
  'patch-invoice|p-admin-1|own|write:status',
  'patch-invoice|p-admin-1|peer',
  'patch-invoice|p-admin-1|peer|write:amount',
  'patch-invoice|p-admin-1|peer|write:status',
  'patch-invoice|p-admin-1|cross-tenant',
  'patch-invoice|p-mgr-1|own',
  'patch-invoice|p-mgr-1|own|write:amount',
  'patch-invoice|p-mgr-1|own|write:status',
  'patch-invoice|p-mgr-1|peer',
  'patch-invoice|p-mgr-1|peer|write:amount',
  'patch-invoice|p-mgr-1|peer|write:status',
  'patch-invoice|p-mgr-1|cross-tenant',
  'patch-invoice|p-mem-1|own',
  'patch-invoice|p-mem-1|peer',
  'patch-invoice|p-mem-1|cross-tenant',
  'patch-invoice|p-mem-2|own',
  'patch-invoice|p-mem-2|cross-tenant',
  'get-user|p-admin-1|own',
  'get-user|p-admin-1|own|read:passwordHash',
  'get-user|p-admin-1|peer',
  'get-user|p-admin-1|cross-tenant',
  'get-user|p-mgr-1|own',
  'get-user|p-mgr-1|own|read:passwordHash',
  'get-user|p-mgr-1|peer',
  'get-user|p-mgr-1|cross-tenant',
  'get-user|p-mem-1|own',
  'get-user|p-mem-1|own|read:passwordHash',
  'get-user|p-mem-1|peer',
  'get-user|p-mem-1|cross-tenant',
  'get-user|p-mem-2|own',
  'get-user|p-mem-2|own|read:passwordHash',
  'get-user|p-mem-2|cross-tenant',
  'patch-user|p-admin-1|own',
  'patch-user|p-admin-1|own|write:role',
  'patch-user|p-admin-1|own|write:email',
  'patch-user|p-admin-1|own|write:passwordHash',
  'patch-user|p-admin-1|peer',
  'patch-user|p-admin-1|cross-tenant',
  'patch-user|p-mgr-1|own',
  'patch-user|p-mgr-1|own|write:role',
  'patch-user|p-mgr-1|own|write:email',
  'patch-user|p-mgr-1|own|write:passwordHash',
  'patch-user|p-mgr-1|peer',
  'patch-user|p-mgr-1|cross-tenant',
  'patch-user|p-mem-1|own',
  'patch-user|p-mem-1|own|write:role',
  'patch-user|p-mem-1|own|write:email',
  'patch-user|p-mem-1|own|write:passwordHash',
  'patch-user|p-mem-1|peer',
  'patch-user|p-mem-1|cross-tenant',
  'patch-user|p-mem-2|own',
  'patch-user|p-mem-2|own|write:role',
  'patch-user|p-mem-2|own|write:email',
  'patch-user|p-mem-2|own|write:passwordHash',
  'patch-user|p-mem-2|cross-tenant',
  'delete-user|p-admin-1|own',
  'delete-user|p-admin-1|peer',
  'delete-user|p-admin-1|cross-tenant',
  'delete-user|p-mgr-1|own',
  'delete-user|p-mgr-1|peer',
  'delete-user|p-mgr-1|cross-tenant',
  'delete-user|p-mem-1|own',
  'delete-user|p-mem-1|peer',
  'delete-user|p-mem-1|cross-tenant',
  'delete-user|p-mem-2|own',
  'delete-user|p-mem-2|cross-tenant',
];

describe('generateCases — frozen Ledgerly behaviour', () => {
  it('reproduces the 83 pre-upgrade ids in the same order with the anonymous row disabled', () => {
    expect(LEDGERLY_IDS).toHaveLength(83);
    expect(ids(generateCases(ledgerly(), WITHOUT_ANONYMOUS))).toEqual([...LEDGERLY_IDS]);
  });

  it('adds neither anonymous nor create cases to Ledgerly when the anonymous row is disabled', () => {
    const cases = generateCases(ledgerly(), WITHOUT_ANONYMOUS);
    expect(cases.some(isAnonymous)).toBe(false);
    expect(cases.some((c) => c.category === 'authentication' || c.targetKind === 'create')).toBe(false);
    expect(cases).toHaveLength(83);
    // Create cases depend on POST endpoints, not on the anonymous option; Ledgerly has none.
    expect(generateCases(ledgerly(), WITH_ANONYMOUS).some((c) => c.targetKind === 'create')).toBe(false);
  });

  it('keeps the pre-upgrade shape and wording of existing cases', () => {
    const cases = generateCases(ledgerly(), WITHOUT_ANONYMOUS);
    expect(caseOf(cases, 'list-invoices|p-mem-2|collection')).toStrictEqual({
      id: 'list-invoices|p-mem-2|collection', endpoint: 'list-invoices', principal: 'p-mem-2', role: 'member',
      targetKind: 'collection', category: 'object', expected: 'allow', rationale: 'Role is allowed and the endpoint is not object-scoped.',
    });
    expect(caseOf(cases, 'get-invoice|p-mem-1|cross-tenant')).toStrictEqual({
      id: 'get-invoice|p-mem-1|cross-tenant', endpoint: 'get-invoice', principal: 'p-mem-1', role: 'member',
      targetKind: 'cross-tenant', targetRecord: 'inv-2001', category: 'object', expected: 'deny',
      rationale: 'Record is owned by p-mem-2, not the caller; ownership rule is "own".',
    });
    expect(caseOf(cases, 'patch-invoice|p-mem-1|own')).toStrictEqual({
      id: 'patch-invoice|p-mem-1|own', endpoint: 'patch-invoice', principal: 'p-mem-1', role: 'member',
      targetKind: 'own', targetRecord: 'inv-1001', category: 'function', expected: 'deny',
      rationale: 'Role "member" is not in the endpoint\'s allowed roles [admin, manager].',
    });
    expect(caseOf(cases, 'patch-invoice|p-admin-1|cross-tenant')).toStrictEqual({
      id: 'patch-invoice|p-admin-1|cross-tenant', endpoint: 'patch-invoice', principal: 'p-admin-1', role: 'admin',
      targetKind: 'cross-tenant', targetRecord: 'inv-2001', category: 'object', expected: 'deny',
      rationale: 'Record belongs to tenant globex.example; ownership rule is "same-tenant".',
    });
    expect(caseOf(cases, 'patch-user|p-mem-2|own|write:role')).toStrictEqual({
      id: 'patch-user|p-mem-2|own|write:role', endpoint: 'patch-user', principal: 'p-mem-2', role: 'member',
      targetKind: 'own', targetRecord: 'p-mem-2', category: 'property', expected: 'allow', probeField: 'role',
      rationale: '"role" is not in writableFields [displayName]; a write must leave it unchanged.',
    });
    expect(caseOf(cases, 'get-user|p-admin-1|own|read:passwordHash')).toStrictEqual({
      id: 'get-user|p-admin-1|own|read:passwordHash', endpoint: 'get-user', principal: 'p-admin-1', role: 'admin',
      targetKind: 'own', targetRecord: 'p-admin-1', category: 'property', expected: 'allow', probeField: 'passwordHash',
      rationale: '"passwordHash" is marked sensitive; it must never appear in the response body.',
    });
    expect(caseOf(cases, 'get-invoice|p-mem-1|own')).toMatchObject({ expected: 'allow', category: 'object', rationale: 'Caller owns the target record.' });
    expect(caseOf(cases, 'patch-invoice|p-mgr-1|peer')).toMatchObject({ expected: 'allow', category: 'object', rationale: 'Target is inside the caller’s tenant.' });
  });
});

describe('anonymous row', () => {
  const recordCount = (c: Contract, endpoint: Endpoint): number => c.resources.find((r) => r.id === endpoint.resource)?.records.length ?? 0;

  it('emits one authentication case per endpoint that has a target when enabled (Ledgerly)', () => {
    const c = ledgerly();
    const anon = generateCases(c, WITH_ANONYMOUS).filter(isAnonymous);
    const endpointsWithTarget = c.endpoints.filter((e) => !hasPathParam(e) || recordCount(c, e) > 0);
    expect(anon).toHaveLength(endpointsWithTarget.length);
    expect(anon.map((a) => a.endpoint)).toEqual(endpointsWithTarget.map((e) => e.id));
    for (const a of anon) {
      expect(a.principal).toBe(ANONYMOUS_PRINCIPAL);
      expect(a.role).toBe(ANONYMOUS_ROLE.id);
      expect(a.category).toBe('authentication');
      expect(a.expected).toBe('deny');
      expect(a.rationale).toBe(ANONYMOUS_RATIONALE);
      expect(a.probeField).toBeUndefined();
    }
  });

  it('targets the collection for endpoints without {id}, otherwise the first record as cross-tenant', () => {
    const cases = generateCases(ledgerly(), WITH_ANONYMOUS);
    expect(caseOf(cases, 'list-invoices|anonymous|collection')).toStrictEqual({
      id: 'list-invoices|anonymous|collection', endpoint: 'list-invoices', principal: ANONYMOUS_PRINCIPAL, role: ANONYMOUS_ROLE.id,
      targetKind: 'collection', category: 'authentication', expected: 'deny', rationale: ANONYMOUS_RATIONALE,
    });
    expect(caseOf(cases, 'get-invoice|anonymous|cross-tenant')).toStrictEqual({
      id: 'get-invoice|anonymous|cross-tenant', endpoint: 'get-invoice', principal: ANONYMOUS_PRINCIPAL, role: ANONYMOUS_ROLE.id,
      targetKind: 'cross-tenant', targetRecord: 'inv-1001', category: 'authentication', expected: 'deny', rationale: ANONYMOUS_RATIONALE,
    });
    expect(caseOf(cases, 'patch-invoice|anonymous|cross-tenant').targetRecord).toBe('inv-1001');
    expect(caseOf(cases, 'get-user|anonymous|cross-tenant').targetRecord).toBe('p-admin-1');
    expect(caseOf(cases, 'patch-user|anonymous|cross-tenant').targetRecord).toBe('p-admin-1');
    expect(caseOf(cases, 'delete-user|anonymous|cross-tenant').targetRecord).toBe('p-admin-1');
    expect(ANONYMOUS_RATIONALE).toBe('No credentials are presented; the endpoint must reject the request (401) before any policy is evaluated.');
  });

  it('appends the anonymous case after that endpoint\'s principal cases and keeps the 83 original ids in order', () => {
    const c = ledgerly();
    const cases = generateCases(c, WITH_ANONYMOUS);
    expect(ids(cases.filter((x) => !isAnonymous(x)))).toEqual([...LEDGERLY_IDS]);
    for (const endpoint of c.endpoints) {
      const indices = cases.map((x, i) => (x.endpoint === endpoint.id ? i : -1)).filter((i) => i >= 0);
      const first = Math.min(...indices);
      const last = Math.max(...indices);
      expect(last - first + 1, `${endpoint.id} cases are contiguous`).toBe(indices.length);
      expect(cases[last]?.principal, `${endpoint.id} ends with its anonymous case`).toBe(ANONYMOUS_PRINCIPAL);
      expect(indices.slice(0, -1).some((i) => cases[i]?.principal === ANONYMOUS_PRINCIPAL)).toBe(false);
    }
  });

  it('skips the {id} anonymous case when the resource has no records, but keeps the collection one', () => {
    const emptied = load({ ...ledgerlyFixture, resources: [{ ...ledgerlyFixture.resources[0], records: [] }, ledgerlyFixture.resources[1]] });
    const cases = generateCases(emptied, WITH_ANONYMOUS);
    const anonIds = ids(cases.filter(isAnonymous));
    expect(anonIds).toContain('list-invoices|anonymous|collection');
    expect(anonIds).not.toContain('get-invoice|anonymous|cross-tenant');
    expect(anonIds).not.toContain('patch-invoice|anonymous|cross-tenant');
    expect(anonIds).toContain('get-user|anonymous|cross-tenant');
    expect(anonIds).toHaveLength(4);
  });

  it('covers every Helpdesk endpoint, using the collection target for POST /tickets too', () => {
    const cases = generateCases(helpdesk(), WITH_ANONYMOUS);
    expect(ids(cases.filter(isAnonymous))).toEqual([
      'list-tickets|anonymous|collection',
      'create-ticket|anonymous|collection',
      'get-ticket|anonymous|cross-tenant',
      'patch-ticket|anonymous|cross-tenant',
      'delete-ticket|anonymous|cross-tenant',
      'export-tickets|anonymous|collection',
    ]);
    expect(caseOf(cases, 'create-ticket|anonymous|collection').targetKind).toBe('collection');
    expect(caseOf(cases, 'get-ticket|anonymous|cross-tenant').targetRecord).toBe('tkt-1001');
  });

  it('only ever adds anonymous cases: collection probes and create cases are identical with the row on or off', () => {
    for (const build of [ledgerly, helpdesk]) {
      const withRow = generateCases(build(), WITH_ANONYMOUS);
      expect(withRow.filter((c) => !isAnonymous(c))).toEqual(generateCases(build(), WITHOUT_ANONYMOUS));
      expect(withRow.filter(isAnonymous).every((c) => c.category === 'authentication')).toBe(true);
      expect(withRow.filter((c) => c.category === 'authentication').every(isAnonymous)).toBe(true);
    }
  });
});

describe('collection sensitive-field probes', () => {
  it('probes each sensitive field once per allowed caller on GET /tickets, right after the base case', () => {
    const c = helpdesk();
    const cases = generateCases(c, WITHOUT_ANONYMOUS);
    for (const p of c.principals) {
      const base = caseOf(cases, `list-tickets|${p.id}|collection`);
      expect(base).toMatchObject({ category: 'object', expected: 'allow', targetKind: 'collection' });
      const probe = caseOf(cases, `list-tickets|${p.id}|collection|read:internalNotes`);
      expect(probe).toStrictEqual({
        id: `list-tickets|${p.id}|collection|read:internalNotes`, endpoint: 'list-tickets', principal: p.id, role: p.role,
        targetKind: 'collection', category: 'property', expected: 'allow', probeField: 'internalNotes',
        rationale: expect.stringContaining('"internalNotes" is marked sensitive'),
      });
      expect(cases.indexOf(probe)).toBe(cases.indexOf(base) + 1);
    }
    expect(ids(cases).filter((id) => id.startsWith('list-tickets|') && id.includes('|read:'))).toHaveLength(c.principals.length);
  });

  it('skips the probe for principals whose collection call is a function-level deny', () => {
    const c = helpdeskWith('list-tickets', { access: { roles: ['admin', 'agent'], ownership: 'same-tenant' } });
    const cases = generateCases(c, WITHOUT_ANONYMOUS);
    expect(caseOf(cases, 'list-tickets|p-cust-1|collection')).toMatchObject({ category: 'function', expected: 'deny' });
    expect(ids(cases).filter((id) => id.startsWith('list-tickets|p-cust-'))).toEqual(['list-tickets|p-cust-1|collection', 'list-tickets|p-cust-2|collection']);
    expect(ids(cases)).toContain('list-tickets|p-admin-1|collection|read:internalNotes');
    expect(ids(cases)).toContain('list-tickets|p-agent-2|collection|read:internalNotes');
  });

  it('emits no collection probe for a GET collection without sensitiveFields (export-tickets)', () => {
    const cases = generateCases(helpdesk(), WITHOUT_ANONYMOUS);
    expect(caseOf(cases, 'export-tickets|p-admin-1|collection')).toMatchObject({ expected: 'allow', category: 'object' });
    expect(ids(cases).filter((id) => id.startsWith('export-tickets|') && id.includes('|read:'))).toEqual([]);
  });
});

describe('POST create cases', () => {
  const CREATE_RATIONALE = 'Role is allowed to create; the server must bind only writable fields.';

  it('treats POST without {id} as a create for allowed roles (Helpdesk customer)', () => {
    const cases = generateCases(helpdesk(), WITHOUT_ANONYMOUS);
    expect(caseOf(cases, 'create-ticket|p-cust-1|create')).toStrictEqual({
      id: 'create-ticket|p-cust-1|create', endpoint: 'create-ticket', principal: 'p-cust-1', role: 'customer',
      targetKind: 'create', category: 'object', expected: 'allow', rationale: CREATE_RATIONALE,
    });
    expect(ids(cases).filter((id) => id.startsWith('create-ticket|') && id.endsWith('|collection'))).toEqual([]);
    expect(cases.filter((c) => c.endpoint === 'create-ticket').every((c) => c.targetKind === 'create')).toBe(true);
  });

  it('adds one write probe per non-writable resource field after each allowed create', () => {
    const c = helpdesk();
    const cases = generateCases(c, WITHOUT_ANONYMOUS);
    for (const p of c.principals) {
      const probeIds = ids(cases).filter((id) => id.startsWith(`create-ticket|${p.id}|create|write:`));
      expect(probeIds).toEqual([
        `create-ticket|${p.id}|create|write:status`,
        `create-ticket|${p.id}|create|write:priority`,
        `create-ticket|${p.id}|create|write:internalNotes`,
      ]);
    }
    expect(caseOf(cases, 'create-ticket|p-cust-1|create|write:status')).toStrictEqual({
      id: 'create-ticket|p-cust-1|create|write:status', endpoint: 'create-ticket', principal: 'p-cust-1', role: 'customer',
      targetKind: 'create', category: 'property', expected: 'allow', probeField: 'status',
      rationale: '"status" is not in writableFields [subject, body]; a create must not accept it.',
    });
    expect(caseOf(cases, 'create-ticket|p-cust-1|create|write:internalNotes')).toMatchObject({ probeField: 'internalNotes', targetKind: 'create', category: 'property', expected: 'allow' });
    const base = caseOf(cases, 'create-ticket|p-cust-1|create');
    expect(cases.indexOf(caseOf(cases, 'create-ticket|p-cust-1|create|write:status'))).toBe(cases.indexOf(base) + 1);
  });

  it('marks a denied role\'s create as a function-level deny with no probes', () => {
    const c = helpdeskWith('create-ticket', { access: { roles: ['admin', 'agent'], ownership: 'any' } });
    const cases = generateCases(c, WITHOUT_ANONYMOUS);
    expect(caseOf(cases, 'create-ticket|p-cust-1|create')).toStrictEqual({
      id: 'create-ticket|p-cust-1|create', endpoint: 'create-ticket', principal: 'p-cust-1', role: 'customer',
      targetKind: 'create', category: 'function', expected: 'deny',
      rationale: 'Role "customer" is not in the endpoint\'s allowed roles [admin, agent].',
    });
    expect(ids(cases).filter((id) => id.startsWith('create-ticket|p-cust-1|'))).toEqual(['create-ticket|p-cust-1|create']);
    expect(ids(cases).filter((id) => id.startsWith('create-ticket|p-agent-1|create|write:'))).toHaveLength(3);
  });

  it('emits no create probes when the POST endpoint declares no writableFields', () => {
    const c = helpdeskWith('create-ticket', { writableFields: undefined });
    expect(endpointOf(c, 'create-ticket').writableFields).toBeUndefined();
    const cases = generateCases(c, WITHOUT_ANONYMOUS);
    expect(caseOf(cases, 'create-ticket|p-cust-1|create')).toMatchObject({ targetKind: 'create', expected: 'allow' });
    expect(ids(cases).filter((id) => id.includes('|create|write:'))).toEqual([]);
  });

  it('resourceFieldNames returns the union of record field names in first-seen order', () => {
    const resource: Resource = {
      id: 'r', label: 'R', records: [
        { id: 'a', owner: 'p', tenant: 't', fields: { alpha: 1, beta: 'x' } },
        { id: 'b', owner: 'p', tenant: 't', fields: { beta: 'y', gamma: true } },
        { id: 'c', owner: 'p', tenant: 't', fields: {} },
        { id: 'd', owner: 'p', tenant: 't', fields: { delta: null, alpha: 2 } },
      ],
    };
    expect(resourceFieldNames(resource)).toEqual(['alpha', 'beta', 'gamma', 'delta']);
    expect(resourceFieldNames({ id: 'empty', label: 'Empty', records: [] })).toEqual([]);
    const tickets = helpdesk().resources[0];
    expect(resourceFieldNames(tickets)).toEqual(HELPDESK_FIELDS);
  });
});

describe('Helpdesk fixture', () => {
  it('validates and matches the documented shape', () => {
    expect(validateContract(helpdeskFixture).ok).toBe(true);
    const c = helpdesk();
    expect(c.name).toBe('Helpdesk Desk API (synthetic demo)');
    expect(c.version).toBe('2.3.0');
    expect(c.servers).toEqual(['mock://helpdesk.example']);
    expect(c.roles.map((r) => r.id)).toEqual(['admin', 'agent', 'customer']);
    expect(c.principals).toHaveLength(5);
    expect(new Set(c.principals.map((p) => p.tenant))).toEqual(new Set(['acme.example', 'globex.example']));
    expect(c.resources.map((r) => r.id)).toEqual(['tickets']);
    const tickets = c.resources[0];
    expect(tickets.records.length).toBeGreaterThanOrEqual(5);
    expect(new Set(tickets.records.map((r) => r.tenant))).toEqual(new Set(['acme.example', 'globex.example']));
    const tenantOf = new Map(c.principals.map((p) => [p.id, p.tenant]));
    for (const p of c.principals) expect(tickets.records.some((r) => r.owner === p.id), `${p.id} owns a ticket`).toBe(true);
    for (const r of tickets.records) {
      expect(r.tenant, `${r.id} sits in its owner's tenant`).toBe(tenantOf.get(r.owner));
      expect(Object.keys(r.fields)).toEqual(HELPDESK_FIELDS);
    }
    expect(c.endpoints.map((e) => `${e.id} ${e.method} ${e.path}`)).toEqual([
      'list-tickets GET /tickets',
      'create-ticket POST /tickets',
      'get-ticket GET /tickets/{id}',
      'patch-ticket PATCH /tickets/{id}',
      'delete-ticket DELETE /tickets/{id}',
      'export-tickets GET /tickets/export',
    ]);
    const all = ['admin', 'agent', 'customer'];
    expect(endpointOf(c, 'list-tickets')).toStrictEqual({ id: 'list-tickets', method: 'GET', path: '/tickets', resource: 'tickets', access: { roles: all, ownership: 'same-tenant' }, sensitiveFields: ['internalNotes'] });
    expect(endpointOf(c, 'create-ticket')).toStrictEqual({ id: 'create-ticket', method: 'POST', path: '/tickets', resource: 'tickets', access: { roles: all, ownership: 'any' }, writableFields: ['subject', 'body'] });
    expect(endpointOf(c, 'get-ticket')).toStrictEqual({ id: 'get-ticket', method: 'GET', path: '/tickets/{id}', resource: 'tickets', access: { roles: all, ownership: 'same-tenant' }, sensitiveFields: ['internalNotes'] });
    expect(endpointOf(c, 'patch-ticket')).toStrictEqual({ id: 'patch-ticket', method: 'PATCH', path: '/tickets/{id}', resource: 'tickets', access: { roles: ['admin', 'agent'], ownership: 'same-tenant' }, writableFields: ['status', 'priority'] });
    expect(endpointOf(c, 'delete-ticket')).toStrictEqual({ id: 'delete-ticket', method: 'DELETE', path: '/tickets/{id}', resource: 'tickets', access: { roles: ['admin'], ownership: 'any' } });
    expect(endpointOf(c, 'export-tickets')).toStrictEqual({ id: 'export-tickets', method: 'GET', path: '/tickets/export', resource: 'tickets', access: { roles: ['admin'], ownership: 'any' } });
    expect(c.builds.vulnerable).toEqual({
      label: 'release/2.3.0 (vulnerable)',
      flaws: [
        { endpoint: 'export-tickets', kind: 'skip-authentication' },
        { endpoint: 'create-ticket', kind: 'accept-all-fields' },
        { endpoint: 'list-tickets', kind: 'return-sensitive-fields' },
        { endpoint: 'list-tickets', kind: 'skip-ownership-check' },
      ],
    });
    expect(c.builds.fixed).toEqual({ label: 'release/2.3.1 (remediated)', flaws: [] });
  });

  it('generates the measured case counts: Ledgerly 83/89, Helpdesk 108/114 without/with the anonymous row', () => {
    // Measured by printing once, then frozen; a change here is a deliberate generator change, not a guess.
    expect(generateCases(ledgerly(), WITHOUT_ANONYMOUS)).toHaveLength(83);
    expect(generateCases(ledgerly(), WITH_ANONYMOUS)).toHaveLength(89);
    expect(generateCases(helpdesk(), WITHOUT_ANONYMOUS)).toHaveLength(108);
    expect(generateCases(helpdesk(), WITH_ANONYMOUS)).toHaveLength(114);
    const perEndpoint = (cases: TestCase[]): Record<string, number> =>
      cases.reduce<Record<string, number>>((acc, c) => ({ ...acc, [c.endpoint]: (acc[c.endpoint] ?? 0) + 1 }), {});
    expect(perEndpoint(generateCases(helpdesk(), WITHOUT_ANONYMOUS))).toEqual({
      'list-tickets': 10,   // 5 × (collection + internalNotes probe)
      'create-ticket': 20,  // 5 × (create + 3 write probes)
      'get-ticket': 25,     // 5 × 3 targets + 2 allowed targets × 1 read probe
      'patch-ticket': 33,   // 3 allowed callers × (3 targets + 2 × 3 write probes) + 2 customers × 3 denies
      'delete-ticket': 15,  // 5 × 3 targets
      'export-tickets': 5,  // 5 × collection
    });
  });

  it('remediated build passes every non-anonymous case under the suite runner (fixture self-consistency)', () => {
    // Anonymous cases need the runner's authentication oracle, which lands separately; everything else must already hold.
    const c = helpdesk();
    const run = runSuite(c, generateCases(c, WITHOUT_ANONYMOUS), []);
    expect(run.findings).toEqual([]);
    expect(run.results.every((r) => r.verdict === 'pass')).toBe(true);
    expect(run.results).toHaveLength(108);
  });

  it('is deterministic, never repeats an id and does not mutate the contract, whatever the options', () => {
    const variants: (GenerateOptions | undefined)[] = [undefined, {}, WITHOUT_ANONYMOUS, WITH_ANONYMOUS];
    for (const build of [ledgerly, helpdesk]) {
      for (const options of variants) {
        const c = build();
        const before = JSON.stringify(c);
        const a = generateCases(c, options);
        const b = generateCases(build(), options);
        expect(a).toEqual(b);
        expect(new Set(ids(a)).size).toBe(a.length);
        expect(JSON.stringify(c)).toBe(before);
      }
    }
  });
});
