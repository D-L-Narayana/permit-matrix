import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import ledgerlyFixture from '../../fixtures/ledgerly-contract.json';
import helpdeskFixture from '../../fixtures/helpdesk-contract.json';
import { validateContract } from '../contract';
import { LINT_RULES, lintContract, type LintCode } from '../lint';
import { LintPanel } from '../../features/lint/LintPanel';
import type { Contract, ContractWarning } from '../types';

/** Loosely typed, editable copy of a contract document so tests can add, remove and misspell freely. */
interface Draft {
  schema: string;
  name: string;
  version: string;
  servers: string[];
  roles: { id: string; label: string }[];
  principals: { id: string; role: string; tenant: string; label: string }[];
  resources: { id: string; label: string; records: { id: string; owner: string; tenant: string; fields: Record<string, string | number | boolean | null> }[] }[];
  endpoints: { id: string; method: string; path: string; resource: string; access: { roles: string[]; ownership: string }; writableFields?: string[]; sensitiveFields?: string[] }[];
  builds: Record<string, { label: string; flaws: { endpoint: string; kind: string }[] }>;
}

const ALL_CODES: LintCode[] = [
  'unused-role', 'principal-without-records', 'single-tenant', 'field-not-on-records', 'writable-on-read-endpoint',
  'sensitive-on-write-endpoint', 'list-item-scope-mismatch', 'record-tenant-mismatch', 'no-negative-cases', 'noop-flaw',
];
const ALL_ROLES = ['admin', 'manager', 'member'];

const ledgerly = (): Draft => structuredClone(ledgerlyFixture) as unknown as Draft;

function load(draft: unknown): Contract {
  const result = validateContract(draft);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
}
const lint = (draft: unknown) => lintContract(load(draft));
const only = (warnings: ContractWarning[], code: LintCode) => warnings.filter((w) => w.code === code);

describe('lintContract — the shipped fixtures lint clean by design', () => {
  it('Ledgerly produces no warnings', () => {
    expect(lint(ledgerlyFixture)).toEqual([]);
  });

  it('Helpdesk (same-tenant list + item, admin-only /tickets/export, all-roles POST with writableFields) produces no warnings', () => {
    expect(lint(helpdeskFixture)).toEqual([]);
  });
});

describe('LINT_RULES', () => {
  it('documents every code with a severity and a summary', () => {
    expect(Object.keys(LINT_RULES).sort()).toEqual([...ALL_CODES].sort());
    for (const code of ALL_CODES) {
      expect(['info', 'warn']).toContain(LINT_RULES[code].severity);
      expect(LINT_RULES[code].summary.length).toBeGreaterThan(20);
    }
    expect(LINT_RULES['single-tenant'].severity).toBe('info');
    expect(LINT_RULES['sensitive-on-write-endpoint'].severity).toBe('info');
    expect(LINT_RULES['no-negative-cases'].severity).toBe('info');
    expect(LINT_RULES['list-item-scope-mismatch'].severity).toBe('warn');
    expect(LINT_RULES['noop-flaw'].severity).toBe('warn');
  });

  it('every emitted warning carries the severity of its rule', () => {
    const d = ledgerly();
    d.roles.push({ id: 'auditor', label: 'Auditor' });
    d.endpoints[4].sensitiveFields = ['passwordHash'];
    for (const p of d.principals) p.tenant = 'acme.example';
    for (const r of d.resources) for (const rec of r.records) rec.tenant = 'acme.example';
    const warnings = lint(d);
    expect(warnings.length).toBeGreaterThanOrEqual(3);
    for (const w of warnings) expect(w.severity).toBe(LINT_RULES[w.code].severity);
  });
});

describe('unused-role', () => {
  it('fires for a role that no principal carries', () => {
    const d = ledgerly();
    d.roles.push({ id: 'auditor', label: 'Auditor' });
    const w = only(lint(d), 'unused-role');
    expect(w).toHaveLength(1);
    expect(w[0]).toMatchObject({ severity: 'warn', path: 'roles[3]' });
    expect(w[0].message).toMatch(/"auditor"/);
  });

  it('stays silent once the role has a principal, even one no endpoint allows and that owns nothing', () => {
    const d = ledgerly();
    d.roles.push({ id: 'auditor', label: 'Auditor' });
    d.principals.push({ id: 'p-aud-1', role: 'auditor', tenant: 'acme.example', label: 'Audit (auditor)' });
    expect(lint(d)).toEqual([]);
  });
});

describe('principal-without-records', () => {
  it('fires when a principal owns nothing in a resource whose own-scoped {id} endpoint it may call', () => {
    const d = ledgerly();
    d.resources[0].records = d.resources[0].records.filter((r) => r.id !== 'inv-2001');
    const w = only(lint(d), 'principal-without-records');
    expect(w).toHaveLength(1);
    expect(w[0]).toMatchObject({ severity: 'warn', path: 'resources[0].records' });
    expect(w[0].message).toMatch(/"p-mem-2"/);
    expect(w[0].message).toMatch(/"invoices"/);
    expect(w[0].message).toMatch(/"get-invoice"/);
  });

  it('stays silent when no {id} endpoint of the resource is own-scoped', () => {
    const d = ledgerly();
    d.resources[0].records = d.resources[0].records.filter((r) => r.id !== 'inv-2001');
    for (const e of d.endpoints) if (e.resource === 'invoices') e.access.ownership = 'same-tenant';
    expect(only(lint(d), 'principal-without-records')).toEqual([]);
  });
});

describe('single-tenant', () => {
  it('notes (info) when every principal shares one tenant', () => {
    const d = ledgerly();
    for (const p of d.principals) p.tenant = 'acme.example';
    for (const r of d.resources) for (const rec of r.records) rec.tenant = 'acme.example';
    expect(lint(d)).toEqual([
      { code: 'single-tenant', severity: 'info', path: 'principals', message: expect.stringMatching(/cross-tenant/) },
    ]);
  });

  it('stays silent with two tenants', () => {
    expect(only(lint(ledgerlyFixture), 'single-tenant')).toEqual([]);
  });
});

describe('field-not-on-records', () => {
  it('fires, addressed to the list element, for a writable or sensitive field no record of the resource has', () => {
    const d = ledgerly();
    d.endpoints[2].writableFields = ['memo', 'discount'];
    d.endpoints[3].sensitiveFields = ['passwordHash', 'ssn'];
    const w = only(lint(d), 'field-not-on-records');
    expect(w.map((x) => x.path)).toEqual(['endpoints[2].writableFields[1]', 'endpoints[3].sensitiveFields[1]']);
    expect(w.every((x) => x.severity === 'warn')).toBe(true);
    expect(w[0].message).toMatch(/"discount"/);
    expect(w[0].message).toMatch(/"invoices"/);
    expect(w[1].message).toMatch(/"ssn"/);
  });

  it('stays silent when at least one record of the resource has the field', () => {
    const d = ledgerly();
    d.resources[0].records[0].fields.discount = 5;
    d.endpoints[2].writableFields = ['memo', 'discount'];
    expect(only(lint(d), 'field-not-on-records')).toEqual([]);
  });
});

describe('writable-on-read-endpoint', () => {
  it('fires for writableFields on GET or DELETE', () => {
    const d = ledgerly();
    d.endpoints[1].writableFields = ['memo'];
    d.endpoints[5].writableFields = ['displayName'];
    const w = only(lint(d), 'writable-on-read-endpoint');
    expect(w.map((x) => x.path)).toEqual(['endpoints[1].writableFields', 'endpoints[5].writableFields']);
    expect(w.every((x) => x.severity === 'warn')).toBe(true);
    expect(w[0].message).toMatch(/GET/);
    expect(w[1].message).toMatch(/DELETE/);
  });

  it('stays silent for writableFields on PATCH, PUT and POST', () => {
    const d = ledgerly();
    d.endpoints[2].method = 'PUT';
    d.endpoints.push({ id: 'create-invoice', method: 'POST', path: '/invoices', resource: 'invoices', access: { roles: ['admin'], ownership: 'any' }, writableFields: ['memo'] });
    expect(only(lint(d), 'writable-on-read-endpoint')).toEqual([]);
  });
});

describe('sensitive-on-write-endpoint', () => {
  it('notes (info) sensitiveFields on PATCH or DELETE', () => {
    const d = ledgerly();
    d.endpoints[4].sensitiveFields = ['passwordHash'];
    d.endpoints[5].sensitiveFields = ['passwordHash'];
    const w = only(lint(d), 'sensitive-on-write-endpoint');
    expect(w.map((x) => x.path)).toEqual(['endpoints[4].sensitiveFields', 'endpoints[5].sensitiveFields']);
    expect(w.every((x) => x.severity === 'info')).toBe(true);
    expect(w[0].message).toMatch(/PATCH/);
    expect(w[0].message).toMatch(/GET/);
  });

  it('stays silent for sensitiveFields on GET', () => {
    expect(only(lint(ledgerlyFixture), 'sensitive-on-write-endpoint')).toEqual([]);
  });
});

describe('list-item-scope-mismatch', () => {
  it('fires when GET <path> and GET <path>/{id} on the same resource disagree on ownership', () => {
    const d = ledgerly();
    d.endpoints[0].access.ownership = 'same-tenant';
    const w = only(lint(d), 'list-item-scope-mismatch');
    expect(w).toHaveLength(1);
    expect(w[0]).toMatchObject({ severity: 'warn', path: 'endpoints[0].access.ownership' });
    expect(w[0].message).toMatch(/"list-invoices"/);
    expect(w[0].message).toMatch(/"get-invoice"/);
    expect(w[0].message).toMatch(/"same-tenant"/);
    expect(w[0].message).toMatch(/"own"/);
  });

  it('does not pair a literal sibling such as GET /invoices/export (any) with GET /invoices/{id} (own)', () => {
    const d = ledgerly();
    d.endpoints.push({ id: 'export-invoices', method: 'GET', path: '/invoices/export', resource: 'invoices', access: { roles: ['admin'], ownership: 'any' } });
    expect(lint(d)).toEqual([]);
  });
});

describe('record-tenant-mismatch', () => {
  it('fires when a record sits in a different tenant from its owner', () => {
    const d = ledgerly();
    d.resources[0].records[0].tenant = 'globex.example'; // inv-1001 is owned by p-mem-1 (acme.example)
    const w = only(lint(d), 'record-tenant-mismatch');
    expect(w).toEqual([
      { code: 'record-tenant-mismatch', severity: 'warn', path: 'resources[0].records[0].tenant', message: expect.stringMatching(/"inv-1001".*"p-mem-1"/) },
    ]);
  });

  it('stays silent when a record moves tenant together with its owner', () => {
    const d = ledgerly();
    d.resources[0].records[2].owner = 'p-mem-1';
    d.resources[0].records[2].tenant = 'acme.example';
    expect(only(lint(d), 'record-tenant-mismatch')).toEqual([]);
  });
});

describe('no-negative-cases', () => {
  it('notes (info) an endpoint where every role is allowed with ownership "any" and no property probe applies', () => {
    const d = ledgerly();
    d.endpoints[5].access.roles = [...ALL_ROLES]; // delete-user is already ownership "any"; DELETE never has probes
    d.endpoints[2].access = { roles: [...ALL_ROLES], ownership: 'any' };
    d.endpoints[2].writableFields = ['memo', 'amount', 'status']; // every invoice field is writable: no probe left
    const w = only(lint(d), 'no-negative-cases');
    expect(w.map((x) => x.path)).toEqual(['endpoints[2].access', 'endpoints[5].access']);
    expect(w.every((x) => x.severity === 'info')).toBe(true);
    expect(w[1].message).toMatch(/"delete-user"/);
  });

  it('stays silent while writable or sensitive field probes still yield negative cases', () => {
    const d = ledgerly();
    d.endpoints[2].access = { roles: [...ALL_ROLES], ownership: 'any' }; // patch-invoice keeps writable [memo]; amount/status probes remain
    d.endpoints[3].access = { roles: [...ALL_ROLES], ownership: 'any' }; // get-user keeps sensitive [passwordHash]
    expect(only(lint(d), 'no-negative-cases')).toEqual([]);
  });
});

describe('noop-flaw', () => {
  it('fires for each seeded flaw the suite could never observe (the four specified conditions)', () => {
    const d = ledgerly();
    d.builds.vulnerable.flaws = [
      { endpoint: 'delete-user', kind: 'skip-ownership-check' }, // ownership "any": nothing to skip
      { endpoint: 'get-user', kind: 'accept-all-fields' }, // GET carries no body
      { endpoint: 'get-invoice', kind: 'return-sensitive-fields' }, // invoices declares no sensitive fields anywhere
      { endpoint: 'get-user', kind: 'skip-role-check' }, // every role already allowed
    ];
    const w = only(lint(d), 'noop-flaw');
    expect(w.map((x) => x.path)).toEqual(['builds.vulnerable.flaws[0]', 'builds.vulnerable.flaws[1]', 'builds.vulnerable.flaws[2]', 'builds.vulnerable.flaws[3]']);
    expect(w.every((x) => x.severity === 'warn')).toBe(true);
    expect(w[0].message).toMatch(/"skip-ownership-check".*"delete-user".*"any"/);
    expect(w[1].message).toMatch(/GET/);
    expect(w[2].message).toMatch(/sensitiveFields/);
    expect(w[3].message).toMatch(/every role/i);
  });

  it('also catches flaws no probe can reach: accept-all-fields without writableFields, return-sensitive-fields on a GET that declares none, skip-ownership-check on create', () => {
    const d = ledgerly();
    delete d.endpoints[2].writableFields;
    d.endpoints.push({ id: 'create-invoice', method: 'POST', path: '/invoices', resource: 'invoices', access: { roles: [...ALL_ROLES], ownership: 'own' }, writableFields: ['memo'] });
    d.endpoints.push({ id: 'list-users', method: 'GET', path: '/users', resource: 'users', access: { roles: ['admin'], ownership: 'own' } });
    d.builds.vulnerable.flaws = [
      { endpoint: 'patch-invoice', kind: 'accept-all-fields' },
      { endpoint: 'create-invoice', kind: 'skip-ownership-check' },
      { endpoint: 'list-users', kind: 'return-sensitive-fields' },
    ];
    const w = only(lint(d), 'noop-flaw');
    expect(w.map((x) => x.path)).toEqual(['builds.vulnerable.flaws[0]', 'builds.vulnerable.flaws[1]', 'builds.vulnerable.flaws[2]']);
    expect(w[0].message).toMatch(/writableFields/);
    expect(w[1].message).toMatch(/creat/i);
    expect(w[2].message).toMatch(/"list-users"/);
  });

  it('stays silent for the seeded Ledgerly flaws and for skip-authentication / deny-everything, which always have an effect', () => {
    const d = ledgerly();
    d.builds.vulnerable.flaws.push({ endpoint: 'delete-user', kind: 'skip-authentication' }, { endpoint: 'delete-user', kind: 'deny-everything' });
    expect(lint(d)).toEqual([]);
  });
});

describe('ordering', () => {
  it('is deterministic and sorted by path (indices in contract order), then code, then message', () => {
    const d = ledgerly();
    for (let i = 0; i < 7; i++) d.resources[0].records.push({ id: `inv-30${i}`, owner: 'p-mem-1', tenant: 'acme.example', fields: { amount: i, status: 'open', memo: 'Filler' } });
    d.resources[0].records[10].tenant = 'globex.example'; // owner p-mem-1 is acme
    d.resources[0].records[2].tenant = 'acme.example'; // inv-2001: owner p-mem-2 is globex
    d.roles.push({ id: 'auditor', label: 'Auditor' });
    d.endpoints[0].access.ownership = 'same-tenant';
    d.endpoints[1].writableFields = ['memo', 'discount'];
    const first = lint(d);
    const second = lintContract(load(d));
    expect(second).toEqual(first);
    expect(first.map((w) => `${w.path} ${w.code}`)).toEqual([
      'endpoints[0].access.ownership list-item-scope-mismatch',
      'endpoints[1].writableFields writable-on-read-endpoint',
      'endpoints[1].writableFields[1] field-not-on-records',
      'resources[0].records[2].tenant record-tenant-mismatch',
      'resources[0].records[10].tenant record-tenant-mismatch',
      'roles[3] unused-role',
    ]);
  });

  it('breaks same-path ties by message so repeated codes keep a stable order', () => {
    const d = ledgerly();
    d.resources[0].records = d.resources[0].records.filter((r) => r.id !== 'inv-2001' && r.id !== 'inv-1002');
    const w = only(lint(d), 'principal-without-records');
    expect(w.map((x) => x.path)).toEqual(['resources[0].records', 'resources[0].records']);
    expect(w[0].message).toMatch(/"p-mem-2"/);
    expect(w[1].message).toMatch(/"p-mgr-1"/);
  });
});

describe('LintPanel (static markup, text nodes only)', () => {
  const render = (warnings: ContractWarning[], compact?: boolean) => renderToStaticMarkup(createElement(LintPanel, { warnings, compact }));

  it('renders a labelled section with a heading and a one-line empty state', () => {
    const html = render([]);
    expect(html).toContain('aria-label="Contract health"');
    expect(html).toMatch(/<h2[^>]*>Contract health<\/h2>/);
    expect(html).toContain('No warnings');
    expect(html).not.toContain('<li');
  });

  it('lists each warning with a severity badge, code, path and message, escaping any markup in messages', () => {
    const html = render([
      { code: 'unused-role', severity: 'warn', path: 'roles[3]', message: 'Role auditor has no principal.' },
      { code: 'single-tenant', severity: 'info', path: 'principals', message: 'All <b>4</b> principals share one tenant.' },
    ], true);
    expect(html).toContain('<code class="lint-code">unused-role</code>');
    expect(html).toContain('<code class="lint-path">roles[3]</code>');
    expect(html).toMatch(/lint-badge[^>]*>warn</);
    expect(html).toMatch(/lint-badge[^>]*>info</);
    expect(html).toContain('Role auditor has no principal.');
    expect(html).toContain('&lt;b&gt;4&lt;/b&gt;');
    expect(html).not.toContain('<b>');
    expect(html).toMatch(/class="lint-panel compact"/);
    expect(html).toMatch(/1 warning/);
    expect(html).toMatch(/1 note/);
  });
});
