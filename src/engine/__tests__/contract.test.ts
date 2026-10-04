import { describe, expect, it } from 'vitest';
import fixture from '../../fixtures/ledgerly-contract.json';
import { FLAW_KINDS, LIMITS, RESERVED_IDS, isLocalTarget, parseContract, validateContract } from '../contract';
import type { ValidationResult } from '../contract';
import { ANONYMOUS_PRINCIPAL, ANONYMOUS_ROLE } from '../types';
import type { ValidationIssue } from '../types';

// A mutable deep copy of the frozen Ledgerly fixture, typed loosely so tests can inject wrong shapes
// without casts. The fixture itself is never mutated.
interface DraftRecord { id: string; owner: string; tenant: string; fields: Record<string, unknown> }
interface DraftResource { id: string; label: string; records: DraftRecord[] }
interface DraftEndpoint {
  id: string;
  method: string;
  path: string;
  resource: string;
  access: Record<string, unknown>;
  writableFields?: unknown;
  sensitiveFields?: unknown;
}
interface Draft {
  [key: string]: unknown;
  schema: unknown;
  name: unknown;
  version: unknown;
  servers: string[];
  roles: Record<string, unknown>[];
  principals: Record<string, unknown>[];
  resources: DraftResource[];
  endpoints: DraftEndpoint[];
  builds: Record<string, { label: unknown; flaws: Record<string, unknown>[] }>;
}
const draft = (): Draft => JSON.parse(JSON.stringify(fixture)) as Draft;

/** Validates, asserts rejection, and returns the narrowed failure branch. */
function failing(input: unknown) {
  const result = validateContract(input);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error('expected the contract to be rejected');
  return result;
}
/** The messages reported at exactly this path. */
const at = (result: { issues: ValidationIssue[] }, path: string): string[] =>
  result.issues.filter((issue) => issue.path === path).map((issue) => issue.message);
/** How an issue must appear in the flat `errors` list. */
const render = (issue: ValidationIssue): string => (issue.path ? `${issue.path}: ${issue.message}` : issue.message);
/** Asserts a whole-document failure: one issue, empty path, bare message. */
function bare(result: ValidationResult, message: string): void {
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.issues).toEqual([{ path: '', message }]);
  expect(result.errors).toEqual([message]);
}

describe('path-addressed validation errors', () => {
  it('reports issues one-to-one with errors and renders each error as "<path>: <message>"', () => {
    const d = draft();
    d.servers = ['mock://ok.example', 'https://api.victim.example'];
    d.resources[0].records[1].id = 'inv-1001';
    d.endpoints[3].access.roles = ['admin', 'superuser'];
    d.builds.vulnerable.flaws[1].kind = 'nope';
    const r = failing(d);
    expect(r.errors.length).toBeGreaterThanOrEqual(4);
    expect(r.issues).toHaveLength(r.errors.length);
    r.errors.forEach((error, i) => expect(error).toBe(render(r.issues[i])));
    expect(r.issues.every((issue) => issue.path !== '')).toBe(true);
  });

  it('addresses a refused server to servers[i] with the frozen wording', () => {
    const d = draft();
    d.servers = ['mock://ok.example', 'https://api.victim.example'];
    const r = failing(d);
    const message = 'External target refused: "https://api.victim.example". Only mock:// or localhost targets are allowed.';
    expect(at(r, 'servers[1]')).toEqual([message]);
    expect(at(r, 'servers[0]')).toEqual([]);
    expect(r.errors).toEqual([`servers[1]: ${message}`]);
  });

  it('addresses a duplicate record id to resources[i].records[j].id with the frozen wording', () => {
    const d = draft();
    d.resources[0].records[1].id = 'inv-1001';
    const r = failing(d);
    expect(at(r, 'resources[0].records[1].id')).toEqual(['duplicate record id inv-1001 in resource invoices.']);
    expect(r.errors).toEqual(['resources[0].records[1].id: duplicate record id inv-1001 in resource invoices.']);
  });

  it('addresses an unknown role to endpoints[i].access.roles[k] and names the role', () => {
    const d = draft();
    d.endpoints[3].access.roles = ['admin', 'superuser'];
    const r = failing(d);
    expect(at(r, 'endpoints[3].access.roles[1]')).toEqual(['endpoint get-user references unknown role superuser.']);
    expect(r.errors).toEqual(['endpoints[3].access.roles[1]: endpoint get-user references unknown role superuser.']);
  });

  it('addresses a duplicate route to the offending endpoint with the frozen wording', () => {
    const d = draft();
    d.endpoints.push({ id: 'get-invoice-admin', method: 'GET', path: '/invoices/{id}', resource: 'invoices', access: { roles: ['admin'], ownership: 'any' } });
    const r = failing(d);
    expect(at(r, 'endpoints[6]')).toEqual([
      'endpoint get-invoice-admin: duplicate route GET /invoices/{id}; each method + path template may appear once so every request maps to exactly one policy.',
    ]);
    expect(r.errors).toHaveLength(1);
  });

  it('addresses method, resource, ownership and path problems to their endpoint fields', () => {
    const d = draft();
    d.endpoints[0].method = 'HEAD';
    d.endpoints[0].resource = 'ghosts';
    d.endpoints[0].access.ownership = 'everyone';
    d.endpoints[1].path = '/invoices/{invoiceId}';
    const r = failing(d);
    expect(at(r, 'endpoints[0].method')).toEqual(['endpoint list-invoices has unsupported method HEAD.']);
    expect(at(r, 'endpoints[0].resource')).toEqual(['endpoint list-invoices references unknown resource ghosts.']);
    expect(at(r, 'endpoints[0].access.ownership')).toEqual(['endpoint list-invoices ownership must be any|own|same-tenant.']);
    expect(at(r, 'endpoints[1].path')).toEqual(['endpoint get-invoice path may use only {id} as a parameter.']);
    expect(r.errors).toHaveLength(4);
  });

  it('addresses a bad field value or name to resources[i].records[j].fields.<key>, bracketing non-identifier keys', () => {
    const d = draft();
    d.resources[1].records[3].fields.role = []; // a nested object would trip the depth limit first
    d.resources[0].records[0].fields['amount-due'] = [];
    d.resources[0].records[0].fields['bad name'] = 1;
    const r = failing(d);
    expect(at(r, 'resources[1].records[3].fields.role')).toEqual(['record p-mem-2 field "role" must be a string, finite number, boolean or null.']);
    expect(at(r, 'resources[0].records[0].fields["amount-due"]')).toEqual(['record inv-1001 field "amount-due" must be a string, finite number, boolean or null.']);
    expect(at(r, 'resources[0].records[0].fields["bad name"]')).toEqual(['record inv-1001 field name "bad name" is malformed.']);
    expect(r.errors).toHaveLength(3);
  });

  it('addresses role, principal and flaw problems to roles[i].id, principals[i].role and builds.<key>.flaws[k].<field>', () => {
    const d = draft();
    d.roles.push({ id: 'admin', label: 'Admin again' });
    d.principals[2].role = 'ghost';
    d.builds.vulnerable.flaws[0].endpoint = 'ghost-endpoint';
    d.builds.vulnerable.flaws[1].kind = 'nope';
    const r = failing(d);
    expect(at(r, 'roles[3].id')).toEqual(['duplicate role id admin.']);
    expect(at(r, 'principals[2].role')).toEqual(['principal p-mem-1 references unknown role ghost.']);
    expect(at(r, 'builds.vulnerable.flaws[0].endpoint')).toEqual(['build vulnerable flaw references unknown endpoint ghost-endpoint.']);
    expect(at(r, 'builds.vulnerable.flaws[1].kind')).toEqual([
      'build vulnerable flaw kind must be one of skip-ownership-check, skip-role-check, accept-all-fields, return-sensitive-fields, deny-everything, skip-authentication.',
    ]);
    expect(r.errors).toHaveLength(4);
  });

  it('rejects a builds value that is not an object instead of silently dropping it', () => {
    const d: Record<string, unknown> = draft();
    d.builds = 'nope';
    const r = failing(d);
    expect(at(r, 'builds')).toEqual(['builds must be an object keyed by build id.']);
    expect(r.errors).toHaveLength(1);
  });

  it('addresses top-level scalar and count problems to their keys', () => {
    const d = draft();
    d.schema = 'permitmatrix.contract/2';
    d.name = '';
    d.version = 7;
    d.servers = [];
    const r = failing(d);
    expect(at(r, 'schema')).toEqual(['schema must be "permitmatrix.contract/1".']);
    expect(at(r, 'name')).toEqual([`name must be a string of 1–${LIMITS.maxStringLength} characters.`]);
    expect(at(r, 'version')).toEqual([`version must be a string of 1–${LIMITS.maxStringLength} characters.`]);
    expect(at(r, 'servers')).toEqual([`servers must list 1–${LIMITS.maxServers} mock:// or localhost targets.`]);
    expect(r.errors).toHaveLength(4);
  });

  it('uses an empty path and the bare message for whole-document problems', () => {
    bare(validateContract(42), 'Contract must be a JSON object.');
    bare(validateContract([]), 'Contract must be a JSON object.');
    bare(validateContract({ ...fixture, extra: [[[[[[[[1]]]]]]]] }), `Contract nesting exceeds ${LIMITS.maxDepth} levels.`);
    const text = JSON.stringify(fixture).replace('"amount":120.5', '"amount":1e999');
    expect(text).toMatch(/1e999/);
    bare(parseContract(text), 'Contract contains a non-finite number (numbers must be finite).');
  });

  it('parseContract reports the byte limit and invalid JSON as issues too', () => {
    bare(parseContract('{ not json'), 'Contract is not valid JSON.');
    bare(parseContract(JSON.stringify(fixture) + ' '.repeat(LIMITS.maxBytes)), `Contract text exceeds ${LIMITS.maxBytes} bytes (UTF-8).`);
  });
});

describe('access.roles', () => {
  const message = 'endpoint list-invoices access.roles must be a non-empty list of role ids.';

  it('is required: a missing list is an error, not an endpoint nobody may call', () => {
    const d = draft();
    delete d.endpoints[0].access.roles;
    expect(at(failing(d), 'endpoints[0].access.roles')).toEqual([message]);
  });

  it('must be an array: a bare string is an error, not an empty list', () => {
    const d = draft();
    d.endpoints[0].access.roles = 'admin';
    expect(at(failing(d), 'endpoints[0].access.roles')).toEqual([message]);
  });

  it('must not be empty', () => {
    const d = draft();
    d.endpoints[0].access.roles = [];
    expect(at(failing(d), 'endpoints[0].access.roles')).toEqual([message]);
  });

  it('rejects non-string entries at their index', () => {
    const d = draft();
    d.endpoints[0].access.roles = [1, 'admin', null];
    const r = failing(d);
    expect(at(r, 'endpoints[0].access.roles[0]')).toEqual(['endpoint list-invoices access.roles entries must be strings.']);
    expect(at(r, 'endpoints[0].access.roles[2]')).toEqual(['endpoint list-invoices access.roles entries must be strings.']);
    expect(at(r, 'endpoints[0].access.roles[1]')).toEqual([]);
    expect(r.errors).toHaveLength(2);
  });

  it('rejects a repeated role at the repeated index', () => {
    const d = draft();
    d.endpoints[0].access.roles = ['admin', 'member', 'admin'];
    const r = failing(d);
    expect(at(r, 'endpoints[0].access.roles[2]')).toEqual(['endpoint list-invoices access.roles contains duplicate role admin.']);
    expect(r.errors).toHaveLength(1);
  });
});

describe('writableFields and sensitiveFields', () => {
  it('reject a repeated field name at the repeated index', () => {
    const d = draft();
    d.endpoints[2].writableFields = ['memo', 'memo'];
    d.endpoints[3].sensitiveFields = ['passwordHash', 'email', 'passwordHash'];
    const r = failing(d);
    expect(at(r, 'endpoints[2].writableFields[1]')).toEqual(['endpoint patch-invoice writableFields contains duplicate field memo.']);
    expect(at(r, 'endpoints[3].sensitiveFields[2]')).toEqual(['endpoint get-user sensitiveFields contains duplicate field passwordHash.']);
    expect(r.errors).toHaveLength(2);
  });

  it('must be lists of field names, reported per list or per entry', () => {
    const d = draft();
    d.endpoints[2].writableFields = 'memo';
    d.endpoints[3].sensitiveFields = ['passwordHash', 42];
    const r = failing(d);
    expect(at(r, 'endpoints[2].writableFields')).toEqual(['endpoint patch-invoice writableFields must be a list of field names.']);
    expect(at(r, 'endpoints[3].sensitiveFields[1]')).toEqual(['endpoint get-user sensitiveFields entries must be field names.']);
    expect(r.errors).toHaveLength(2);
  });
});

describe('reserved identifiers', () => {
  it('exports the ids claimed by the synthetic anonymous caller as a frozen list', () => {
    expect(RESERVED_IDS).toContain(ANONYMOUS_PRINCIPAL);
    expect(RESERVED_IDS).toContain(ANONYMOUS_ROLE.id);
    expect(Object.isFrozen(RESERVED_IDS)).toBe(true);
  });

  it.each(['anonymous', 'Anonymous', 'ANONYMOUS'])('refuses role id "%s" as reserved', (id) => {
    const d = draft();
    d.roles[2].id = id;
    const messages = at(failing(d), 'roles[2].id');
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatch(/reserved/);
  });

  it.each(['anonymous', 'Anonymous'])('refuses principal id "%s" as reserved', (id) => {
    const d = draft();
    d.principals[3].id = id;
    const messages = at(failing(d), 'principals[3].id');
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatch(/reserved/);
  });

  it('refuses a record owner of anonymous as reserved, with a single error', () => {
    const d = draft();
    d.resources[0].records[2].owner = 'anonymous';
    const r = failing(d);
    const messages = at(r, 'resources[0].records[2].owner');
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatch(/reserved/);
    expect(r.errors).toHaveLength(1);
  });

  it('refuses anonymous inside access.roles as reserved rather than merely unknown', () => {
    const d = draft();
    d.endpoints[0].access.roles = ['admin', 'anonymous'];
    const messages = at(failing(d), 'endpoints[0].access.roles[1]');
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatch(/reserved/);
  });
});

describe('reserved field names', () => {
  it.each(['constructor', 'prototype'])('refuses record field key "%s"', (key) => {
    const d = draft();
    d.resources[1].records[0].fields[key] = 'x';
    const messages = at(failing(d), `resources[1].records[0].fields.${key}`);
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatch(/reserved field name/);
  });

  it('refuses a __proto__ record field key arriving through JSON text', () => {
    const text = JSON.stringify(fixture).replace('"memo":"Design retainer"', '"__proto__":"Design retainer"');
    expect(text).toContain('"__proto__"');
    const r = parseContract(text);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(at(r, 'resources[0].records[0].fields.__proto__')).toEqual(['record inv-1001 uses reserved field name "__proto__".']);
  });

  it('refuses reserved names in writableFields and sensitiveFields', () => {
    const d = draft();
    d.endpoints[2].writableFields = ['memo', 'constructor'];
    d.endpoints[3].sensitiveFields = ['__proto__'];
    const r = failing(d);
    expect(at(r, 'endpoints[2].writableFields[1]')).toHaveLength(1);
    expect(at(r, 'endpoints[2].writableFields[1]')[0]).toMatch(/reserved field name/);
    expect(at(r, 'endpoints[3].sensitiveFields[0]')).toHaveLength(1);
    expect(at(r, 'endpoints[3].sensitiveFields[0]')[0]).toMatch(/reserved field name/);
    expect(r.errors).toHaveLength(2);
  });

  it.each(['__proto__', 'constructor', 'prototype'])('refuses build key "%s" without touching Object.prototype', (key) => {
    const text = JSON.stringify(fixture).replace('"vulnerable":', `"${key}":`);
    expect(text).toContain(`"${key}":`);
    const r = parseContract(text);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    const messages = at(r, `builds.${key}`);
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatch(/reserved/);
    expect(Object.prototype).not.toHaveProperty('label');
    expect(({} as Record<string, unknown>).flaws).toBeUndefined();
  });
});

describe('flaw kinds', () => {
  it('exports the frozen list including skip-authentication', () => {
    expect(FLAW_KINDS).toContain('skip-authentication');
    expect(FLAW_KINDS).toHaveLength(6);
    expect(Object.isFrozen(FLAW_KINDS)).toBe(true);
  });

  it('accepts a build that seeds skip-authentication', () => {
    const d = draft();
    d.builds.vulnerable.flaws.push({ endpoint: 'list-invoices', kind: 'skip-authentication' });
    const r = validateContract(d);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.contract.builds.vulnerable.flaws).toContainEqual({ endpoint: 'list-invoices', kind: 'skip-authentication' });
  });
});

describe('normalisation', () => {
  it('is a fixpoint: validating a validated contract yields a deep-equal contract', () => {
    const first = validateContract(fixture);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const second = validateContract(first.contract);
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.contract).toStrictEqual(first.contract);
  });

  it('fills in the fixed build, drops unknown top-level keys and stays a fixpoint', () => {
    const d = draft();
    delete d.builds.fixed;
    d.$schema = 'https://example.invalid/permitmatrix.contract-1.schema.json';
    d.notes = { anything: true };
    const first = validateContract(d);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.contract.builds.fixed).toEqual({ label: 'fixed (no seeded flaws)', flaws: [] });
    expect(Object.keys(first.contract).sort()).toEqual(['builds', 'endpoints', 'name', 'principals', 'resources', 'roles', 'schema', 'servers', 'version']);
    const second = validateContract(first.contract);
    expect(second.ok).toBe(true);
    if (second.ok) expect(second.contract).toStrictEqual(first.contract);
  });

  it('does not alias the caller\'s servers array', () => {
    const d = draft();
    const r = validateContract(d);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    d.servers.push('https://api.victim.example');
    expect(r.contract.servers).toEqual(['mock://ledgerly.example']);
  });
});

describe('isLocalTarget (characterisation of the loopback rule)', () => {
  it.each([
    'http://localhost@evil.example', // "localhost" is only the userinfo; the host is evil.example
    'http://evil.example/#localhost', // "localhost" is only the fragment
    'http://127.0.0.1.evil.example', // loopback-looking label on a real domain
    'mock://x.example/path', // mock targets are bare hosts
    'ftp://localhost', // loopback, but not http(s)
    'javascript:alert(1)', // not a network scheme
    'mock://', // no host
    'http://0.0.0.0', // not the loopback literal the engine accepts
    'http://localhost:6110@evil.example', // userinfo with a port still names evil.example as the host
    'http://localhost.', // trailing dot: not the exact literal (over-strict, but refusing is the safe side)
    'http://[::ffff:127.0.0.1]', // IPv4-mapped IPv6 loopback is not recognised (over-strict, same reasoning)
    '',
  ])('refuses %j', (target) => {
    expect(isLocalTarget(target)).toBe(false);
  });

  it.each([
    'http://localhost:6110/api',
    'https://[::1]:8443',
    'MOCK://X.EXAMPLE', // scheme and host are case-insensitive
    'http://LOCALHOST', // the URL parser lowercases special-scheme hosts
    'http://127.0.0.1',
    'http://127.1', // the URL parser normalises short IPv4 forms to 127.0.0.1
    'mock://ledgerly.example',
  ])('accepts %j', (target) => {
    expect(isLocalTarget(target)).toBe(true);
  });
});
