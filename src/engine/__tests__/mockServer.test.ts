import { describe, expect, it } from 'vitest';
import fixture from '../../fixtures/ledgerly-contract.json';
import helpdesk from '../../fixtures/helpdesk-contract.json';
import { validateContract } from '../contract';
import { createMockServer } from '../mockServer';
import { ANONYMOUS_PRINCIPAL } from '../types';
import type { Contract, Endpoint, Flaw, FlawKind } from '../types';

const ledgerly = (): Contract => {
  const result = validateContract(fixture);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
};

const ALL_ROLES = ['admin', 'manager', 'member'];
// Ledgerly has no collection endpoint with sensitive fields and no POST endpoint; these two are added by
// mutation so the new behaviours can be exercised against the frozen fixture.
const LIST_USERS: Endpoint = {
  id: 'list-users', method: 'GET', path: '/users', resource: 'users',
  access: { roles: ALL_ROLES, ownership: 'any' }, sensitiveFields: ['passwordHash'],
};
const CREATE_INVOICE: Endpoint = {
  id: 'create-invoice', method: 'POST', path: '/invoices', resource: 'invoices',
  access: { roles: ['admin', 'manager'], ownership: 'any' }, writableFields: ['memo'],
};

const withEndpoints = (contract: Contract, ...extra: Endpoint[]): Contract => ({ ...contract, endpoints: [...contract.endpoints, ...extra] });
const flaw = (endpoint: string, kind: FlawKind): Flaw => ({ endpoint, kind });

describe('mock server — routing before authentication', () => {
  it('answers 401 { error: "unauthenticated" } to a caller without credentials on the fixed build', () => {
    const server = createMockServer(ledgerly(), []);
    const anonymous = server.handle({ method: 'GET', path: '/invoices', principal: ANONYMOUS_PRINCIPAL });
    expect(anonymous.status).toBe(401);
    expect(anonymous.body).toEqual({ error: 'unauthenticated' });
    expect(server.handle({ method: 'GET', path: '/invoices/inv-1001', principal: '' }).status).toBe(401);
    // Frozen expectation from engine.test.ts.
    expect(server.handle({ method: 'GET', path: '/invoices/inv-1001', principal: 'nobody' }).status).toBe(401);
  });

  it('routes first: an unknown path is 404 and a method mismatch is 405 even without credentials', () => {
    const server = createMockServer(ledgerly(), []);
    const missing = server.handle({ method: 'GET', path: '/nope', principal: ANONYMOUS_PRINCIPAL });
    expect(missing.status).toBe(404);
    expect(missing.body).toEqual({ error: 'no such route' });
    const mismatch = server.handle({ method: 'POST', path: '/invoices/inv-1001', principal: ANONYMOUS_PRINCIPAL });
    expect(mismatch.status).toBe(405);
    expect(mismatch.body).toEqual({ error: 'method not allowed' });
    // Frozen expectation from engine.test.ts.
    expect(server.handle({ method: 'GET', path: '/nope', principal: 'p-admin-1' }).status).toBe(404);
  });

  it("returns 405 when the path matches another method's template", () => {
    const server = createMockServer(ledgerly(), []);
    // /invoices/{id} exists for GET and PATCH only; /invoices exists for GET only; /users/{id} has no PUT.
    expect(server.handle({ method: 'POST', path: '/invoices/inv-1001', principal: 'p-admin-1' }).status).toBe(405);
    expect(server.handle({ method: 'DELETE', path: '/invoices', principal: 'p-admin-1' }).status).toBe(405);
    const put = server.handle({ method: 'PUT', path: '/users/p-mem-1', principal: 'p-admin-1', body: { displayName: 'R.' } });
    expect(put.status).toBe(405);
    expect(put.body).toEqual({ error: 'method not allowed' });
  });

  it('keeps 401 on endpoints that still authenticate when a different endpoint skips authentication', () => {
    const server = createMockServer(ledgerly(), [flaw('list-invoices', 'skip-authentication')]);
    expect(server.handle({ method: 'GET', path: '/invoices/inv-1001', principal: ANONYMOUS_PRINCIPAL }).status).toBe(401);
    expect(server.handle({ method: 'PATCH', path: '/users/p-mem-1', principal: ANONYMOUS_PRINCIPAL, body: { displayName: 'x' } }).status).toBe(401);
  });

  it('keeps the fixed/vulnerable object-level behaviour for authenticated callers', () => {
    expect(createMockServer(ledgerly(), []).handle({ method: 'GET', path: '/invoices/inv-1002', principal: 'p-mem-1' }).status).toBe(403);
    const vulnerable = createMockServer(ledgerly(), fixture.builds.vulnerable.flaws as Flaw[]);
    expect(vulnerable.handle({ method: 'GET', path: '/invoices/inv-1002', principal: 'p-mem-1' }).status).toBe(200);
  });
});

describe('mock server — skip-authentication flaw', () => {
  it('lets an anonymous caller list a collection with no role check and no ownership scope', () => {
    // list-invoices is owner-scoped and role-restricted; an anonymous caller has neither owner nor role.
    const server = createMockServer(ledgerly(), [flaw('list-invoices', 'skip-authentication')]);
    const res = server.handle({ method: 'GET', path: '/invoices', principal: ANONYMOUS_PRINCIPAL });
    expect(res.status).toBe(200);
    const ids = (res.body?.items ?? []).map((i) => i.id).sort();
    expect(ids).toEqual(['inv-0001', 'inv-1001', 'inv-1002', 'inv-2001']);
  });

  it('still strips sensitive fields for the anonymous caller unless return-sensitive-fields is also seeded', () => {
    const contract = withEndpoints(ledgerly(), LIST_USERS);
    const stripped = createMockServer(contract, [flaw('list-users', 'skip-authentication')])
      .handle({ method: 'GET', path: '/users', principal: ANONYMOUS_PRINCIPAL });
    expect(stripped.status).toBe(200);
    expect(stripped.body?.items).toHaveLength(4);
    for (const item of stripped.body?.items ?? []) {
      expect(item.fields).not.toHaveProperty('passwordHash');
      expect(item.fields).toHaveProperty('displayName');
    }
    const leaking = createMockServer(contract, [flaw('list-users', 'skip-authentication'), flaw('list-users', 'return-sensitive-fields')])
      .handle({ method: 'GET', path: '/users', principal: ANONYMOUS_PRINCIPAL });
    expect(leaking.status).toBe(200);
    for (const item of leaking.body?.items ?? []) expect(item.fields).toHaveProperty('passwordHash');
  });

  it('lets an anonymous caller read any single record, and still answers 404 for a missing one', () => {
    const server = createMockServer(ledgerly(), [flaw('get-invoice', 'skip-authentication')]);
    const res = server.handle({ method: 'GET', path: '/invoices/inv-2001', principal: ANONYMOUS_PRINCIPAL });
    expect(res.status).toBe(200);
    expect(res.body?.id).toBe('inv-2001');
    expect(server.handle({ method: 'GET', path: '/invoices/inv-9999', principal: ANONYMOUS_PRINCIPAL }).status).toBe(404);
  });

  it('records anonymous creations with owner "anonymous" and an empty tenant while still filtering writable fields', () => {
    const server = createMockServer(withEndpoints(ledgerly(), CREATE_INVOICE), [flaw('create-invoice', 'skip-authentication')]);
    const res = server.handle({ method: 'POST', path: '/invoices', principal: ANONYMOUS_PRINCIPAL, body: { memo: 'Walk-in', status: 'paid' } });
    expect(res.status).toBe(201);
    const id = res.body?.id;
    expect(typeof id).toBe('string');
    const row = server.inspect('invoices', id!);
    expect(row).toMatchObject({ owner: 'anonymous', tenant: '', fields: { memo: 'Walk-in' } });
    expect(row?.fields).not.toHaveProperty('status');
  });

  it('does not relax role or ownership checks for authenticated callers', () => {
    const invoices = createMockServer(ledgerly(), [flaw('get-invoice', 'skip-authentication')]);
    expect(invoices.handle({ method: 'GET', path: '/invoices/inv-1002', principal: 'p-mem-1' }).status).toBe(403);
    const users = createMockServer(ledgerly(), [flaw('delete-user', 'skip-authentication')]);
    expect(users.handle({ method: 'DELETE', path: '/users/p-admin-1', principal: 'p-mem-1' }).status).toBe(403);
    expect(users.handle({ method: 'DELETE', path: '/users/p-admin-1', principal: ANONYMOUS_PRINCIPAL }).status).toBe(204);
    expect(users.inspect('users', 'p-admin-1')).toBeUndefined();
  });

  it('still answers 403 to the anonymous caller when deny-everything is seeded on the same endpoint', () => {
    const server = createMockServer(ledgerly(), [flaw('list-invoices', 'skip-authentication'), flaw('list-invoices', 'deny-everything')]);
    expect(server.handle({ method: 'GET', path: '/invoices', principal: ANONYMOUS_PRINCIPAL }).status).toBe(403);
  });

  it('rejects a malformed body from the anonymous caller with 400', () => {
    const server = createMockServer(withEndpoints(ledgerly(), CREATE_INVOICE), [flaw('create-invoice', 'skip-authentication')]);
    const res = server.handle({ method: 'POST', path: '/invoices', principal: ANONYMOUS_PRINCIPAL, body: { 'bad key!': 'x' } });
    expect(res.status).toBe(400);
  });
});

describe('mock server — Helpdesk fixture', () => {
  const helpdeskContract = (): Contract => {
    const result = validateContract(helpdesk);
    if (!result.ok) throw new Error(result.errors.join('\n'));
    return result.contract;
  };

  it('exposes the literal export route (registered after its {id} sibling) to anonymous callers only on the vulnerable build', () => {
    const fixed = createMockServer(helpdeskContract(), []);
    expect(fixed.handle({ method: 'GET', path: '/tickets/export', principal: ANONYMOUS_PRINCIPAL })).toEqual({ status: 401, body: { error: 'unauthenticated' } });
    const vulnerable = createMockServer(helpdeskContract(), helpdesk.builds.vulnerable.flaws as Flaw[]);
    const res = vulnerable.handle({ method: 'GET', path: '/tickets/export', principal: ANONYMOUS_PRINCIPAL });
    expect(res.status).toBe(200);
    expect(res.body?.items).toHaveLength(5);
    // internalNotes is sensitive on the tickets resource and the export route has no return-sensitive-fields flaw.
    for (const item of res.body?.items ?? []) expect(item.fields).not.toHaveProperty('internalNotes');
    // The {id} sibling still authenticates, the export route still enforces its admin-only role for real callers,
    // and an unsupported method on a known template is 405.
    expect(vulnerable.handle({ method: 'GET', path: '/tickets/tkt-1001', principal: ANONYMOUS_PRINCIPAL }).status).toBe(401);
    expect(vulnerable.handle({ method: 'GET', path: '/tickets/export', principal: 'p-cust-1' }).status).toBe(403);
    expect(vulnerable.handle({ method: 'PUT', path: '/tickets/tkt-1001', principal: 'p-admin-1' }).status).toBe(405);
  });
});
