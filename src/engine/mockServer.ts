import { ANONYMOUS_PRINCIPAL } from './types';
import type { Contract, Endpoint, FieldValue, Flaw, FlawKind, MockRequest, MockResponse, Principal, RecordRow } from './types';

const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/i;

export interface MockServer {
  handle(request: MockRequest): MockResponse;
  /** Test-oracle hook: read server-side state directly, the way an integration test would query the database. */
  inspect(resource: string, recordId: string): RecordRow | undefined;
  flaws: Flaw[];
}

function routeRegex(path: string): RegExp {
  const escaped = path.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{id\}/g, '([a-z0-9._-]+)');
  return new RegExp(`^${escaped}$`, 'i');
}

function validBody(body: unknown): body is Record<string, FieldValue> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;
  const entries = Object.entries(body as Record<string, unknown>);
  if (entries.length > 24) return false;
  return entries.every(([k, v]) => ID.test(k) && (v === null || ['string', 'number', 'boolean'].includes(typeof v)) && (typeof v !== 'string' || v.length <= 200));
}

/**
 * A deterministic, in-memory implementation of the contract. The "fixed" build enforces the
 * contract exactly; `flaws` switch off individual checks per endpoint so that the tester has
 * something real to catch. Nothing here performs network I/O.
 *
 * Requests are routed before they are authenticated: an unknown path is 404 and a known path with the
 * wrong method is 405 for every caller, and whether a request may proceed without credentials is a
 * property of the matched endpoint (the `skip-authentication` flaw). When that flaw lets a request
 * through, the handler runs with no subject at all — no role to check and nothing to scope records
 * by — which is exactly the shape of a route that is missing its authentication middleware.
 */
export function createMockServer(contract: Contract, flaws: Flaw[]): MockServer {
  const state = new Map<string, Map<string, RecordRow>>();
  for (const resource of contract.resources) {
    state.set(resource.id, new Map(resource.records.map((r) => [r.id, { ...r, fields: { ...r.fields } }])));
  }
  const principals = new Map(contract.principals.map((p) => [p.id, p]));
  // Literal routes are tried before parameterised ones (fewest `{id}` segments first), so `/invoices/export`
  // is never swallowed by `/invoices/{id}` regardless of declaration order.
  const routes = contract.endpoints
    .map((e) => ({ endpoint: e, regex: routeRegex(e.path), params: (e.path.match(/\{id\}/g) ?? []).length }))
    .sort((a, b) => a.params - b.params);
  const sensitiveByResource = new Map<string, Set<string>>();
  for (const e of contract.endpoints) {
    const set = sensitiveByResource.get(e.resource) ?? new Set<string>();
    for (const f of e.sensitiveFields ?? []) set.add(f);
    sensitiveByResource.set(e.resource, set);
  }
  const flawSet = new Set(flaws.map((f) => `${f.endpoint}:${f.kind}`));
  const has = (endpoint: Endpoint, kind: FlawKind) => flawSet.has(`${endpoint.id}:${kind}`);
  let counter = 0;

  const present = (endpoint: Endpoint, record: RecordRow): RecordRow => {
    if (has(endpoint, 'return-sensitive-fields')) return { ...record, fields: { ...record.fields } };
    const strip = sensitiveByResource.get(endpoint.resource) ?? new Set<string>();
    const fields = Object.fromEntries(Object.entries(record.fields).filter(([k]) => !strip.has(k)));
    return { ...record, fields };
  };

  // `principal` is undefined only when `skip-authentication` let an unauthenticated request through; with no
  // subject there is nothing to compare owner or tenant against, so the handler behaves as if ownership were `any`.
  const inScope = (endpoint: Endpoint, record: RecordRow, principal: Principal | undefined): boolean => {
    if (!principal) return true;
    if (has(endpoint, 'skip-ownership-check')) return true;
    if (endpoint.access.ownership === 'any') return true;
    if (endpoint.access.ownership === 'own') return record.owner === principal.id;
    return record.tenant === principal.tenant;
  };

  return {
    flaws,
    inspect(resource, recordId) {
      const row = state.get(resource)?.get(recordId);
      return row ? { ...row, fields: { ...row.fields } } : undefined;
    },
    handle(request) {
      const candidates = routes.filter((r) => r.regex.test(request.path));
      if (candidates.length === 0) return { status: 404, body: { error: 'no such route' } };
      const route = candidates.find((r) => r.endpoint.method === request.method);
      if (!route) return { status: 405, body: { error: 'method not allowed' } };
      const { endpoint } = route;
      const principal = principals.get(request.principal);
      if (!principal && !has(endpoint, 'skip-authentication')) return { status: 401, body: { error: 'unauthenticated' } };
      if (has(endpoint, 'deny-everything')) return { status: 403, body: { error: 'forbidden' } };
      if (principal && !has(endpoint, 'skip-role-check') && !endpoint.access.roles.includes(principal.role)) {
        return { status: 403, body: { error: 'forbidden: role' } };
      }
      if (request.body !== undefined && !validBody(request.body)) return { status: 400, body: { error: 'malformed body' } };
      const table = state.get(endpoint.resource)!;
      const match = request.path.match(route.regex);
      const recordId = match?.[1];

      if (recordId === undefined) {
        if (request.method === 'GET') {
          const items = [...table.values()].filter((r) => inScope(endpoint, r, principal)).map((r) => present(endpoint, r));
          return { status: 200, body: { items } };
        }
        if (request.method === 'POST') {
          counter += 1;
          const allowed = has(endpoint, 'accept-all-fields') ? null : new Set(endpoint.writableFields ?? []);
          const fields = Object.fromEntries(Object.entries(request.body ?? {}).filter(([k]) => !allowed || allowed.has(k)));
          const row: RecordRow = {
            id: `${endpoint.resource}-new-${counter}`,
            owner: principal?.id ?? ANONYMOUS_PRINCIPAL,
            tenant: principal?.tenant ?? '',
            fields,
          };
          table.set(row.id, row);
          return { status: 201, body: { id: row.id, fields: present(endpoint, row).fields } };
        }
        return { status: 405, body: { error: 'method not allowed on collection' } };
      }

      const record = table.get(recordId);
      if (!record) return { status: 404, body: { error: 'not found' } };
      if (!inScope(endpoint, record, principal)) return { status: 403, body: { error: 'forbidden: object' } };

      switch (request.method) {
        case 'GET': {
          const shown = present(endpoint, record);
          return { status: 200, body: { id: shown.id, fields: shown.fields } };
        }
        case 'PATCH':
        case 'PUT': {
          const allowed = has(endpoint, 'accept-all-fields') ? null : new Set(endpoint.writableFields ?? []);
          for (const [k, v] of Object.entries(request.body ?? {})) {
            if (!allowed || allowed.has(k)) record.fields[k] = v;
          }
          const shown = present(endpoint, record);
          return { status: 200, body: { id: shown.id, fields: shown.fields } };
        }
        case 'DELETE':
          table.delete(recordId);
          return { status: 204 };
        default:
          return { status: 405, body: { error: 'method not allowed on item' } };
      }
    },
  };
}
