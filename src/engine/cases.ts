import { ANONYMOUS_PRINCIPAL, ANONYMOUS_ROLE } from './types';
import type { CaseCategory, Contract, Endpoint, Expectation, FieldValue, Principal, RecordRow, Resource, TargetKind, TestCase } from './types';

export const hasPathParam = (endpoint: Endpoint): boolean => endpoint.path.includes('{id}');

/** Rationale on every anonymous case: authentication precedes policy, so the expectation never depends on the endpoint. */
export const ANONYMOUS_RATIONALE = 'No credentials are presented; the endpoint must reject the request (401) before any policy is evaluated.';

export interface GenerateOptions {
  /** Emit the anonymous (no-credentials) authentication row for every endpoint. */
  anonymous?: boolean;
}

export function probeValue(original: FieldValue | undefined): FieldValue {
  if (typeof original === 'number') return original + 1;
  if (typeof original === 'boolean') return !original;
  if (typeof original === 'string') return `${original}-tampered`;
  return 'tampered';
}

/** Union of field names across a resource's records, in first-seen order (records may be heterogeneous). */
export function resourceFieldNames(resource: Resource): string[] {
  const seen = new Set<string>();
  const names: string[] = [];
  for (const record of resource.records) {
    for (const name of Object.keys(record.fields)) {
      if (seen.has(name)) continue;
      seen.add(name);
      names.push(name);
    }
  }
  return names;
}

function pickTargets(records: RecordRow[], principal: Principal): Partial<Record<TargetKind, RecordRow>> {
  const own = records.find((r) => r.owner === principal.id);
  const peer = records.find((r) => r.owner !== principal.id && r.tenant === principal.tenant);
  const cross = records.find((r) => r.tenant !== principal.tenant);
  return { ...(own ? { own } : {}), ...(peer ? { peer } : {}), ...(cross ? { 'cross-tenant': cross } : {}) };
}

function expectation(endpoint: Endpoint, principal: Principal, target: RecordRow | undefined): { expected: Expectation; category: CaseCategory; rationale: string } {
  if (!endpoint.access.roles.includes(principal.role)) {
    return { expected: 'deny', category: 'function', rationale: `Role "${principal.role}" is not in the endpoint's allowed roles [${endpoint.access.roles.join(', ')}].` };
  }
  if (!target || endpoint.access.ownership === 'any') {
    return { expected: 'allow', category: 'object', rationale: 'Role is allowed and the endpoint is not object-scoped.' };
  }
  if (endpoint.access.ownership === 'own') {
    const ok = target.owner === principal.id;
    return { expected: ok ? 'allow' : 'deny', category: 'object', rationale: ok ? 'Caller owns the target record.' : `Record is owned by ${target.owner}, not the caller; ownership rule is "own".` };
  }
  const ok = target.tenant === principal.tenant;
  return { expected: ok ? 'allow' : 'deny', category: 'object', rationale: ok ? 'Target is inside the caller’s tenant.' : `Record belongs to tenant ${target.tenant}; ownership rule is "same-tenant".` };
}

/** POST on a collection creates a record: the base case checks the role, the probes check that only writable fields bind. */
function createCases(endpoint: Endpoint, principal: Principal, resource: Resource | undefined): TestCase[] {
  const e = expectation(endpoint, principal, undefined);
  const allowed = e.expected === 'allow';
  const cases: TestCase[] = [{
    id: `${endpoint.id}|${principal.id}|create`,
    endpoint: endpoint.id, principal: principal.id, role: principal.role,
    targetKind: 'create', category: allowed ? 'object' : 'function', expected: e.expected,
    rationale: allowed ? 'Role is allowed to create; the server must bind only writable fields.' : e.rationale,
  }];
  if (!allowed || !endpoint.writableFields || !resource) return cases;
  const writable = new Set(endpoint.writableFields);
  for (const field of resourceFieldNames(resource).filter((f) => !writable.has(f))) {
    cases.push({
      id: `${endpoint.id}|${principal.id}|create|write:${field}`,
      endpoint: endpoint.id, principal: principal.id, role: principal.role,
      targetKind: 'create', category: 'property', expected: 'allow', probeField: field,
      rationale: `"${field}" is not in writableFields [${endpoint.writableFields.join(', ')}]; a create must not accept it.`,
    });
  }
  return cases;
}

/** Every listing case plus, where the caller may list, one exposure probe per sensitive field (items must be stripped too). */
function collectionCases(endpoint: Endpoint, principal: Principal): TestCase[] {
  const e = expectation(endpoint, principal, undefined);
  const cases: TestCase[] = [{
    id: `${endpoint.id}|${principal.id}|collection`,
    endpoint: endpoint.id, principal: principal.id, role: principal.role,
    targetKind: 'collection', category: e.category === 'function' ? 'function' : 'object',
    expected: e.expected, rationale: e.rationale,
  }];
  if (e.expected !== 'allow' || endpoint.method !== 'GET' || !endpoint.sensitiveFields) return cases;
  for (const field of endpoint.sensitiveFields) {
    cases.push({
      id: `${endpoint.id}|${principal.id}|collection|read:${field}`,
      endpoint: endpoint.id, principal: principal.id, role: principal.role,
      targetKind: 'collection', category: 'property', expected: 'allow', probeField: field,
      rationale: `"${field}" is marked sensitive; it must never appear in any listed item.`,
    });
  }
  return cases;
}

/** The no-credentials row: collection endpoints are hit directly, item endpoints via the resource's first record. */
function anonymousCase(endpoint: Endpoint, records: RecordRow[]): TestCase | undefined {
  const base = { endpoint: endpoint.id, principal: ANONYMOUS_PRINCIPAL, role: ANONYMOUS_ROLE.id, category: 'authentication' as const, expected: 'deny' as const, rationale: ANONYMOUS_RATIONALE };
  if (!hasPathParam(endpoint)) return { id: `${endpoint.id}|${ANONYMOUS_PRINCIPAL}|collection`, ...base, targetKind: 'collection' };
  const target = records[0];
  if (!target) return undefined;
  return { id: `${endpoint.id}|${ANONYMOUS_PRINCIPAL}|cross-tenant`, ...base, targetKind: 'cross-tenant', targetRecord: target.id };
}

/**
 * Generates the full role × endpoint × object matrix plus property-level probes.
 * Output order is stable (contract order), so two runs over the same contract are identical.
 */
export function generateCases(contract: Contract, options: GenerateOptions = {}): TestCase[] {
  // The no-credentials row is part of the standard matrix; callers opt out explicitly (e.g. to compare with older runs).
  const anonymous = options.anonymous !== false;
  const cases: TestCase[] = [];
  const byResource = new Map(contract.resources.map((r) => [r.id, r]));

  for (const endpoint of contract.endpoints) {
    const resource = byResource.get(endpoint.resource);
    const records = resource?.records ?? [];
    for (const principal of contract.principals) {
      if (!hasPathParam(endpoint)) {
        for (const c of endpoint.method === 'POST' ? createCases(endpoint, principal, resource) : collectionCases(endpoint, principal)) cases.push(c);
        continue;
      }
      const targets = pickTargets(records, principal);
      for (const kind of ['own', 'peer', 'cross-tenant'] as const) {
        const target = targets[kind];
        if (!target) continue;
        const e = expectation(endpoint, principal, target);
        cases.push({
          id: `${endpoint.id}|${principal.id}|${kind}`,
          endpoint: endpoint.id, principal: principal.id, role: principal.role,
          targetKind: kind, targetRecord: target.id, category: e.category, expected: e.expected, rationale: e.rationale,
        });

        // Property-level probes only make sense where the base call is expected to succeed.
        if (e.expected !== 'allow') continue;
        if ((endpoint.method === 'PATCH' || endpoint.method === 'PUT') && endpoint.writableFields) {
          const writable = new Set(endpoint.writableFields);
          for (const field of Object.keys(target.fields).filter((f) => !writable.has(f))) {
            cases.push({
              id: `${endpoint.id}|${principal.id}|${kind}|write:${field}`,
              endpoint: endpoint.id, principal: principal.id, role: principal.role,
              targetKind: kind, targetRecord: target.id, category: 'property', expected: 'allow', probeField: field,
              rationale: `"${field}" is not in writableFields [${endpoint.writableFields.join(', ')}]; a write must leave it unchanged.`,
            });
          }
        }
        if (endpoint.method === 'GET' && endpoint.sensitiveFields) {
          for (const field of endpoint.sensitiveFields) {
            cases.push({
              id: `${endpoint.id}|${principal.id}|${kind}|read:${field}`,
              endpoint: endpoint.id, principal: principal.id, role: principal.role,
              targetKind: kind, targetRecord: target.id, category: 'property', expected: 'allow', probeField: field,
              rationale: `"${field}" is marked sensitive; it must never appear in the response body.`,
            });
          }
        }
      }
    }
    // Emitted last so every endpoint's cases stay contiguous and all pre-existing ids keep their relative order.
    if (anonymous) {
      const anon = anonymousCase(endpoint, records);
      if (anon) cases.push(anon);
    }
  }
  return cases;
}
