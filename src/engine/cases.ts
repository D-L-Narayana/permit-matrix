import type { CaseCategory, Contract, Endpoint, Expectation, FieldValue, Principal, RecordRow, TargetKind, TestCase } from './types';

export const hasPathParam = (endpoint: Endpoint): boolean => endpoint.path.includes('{id}');

export function probeValue(original: FieldValue | undefined): FieldValue {
  if (typeof original === 'number') return original + 1;
  if (typeof original === 'boolean') return !original;
  if (typeof original === 'string') return `${original}-tampered`;
  return 'tampered';
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
  return { expected: ok ? 'allow' : 'deny', category: 'object', rationale: ok ? 'Target is inside the caller\u2019s tenant.' : `Record belongs to tenant ${target.tenant}; ownership rule is "same-tenant".` };
}

/**
 * Generates the full role × endpoint × object matrix plus property-level probes.
 * Output order is stable (contract order), so two runs over the same contract are identical.
 */
export function generateCases(contract: Contract): TestCase[] {
  const cases: TestCase[] = [];
  const byResource = new Map(contract.resources.map((r) => [r.id, r.records]));

  for (const endpoint of contract.endpoints) {
    const records = byResource.get(endpoint.resource) ?? [];
    for (const principal of contract.principals) {
      if (!hasPathParam(endpoint)) {
        const e = expectation(endpoint, principal, undefined);
        cases.push({
          id: `${endpoint.id}|${principal.id}|collection`,
          endpoint: endpoint.id, principal: principal.id, role: principal.role,
          targetKind: 'collection', category: e.category === 'function' ? 'function' : 'object',
          expected: e.expected, rationale: e.rationale,
        });
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
  }
  return cases;
}
