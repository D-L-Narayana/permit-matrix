import type { Contract, ContractWarning, Endpoint, FlawKind, RecordRow } from './types';

/**
 * Contract health codes. Lint is advisory: it never blocks validation or a run. Each rule flags either a
 * likely authoring mistake or a coverage hole (something the generated suite could never exercise).
 */
export type LintCode =
  | 'unused-role'
  | 'principal-without-records'
  | 'single-tenant'
  | 'field-not-on-records'
  | 'writable-on-read-endpoint'
  | 'sensitive-on-write-endpoint'
  | 'list-item-scope-mismatch'
  | 'record-tenant-mismatch'
  | 'no-negative-cases'
  | 'noop-flaw';

/** A lint warning: the shared `ContractWarning` shape with the code narrowed to the known rule set. */
export interface LintWarning extends ContractWarning {
  code: LintCode;
}

/**
 * Severity policy: `warn` marks a probable mistake or a hole that silently weakens a run (a flaw the suite
 * cannot catch, a matrix column with no cases); `info` marks a limitation worth knowing that may be intended.
 */
export const LINT_RULES: Record<LintCode, { severity: 'info' | 'warn'; summary: string }> = {
  'unused-role': { severity: 'warn', summary: 'A role that no principal carries; its matrix column cannot contain any case.' },
  'principal-without-records': { severity: 'warn', summary: 'A principal owns nothing in a resource whose own-scoped {id} endpoint it may call.' },
  'single-tenant': { severity: 'info', summary: 'Every principal shares one tenant, so cross-tenant cases cannot be generated.' },
  'field-not-on-records': { severity: 'warn', summary: 'A writable or sensitive field that appears on no record of the resource.' },
  'writable-on-read-endpoint': { severity: 'warn', summary: 'writableFields declared on a GET or DELETE endpoint, which carries no request body.' },
  'sensitive-on-write-endpoint': { severity: 'info', summary: 'sensitiveFields declared on a write endpoint; read probes are generated only for GET.' },
  'list-item-scope-mismatch': { severity: 'warn', summary: 'A GET collection and its GET {id} route on the same resource disagree on ownership.' },
  'record-tenant-mismatch': { severity: 'warn', summary: 'A record whose tenant differs from the tenant of the principal that owns it.' },
  'no-negative-cases': { severity: 'info', summary: 'Every role allowed, ownership "any" and no field probe: only the anonymous row can ever fail.' },
  'noop-flaw': { severity: 'warn', summary: 'A seeded flaw that no generated case could observe.' },
};

const quote = (value: string): string => `"${value}"`;
const list = (values: readonly string[]): string => `[${values.join(', ')}]`;
const hasIdParam = (endpoint: Endpoint): boolean => endpoint.path.includes('{id}');
const isWriteMethod = (endpoint: Endpoint): boolean => endpoint.method === 'POST' || endpoint.method === 'PUT' || endpoint.method === 'PATCH';

/** Every field name seen on the records of a resource, in first-seen order. */
function fieldNames(records: readonly RecordRow[]): string[] {
  const seen = new Set<string>();
  for (const record of records) for (const key of Object.keys(record.fields)) seen.add(key);
  return [...seen];
}

/**
 * Whether the generator can produce at least one property probe for the endpoint: a sensitive-read probe
 * needs a GET with `sensitiveFields`; a mass-assignment probe needs a write method with `writableFields`
 * that leaves at least one known record field non-writable.
 */
function hasPropertyProbe(endpoint: Endpoint, resourceFields: readonly string[]): boolean {
  if (endpoint.method === 'GET') return (endpoint.sensitiveFields?.length ?? 0) > 0;
  if (!isWriteMethod(endpoint) || !endpoint.writableFields) return false;
  const writable = new Set(endpoint.writableFields);
  return resourceFields.some((field) => !writable.has(field));
}

/** Explains why a seeded flaw could never flip a verdict, or returns null when it can. */
function noopReason(kind: FlawKind, endpoint: Endpoint, resourceFields: readonly string[], resourceSensitive: readonly string[], allowsEveryRole: boolean): string | null {
  switch (kind) {
    case 'skip-ownership-check':
      if (endpoint.access.ownership === 'any') return 'the endpoint’s ownership is already "any", so there is no scope check to skip.';
      if (endpoint.method === 'POST' && !hasIdParam(endpoint)) return 'creating a record through a POST collection endpoint performs no ownership check, so there is nothing to skip.';
      return null;
    case 'accept-all-fields':
      if (!isWriteMethod(endpoint)) return `${endpoint.method} requests carry no body, so there are no fields to accept.`;
      if (!endpoint.writableFields) return 'the endpoint declares no writableFields, so no mass-assignment probe is generated.';
      if (!hasPropertyProbe(endpoint, resourceFields)) return `writableFields already cover every field found on the records of ${quote(endpoint.resource)}, so no mass-assignment probe is generated.`;
      return null;
    case 'return-sensitive-fields':
      if (endpoint.method !== 'GET') return `${endpoint.method} responses are never checked for sensitive fields; read probes exist only for GET endpoints.`;
      if (endpoint.sensitiveFields?.length) return null;
      return resourceSensitive.length
        ? `the endpoint declares no sensitiveFields of its own (resource ${quote(endpoint.resource)} marks ${list(resourceSensitive)} elsewhere), so no read probe is generated for it.`
        : `no endpoint of resource ${quote(endpoint.resource)} declares sensitiveFields, so no read probe can observe a leak.`;
    case 'skip-role-check':
      return allowsEveryRole ? 'every role is already allowed, so there is no role check to skip.' : null;
    default:
      // deny-everything and skip-authentication always flip at least one verdict.
      return null;
  }
}

const NUMERIC = /^\d+$/;
const compareStrings = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Natural order for document paths, so `records[2]` sorts before `records[10]` and a parent before its children. */
function comparePaths(a: string, b: string): number {
  if (a === b) return 0;
  const left = a.split(/(\d+)/);
  const right = b.split(/(\d+)/);
  const shared = Math.min(left.length, right.length);
  for (let i = 0; i < shared; i++) {
    const l = left[i];
    const r = right[i];
    if (l === r) continue;
    if (NUMERIC.test(l) && NUMERIC.test(r) && Number(l) !== Number(r)) return Number(l) - Number(r);
    return compareStrings(l, r);
  }
  return left.length - right.length;
}

const compareWarnings = (a: LintWarning, b: LintWarning): number =>
  comparePaths(a.path, b.path) || compareStrings(a.code, b.code) || compareStrings(a.message, b.message);

/**
 * Lints an already-valid contract for policy inconsistencies and coverage holes. Output is sorted by path
 * (indices in contract order), then code, then message, so the same contract always yields the same list.
 */
export function lintContract(contract: Contract): LintWarning[] {
  const warnings: LintWarning[] = [];
  const emit = (code: LintCode, path: string, message: string): void => {
    warnings.push({ code, severity: LINT_RULES[code].severity, path, message });
  };

  const roleIds = contract.roles.map((role) => role.id);
  const principalById = new Map(contract.principals.map((principal) => [principal.id, principal]));
  const endpointById = new Map(contract.endpoints.map((endpoint) => [endpoint.id, endpoint]));
  const fieldsByResource = new Map(contract.resources.map((resource) => [resource.id, fieldNames(resource.records)]));
  const sensitiveByResource = new Map<string, string[]>();
  for (const endpoint of contract.endpoints) {
    const seen = sensitiveByResource.get(endpoint.resource) ?? [];
    for (const field of endpoint.sensitiveFields ?? []) if (!seen.includes(field)) seen.push(field);
    sensitiveByResource.set(endpoint.resource, seen);
  }
  const allowsEveryRole = (endpoint: Endpoint): boolean => roleIds.every((id) => endpoint.access.roles.includes(id));

  const rolesInUse = new Set(contract.principals.map((principal) => principal.role));
  contract.roles.forEach((role, i) => {
    if (rolesInUse.has(role.id)) return;
    emit('unused-role', `roles[${i}]`, `Role ${quote(role.id)} (${role.label}) is carried by no principal, so its matrix column can never contain a case and any endpoint that allows it is never exercised as that role. Add a principal with this role or remove the role.`);
  });

  const tenants = [...new Set(contract.principals.map((principal) => principal.tenant))];
  if (tenants.length === 1) {
    emit('single-tenant', 'principals', `Every principal (${contract.principals.length}) belongs to tenant ${quote(tenants[0])}, so no cross-tenant case can be generated and "same-tenant" rules are never tested across a boundary. Add a principal, and records it owns, in a second tenant.`);
  }

  contract.resources.forEach((resource, ri) => {
    resource.records.forEach((record, j) => {
      const owner = principalById.get(record.owner);
      if (!owner || owner.tenant === record.tenant) return;
      emit('record-tenant-mismatch', `resources[${ri}].records[${j}].tenant`, `Record ${quote(record.id)} is filed under tenant ${quote(record.tenant)} but its owner ${quote(owner.id)} belongs to ${quote(owner.tenant)}, so it is both an own and a cross-tenant target and the expectations of own- and tenant-scoped endpoints contradict each other. Set the record’s tenant to the owner’s tenant or change the owner.`);
    });

    // Only an own-scoped {id} route needs an own record per caller; an own-scoped listing may legitimately be empty.
    const ownScoped = contract.endpoints.filter((endpoint) => endpoint.resource === resource.id && endpoint.access.ownership === 'own' && hasIdParam(endpoint));
    if (ownScoped.length === 0) return;
    const owners = new Set(resource.records.map((record) => record.owner));
    for (const principal of contract.principals) {
      if (owners.has(principal.id)) continue;
      const callable = ownScoped.filter((endpoint) => endpoint.access.roles.includes(principal.role));
      if (callable.length === 0) continue;
      const plural = callable.length > 1;
      emit('principal-without-records', `resources[${ri}].records`, `Principal ${quote(principal.id)} (${principal.role}) owns no record in resource ${quote(resource.id)}, so the own-scoped ${plural ? 'endpoints' : 'endpoint'} ${callable.map((endpoint) => quote(endpoint.id)).join(', ')} ${plural ? 'get' : 'gets'} no own-target case for it and its allowed path is never exercised. Add a record owned by ${quote(principal.id)} or change the ownership rule.`);
    }
  });

  contract.endpoints.forEach((endpoint, i) => {
    const base = `endpoints[${i}]`;
    const resourceFields = fieldsByResource.get(endpoint.resource) ?? [];
    const known = resourceFields.length ? `(known fields: ${list(resourceFields)})` : '(the resource has no records)';

    for (const key of ['writableFields', 'sensitiveFields'] as const) {
      (endpoint[key] ?? []).forEach((field, j) => {
        if (resourceFields.includes(field)) return;
        emit('field-not-on-records', `${base}.${key}[${j}]`, `Field ${quote(field)} in ${key} of ${quote(endpoint.id)} appears on no record of resource ${quote(endpoint.resource)} ${known}; it is probably misspelled, so no probe can target it and the field it was meant to name is tested with the wrong expectation. Fix the spelling or add the field to the records.`);
      });
    }

    if (endpoint.writableFields && !isWriteMethod(endpoint)) {
      emit('writable-on-read-endpoint', `${base}.writableFields`, `${quote(endpoint.id)} is a ${endpoint.method} endpoint, which carries no request body, so writableFields ${list(endpoint.writableFields)} produces no mass-assignment probe. Move the list to the PATCH, PUT or POST endpoint of ${quote(endpoint.resource)} or remove it.`);
    }
    if (endpoint.sensitiveFields && endpoint.method !== 'GET') {
      emit('sensitive-on-write-endpoint', `${base}.sensitiveFields`, `${quote(endpoint.id)} is a ${endpoint.method} endpoint; read probes for sensitiveFields ${list(endpoint.sensitiveFields)} are generated only from GET endpoints, so this list is not tested here. Declare the same fields on the GET endpoint(s) of ${quote(endpoint.resource)}.`);
    }

    // Pair a collection GET only with the item GET at exactly `<path>/{id}`; literal siblings such as /tickets/export are separate operations.
    if (endpoint.method === 'GET' && !hasIdParam(endpoint)) {
      const item = contract.endpoints.find((candidate) => candidate.method === 'GET' && candidate.resource === endpoint.resource && candidate.path === `${endpoint.path}/{id}`);
      if (item && item.access.ownership !== endpoint.access.ownership) {
        emit('list-item-scope-mismatch', `${base}.access.ownership`, `Collection ${quote(endpoint.id)} (GET ${endpoint.path}) is scoped ${quote(endpoint.access.ownership)} while item ${quote(item.id)} (GET ${item.path}) is scoped ${quote(item.access.ownership)}; the listing can enumerate records the item route denies, or hide records it allows, and no single-route case can reveal the contradiction. Give both routes the same ownership.`);
      }
    }

    if (allowsEveryRole(endpoint) && endpoint.access.ownership === 'any' && !hasPropertyProbe(endpoint, resourceFields)) {
      emit('no-negative-cases', `${base}.access`, `${quote(endpoint.id)} allows every role with ownership "any" and has no property probe, so apart from the anonymous row every generated case expects success and no bypass could ever be detected here. If this openness is unintended, narrow the roles or the scope, or declare writableFields/sensitiveFields.`);
    }
  });

  for (const [key, build] of Object.entries(contract.builds)) {
    build.flaws.forEach((flaw, j) => {
      const endpoint = endpointById.get(flaw.endpoint);
      if (!endpoint) return;
      const reason = noopReason(flaw.kind, endpoint, fieldsByResource.get(endpoint.resource) ?? [], sensitiveByResource.get(endpoint.resource) ?? [], allowsEveryRole(endpoint));
      if (!reason) return;
      emit('noop-flaw', `builds.${key}.flaws[${j}]`, `Flaw ${quote(flaw.kind)} on ${quote(endpoint.id)} has no observable effect: ${reason} Remove the flaw or change the endpoint so that a case exists which it would flip.`);
    });
  }

  return warnings.sort(compareWarnings);
}
