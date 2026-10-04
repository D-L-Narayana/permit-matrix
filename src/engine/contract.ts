import type { Contract, Endpoint, Flaw, FlawKind, Method, Ownership, Principal, RecordRow, Resource, Role, ValidationIssue } from './types';
import { ANONYMOUS_PRINCIPAL, ANONYMOUS_ROLE } from './types';

export const LIMITS = {
  maxBytes: 64 * 1024,
  maxEndpoints: 40,
  maxRoles: 8,
  maxPrincipals: 24,
  maxRecordsPerResource: 100,
  maxResources: 12,
  maxFieldsPerRecord: 24,
  maxStringLength: 200,
  maxDepth: 6,
  maxServers: 4,
  maxBuilds: 8,
  maxFlawsPerBuild: 40,
  /** Hard ceiling on any array encountered while validating; longer lists are rejected without being walked. */
  maxListLength: 1000,
} as const;

const METHODS: readonly Method[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
const OWNERSHIPS: readonly Ownership[] = ['any', 'own', 'same-tenant'];
/** Every flaw a build may seed. Frozen so downstream modules (linter, schema) can mirror it safely. */
export const FLAW_KINDS: readonly FlawKind[] = Object.freeze<FlawKind[]>([
  'skip-ownership-check', 'skip-role-check', 'accept-all-fields', 'return-sensitive-fields', 'deny-everything', 'skip-authentication',
]);
/** Ids claimed by the synthetic unauthenticated caller; matched case-insensitively so `Anonymous` cannot impersonate it. */
export const RESERVED_IDS: readonly string[] = Object.freeze([...new Set([ANONYMOUS_PRINCIPAL, ANONYMOUS_ROLE.id])]);
/** Keys that collide with Object.prototype when records, field lists or builds are read as plain objects. */
export const RESERVED_FIELD_NAMES: readonly string[] = Object.freeze(['__proto__', 'constructor', 'prototype']);
const RESERVED_ID_HINT = 'is reserved for the anonymous (unauthenticated) caller.';
const isReservedId = (id: string): boolean => RESERVED_IDS.includes(id.toLowerCase());
const isReservedName = (name: string): boolean => RESERVED_FIELD_NAMES.includes(name);

const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const PATH = /^\/[a-z0-9{}/_-]{0,120}$/i;
const SEGMENT = /^[a-z0-9_-]+$/i;
const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;

/** JSON-path-like addresses: `parent.key` for identifier-like keys, `parent["odd key"]` otherwise, `parent[3]` for list items. */
const member = (parent: string, key: string): string => (IDENTIFIER.test(key) ? `${parent}.${key}` : `${parent}[${JSON.stringify(key)}]`);
const item = (parent: string, i: number): string => `${parent}[${i}]`;

/** Paths are literal segments with at most one `{id}` parameter; any other parameter spelling is rejected. */
function pathProblem(path: string): string | null {
  if (!PATH.test(path)) return 'path is malformed.';
  const segments = path.slice(1).split('/');
  let params = 0;
  for (const seg of segments) {
    if (seg === '{id}') { params += 1; continue; }
    if (seg.includes('{') || seg.includes('}')) return 'path may use only {id} as a parameter.';
    if (!SEGMENT.test(seg)) return 'path has an empty or malformed segment.';
  }
  if (params > 1) return 'path may use only {id} as a parameter, at most once.';
  return null;
}

/**
 * Failure carries the same problems twice: `issues` addressed by path for tooling, and `errors` as
 * display strings (`"<path>: <message>"`, or the bare message when no location applies). `issues[i]`
 * always corresponds to `errors[i]`.
 */
export type ValidationResult = { ok: true; contract: Contract } | { ok: false; errors: string[]; issues: ValidationIssue[] };

/** Only an in-memory mock or a loopback host is ever accepted as a target. */
export function isLocalTarget(server: string): boolean {
  if (/^mock:\/\/[a-z0-9.-]+$/i.test(server)) return true;
  try {
    const url = new URL(server);
    return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) && ['http:', 'https:'].includes(url.protocol);
  } catch {
    return false;
  }
}

/**
 * Iterative structural scan: returns the first structural problem (too deep, list too long, too many keys)
 * without recursion or argument spreading, so hostile inputs cannot blow the stack.
 */
function structuralProblem(root: unknown): string | null {
  const stack: { value: unknown; depth: number }[] = [{ value: root, depth: 0 }];
  let visited = 0;
  while (stack.length) {
    const { value, depth } = stack.pop()!;
    if (++visited > 50_000) return 'Contract has too many values.';
    if (depth > LIMITS.maxDepth) return `Contract nesting exceeds ${LIMITS.maxDepth} levels.`;
    if (Array.isArray(value)) {
      if (value.length > LIMITS.maxListLength) return `A list in the contract exceeds ${LIMITS.maxListLength} entries.`;
      for (const v of value) stack.push({ value: v, depth: depth + 1 });
    } else if (value && typeof value === 'object') {
      const keys = Object.keys(value as object);
      if (keys.length > LIMITS.maxListLength) return `An object in the contract exceeds ${LIMITS.maxListLength} keys.`;
      for (const k of keys) stack.push({ value: (value as Record<string, unknown>)[k], depth: depth + 1 });
    } else if (typeof value === 'number' && !Number.isFinite(value)) {
      return 'Contract contains a non-finite number (numbers must be finite).';
    }
  }
  return null;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v: unknown): v is string => typeof v === 'string' && v.length <= LIMITS.maxStringLength;
const isFieldValue = (v: unknown) => v === null || typeof v === 'string' || typeof v === 'boolean' || (typeof v === 'number' && Number.isFinite(v));
const list = (v: unknown): unknown[] => (Array.isArray(v) ? (v as unknown[]) : []);

export function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

function failure(issues: ValidationIssue[]): ValidationResult {
  return { ok: false, errors: issues.map((issue) => (issue.path ? `${issue.path}: ${issue.message}` : issue.message)), issues };
}
const wholeDocument = (message: string): ValidationResult => failure([{ path: '', message }]);

export function parseContract(text: string): ValidationResult {
  if (byteLength(text) > LIMITS.maxBytes) return wholeDocument(`Contract text exceeds ${LIMITS.maxBytes} bytes (UTF-8).`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return wholeDocument('Contract is not valid JSON.');
  }
  return validateContract(parsed);
}

/**
 * Validates and normalises a contract. Normalisation is a fixpoint: feeding an accepted contract back in
 * yields a deep-equal contract. Unknown top-level keys are ignored; nothing inside a known key is.
 */
export function validateContract(input: unknown): ValidationResult {
  if (!isObj(input)) return wholeDocument('Contract must be a JSON object.');
  const structural = structuralProblem(input);
  if (structural) return wholeDocument(structural);

  const issues: ValidationIssue[] = [];
  const fail = (path: string, message: string): void => { issues.push({ path, message }); };

  if (input.schema !== 'permitmatrix.contract/1') fail('schema', 'schema must be "permitmatrix.contract/1".');
  for (const key of ['name', 'version'] as const) {
    if (!str(input[key]) || !input[key]) fail(key, `${key} must be a string of 1–${LIMITS.maxStringLength} characters.`);
  }

  const servers: string[] = [];
  const rawServers = list(input.servers);
  if (rawServers.length === 0 || rawServers.length > LIMITS.maxServers) fail('servers', `servers must list 1–${LIMITS.maxServers} mock:// or localhost targets.`);
  for (const [i, s] of rawServers.entries()) {
    if (!str(s)) fail(item('servers', i), 'servers entries must be strings.');
    else if (!isLocalTarget(s)) fail(item('servers', i), `External target refused: "${s}". Only mock:// or localhost targets are allowed.`);
    else servers.push(s);
  }

  const roles: Role[] = [];
  const roleIds = new Set<string>();
  const rawRoles = list(input.roles);
  if (rawRoles.length === 0 || rawRoles.length > LIMITS.maxRoles) fail('roles', `roles must contain 1–${LIMITS.maxRoles} entries.`);
  for (const [i, r] of rawRoles.entries()) {
    const at = item('roles', i);
    if (!isObj(r) || !str(r.id) || !ID.test(r.id) || !str(r.label)) { fail(at, 'role entries need id and label.'); continue; }
    if (isReservedId(r.id)) fail(`${at}.id`, `role id ${r.id} ${RESERVED_ID_HINT}`);
    else if (roleIds.has(r.id)) fail(`${at}.id`, `duplicate role id ${r.id}.`);
    roleIds.add(r.id);
    roles.push({ id: r.id, label: r.label });
  }

  const principals: Principal[] = [];
  const principalIds = new Set<string>();
  const rawPrincipals = list(input.principals);
  if (rawPrincipals.length === 0 || rawPrincipals.length > LIMITS.maxPrincipals) fail('principals', `principals must contain 1–${LIMITS.maxPrincipals} entries.`);
  for (const [i, p] of rawPrincipals.entries()) {
    const at = item('principals', i);
    if (!isObj(p) || !str(p.id) || !ID.test(p.id) || !str(p.role) || !str(p.tenant) || !str(p.label)) { fail(at, 'principal entries need id, role, tenant, label.'); continue; }
    if (isReservedId(p.id)) fail(`${at}.id`, `principal id ${p.id} ${RESERVED_ID_HINT}`);
    else if (principalIds.has(p.id)) fail(`${at}.id`, `duplicate principal id ${p.id}.`);
    if (!roleIds.has(p.role)) fail(`${at}.role`, `principal ${p.id} references unknown role ${p.role}.`);
    principalIds.add(p.id);
    principals.push({ id: p.id, role: p.role, tenant: p.tenant, label: p.label });
  }

  const resources: Resource[] = [];
  const resourceIds = new Set<string>();
  const rawResources = list(input.resources);
  if (rawResources.length === 0 || rawResources.length > LIMITS.maxResources) fail('resources', `resources must contain 1–${LIMITS.maxResources} entries.`);
  for (const [i, r] of rawResources.entries()) {
    const at = item('resources', i);
    if (!isObj(r) || !str(r.id) || !ID.test(r.id) || !str(r.label) || !Array.isArray(r.records)) { fail(at, 'resource entries need id, label, records[].'); continue; }
    const rawRecords = list(r.records);
    if (rawRecords.length > LIMITS.maxRecordsPerResource) fail(`${at}.records`, `resource ${r.id} exceeds ${LIMITS.maxRecordsPerResource} records.`);
    const records: RecordRow[] = [];
    const recordIds = new Set<string>();
    for (const [j, rec] of rawRecords.entries()) {
      const recordAt = item(`${at}.records`, j);
      if (!isObj(rec) || !str(rec.id) || !ID.test(rec.id) || !str(rec.owner) || !str(rec.tenant) || !isObj(rec.fields)) { fail(recordAt, `resource ${r.id} has a malformed record.`); continue; }
      const fields = rec.fields;
      const keys = Object.keys(fields);
      if (keys.length > LIMITS.maxFieldsPerRecord) fail(`${recordAt}.fields`, `record ${rec.id} has too many fields.`);
      for (const k of keys) {
        const fieldAt = member(`${recordAt}.fields`, k);
        if (isReservedName(k)) fail(fieldAt, `record ${rec.id} uses reserved field name "${k}".`);
        else if (!ID.test(k)) fail(fieldAt, `record ${rec.id} field name "${k}" is malformed.`);
        else if (!isFieldValue(fields[k])) fail(fieldAt, `record ${rec.id} field "${k}" must be a string, finite number, boolean or null.`);
      }
      if (isReservedId(rec.owner)) fail(`${recordAt}.owner`, `record ${rec.id} owner ${rec.owner} ${RESERVED_ID_HINT}`);
      else if (!principalIds.has(rec.owner)) fail(`${recordAt}.owner`, `record ${rec.id} owner ${rec.owner} is not a known principal.`);
      if (recordIds.has(rec.id)) fail(`${recordAt}.id`, `duplicate record id ${rec.id} in resource ${r.id}.`);
      recordIds.add(rec.id);
      records.push({ id: rec.id, owner: rec.owner, tenant: rec.tenant, fields: { ...(fields as RecordRow['fields']) } });
    }
    if (resourceIds.has(r.id)) fail(`${at}.id`, `duplicate resource id ${r.id}.`);
    resourceIds.add(r.id);
    resources.push({ id: r.id, label: r.label, records });
  }

  const endpoints: Endpoint[] = [];
  const endpointIds = new Set<string>();
  const routes = new Set<string>();
  const rawEndpoints = list(input.endpoints);
  if (rawEndpoints.length === 0 || rawEndpoints.length > LIMITS.maxEndpoints) fail('endpoints', `endpoints must contain 1–${LIMITS.maxEndpoints} entries.`);
  for (const [i, e] of rawEndpoints.entries()) {
    const at = item('endpoints', i);
    if (!isObj(e) || !str(e.id) || !ID.test(e.id) || !str(e.method) || !str(e.path) || !str(e.resource) || !isObj(e.access)) { fail(at, 'endpoint entries need id, method, path, resource, access.'); continue; }
    if (!METHODS.includes(e.method as Method)) fail(`${at}.method`, `endpoint ${e.id} has unsupported method ${e.method}.`);
    const pathIssue = pathProblem(e.path);
    if (pathIssue) fail(`${at}.path`, `endpoint ${e.id} ${pathIssue}`);
    const routeKey = `${e.method} ${e.path}`;
    if (routes.has(routeKey)) fail(at, `endpoint ${e.id}: duplicate route ${routeKey}; each method + path template may appear once so every request maps to exactly one policy.`);
    routes.add(routeKey);
    if (!resourceIds.has(e.resource)) fail(`${at}.resource`, `endpoint ${e.id} references unknown resource ${e.resource}.`);

    // An endpoint with no callable role would silently test nothing, so a missing or empty list is an error.
    const access = e.access;
    const accessRoles: string[] = [];
    const rolesAt = `${at}.access.roles`;
    if (!Array.isArray(access.roles) || access.roles.length === 0) fail(rolesAt, `endpoint ${e.id} access.roles must be a non-empty list of role ids.`);
    for (const [k, role] of list(access.roles).entries()) {
      const roleAt = item(rolesAt, k);
      if (!str(role)) fail(roleAt, `endpoint ${e.id} access.roles entries must be strings.`);
      else if (isReservedId(role)) fail(roleAt, `endpoint ${e.id} access.roles entry ${role} ${RESERVED_ID_HINT}`);
      else if (!roleIds.has(role)) fail(roleAt, `endpoint ${e.id} references unknown role ${role}.`);
      else if (accessRoles.includes(role)) fail(roleAt, `endpoint ${e.id} access.roles contains duplicate role ${role}.`);
      else accessRoles.push(role);
    }
    if (!OWNERSHIPS.includes(access.ownership as Ownership)) fail(`${at}.access.ownership`, `endpoint ${e.id} ownership must be any|own|same-tenant.`);

    const lists: { writableFields?: string[]; sensitiveFields?: string[] } = {};
    for (const key of ['writableFields', 'sensitiveFields'] as const) {
      if (e[key] === undefined) continue;
      const listAt = `${at}.${key}`;
      if (!Array.isArray(e[key])) { fail(listAt, `endpoint ${e.id} ${key} must be a list of field names.`); continue; }
      const names = new Set<string>();
      for (const [k, f] of list(e[key]).entries()) {
        const nameAt = item(listAt, k);
        if (!str(f)) fail(nameAt, `endpoint ${e.id} ${key} entries must be field names.`);
        else if (isReservedName(f)) fail(nameAt, `endpoint ${e.id} ${key} uses reserved field name "${f}".`);
        else if (!ID.test(f)) fail(nameAt, `endpoint ${e.id} ${key} entries must be field names.`);
        else if (names.has(f)) fail(nameAt, `endpoint ${e.id} ${key} contains duplicate field ${f}.`);
        else names.add(f);
      }
      lists[key] = [...names];
    }
    if (endpointIds.has(e.id)) fail(`${at}.id`, `duplicate endpoint id ${e.id}.`);
    endpointIds.add(e.id);
    endpoints.push({
      id: e.id, method: e.method as Method, path: e.path, resource: e.resource,
      access: { roles: accessRoles, ownership: access.ownership as Ownership },
      ...(lists.writableFields ? { writableFields: lists.writableFields } : {}),
      ...(lists.sensitiveFields ? { sensitiveFields: lists.sensitiveFields } : {}),
    });
  }

  const builds: Contract['builds'] = {};
  if (input.builds !== undefined && !isObj(input.builds)) fail('builds', 'builds must be an object keyed by build id.');
  const rawBuilds = isObj(input.builds) ? Object.entries(input.builds) : [];
  if (rawBuilds.length > LIMITS.maxBuilds) fail('builds', `builds must contain at most ${LIMITS.maxBuilds} entries.`);
  for (const [key, b] of rawBuilds) {
    const at = member('builds', key);
    if (isReservedName(key)) { fail(at, `build key "${key}" is a reserved name.`); continue; }
    if (!ID.test(key)) { fail(at, `build key "${key}" is malformed.`); continue; }
    if (!isObj(b) || !str(b.label) || !Array.isArray(b.flaws)) { fail(at, `build ${key} is malformed.`); continue; }
    const rawFlaws = list(b.flaws);
    if (rawFlaws.length > LIMITS.maxFlawsPerBuild) { fail(`${at}.flaws`, `build ${key} exceeds ${LIMITS.maxFlawsPerBuild} flaws.`); continue; }
    const flaws: Flaw[] = [];
    for (const [k, f] of rawFlaws.entries()) {
      const flawAt = item(`${at}.flaws`, k);
      if (!isObj(f)) { fail(flawAt, `build ${key} has a malformed flaw entry.`); continue; }
      const endpointOk = str(f.endpoint) && endpointIds.has(f.endpoint);
      const kindOk = str(f.kind) && FLAW_KINDS.includes(f.kind as FlawKind);
      if (!str(f.endpoint)) fail(`${flawAt}.endpoint`, `build ${key} flaw endpoint must be an endpoint id.`);
      else if (!endpointOk) fail(`${flawAt}.endpoint`, `build ${key} flaw references unknown endpoint ${f.endpoint}.`);
      if (!kindOk) fail(`${flawAt}.kind`, `build ${key} flaw kind must be one of ${FLAW_KINDS.join(', ')}.`);
      if (endpointOk && kindOk) flaws.push({ endpoint: f.endpoint as string, kind: f.kind as FlawKind });
    }
    builds[key] = { label: b.label, flaws };
  }
  if (!builds.fixed) builds.fixed = { label: 'fixed (no seeded flaws)', flaws: [] };

  if (issues.length) return failure(issues);
  return {
    ok: true,
    contract: {
      schema: 'permitmatrix.contract/1', name: input.name as string, version: input.version as string,
      servers, roles, principals, resources, endpoints, builds,
    },
  };
}
