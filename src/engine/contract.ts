import type { Contract, Endpoint, Flaw, FlawKind, Method, Ownership, Principal, RecordRow, Resource, Role } from './types';

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

const METHODS: Method[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
const OWNERSHIPS: Ownership[] = ['any', 'own', 'same-tenant'];
const FLAW_KINDS: FlawKind[] = ['skip-ownership-check', 'skip-role-check', 'accept-all-fields', 'return-sensitive-fields', 'deny-everything'];
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const PATH = /^\/[a-z0-9{}/_-]{0,120}$/i;
const SEGMENT = /^[a-z0-9_-]+$/i;

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

export type ValidationResult = { ok: true; contract: Contract } | { ok: false; errors: string[] };

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

export function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

export function parseContract(text: string): ValidationResult {
  if (byteLength(text) > LIMITS.maxBytes) return { ok: false, errors: [`Contract text exceeds ${LIMITS.maxBytes} bytes (UTF-8).`] };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, errors: ['Contract is not valid JSON.'] };
  }
  return validateContract(parsed);
}

export function validateContract(input: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ['Contract must be a JSON object.'] };
  const structural = structuralProblem(input);
  if (structural) return { ok: false, errors: [structural] };
  if (input.schema !== 'permitmatrix.contract/1') errors.push('schema must be "permitmatrix.contract/1".');
  if (!str(input.name) || !input.name) errors.push('name is required.');
  if (!str(input.version) || !input.version) errors.push('version is required.');

  const servers = Array.isArray(input.servers) ? input.servers : [];
  if (servers.length === 0 || servers.length > LIMITS.maxServers) errors.push(`servers must list 1–${LIMITS.maxServers} mock:// or localhost targets.`);
  for (const s of servers) {
    if (!str(s)) errors.push('servers entries must be strings.');
    else if (!isLocalTarget(s)) errors.push(`External target refused: "${s}". Only mock:// or localhost targets are allowed.`);
  }

  const roles: Role[] = [];
  const roleIds = new Set<string>();
  const rawRoles = Array.isArray(input.roles) ? input.roles : [];
  if (rawRoles.length === 0 || rawRoles.length > LIMITS.maxRoles) errors.push(`roles must contain 1–${LIMITS.maxRoles} entries.`);
  for (const r of rawRoles) {
    if (!isObj(r) || !str(r.id) || !ID.test(r.id) || !str(r.label)) { errors.push('role entries need id and label.'); continue; }
    if (roleIds.has(r.id)) errors.push(`duplicate role id ${r.id}.`);
    roleIds.add(r.id);
    roles.push({ id: r.id, label: r.label });
  }

  const principals: Principal[] = [];
  const principalIds = new Set<string>();
  const rawPrincipals = Array.isArray(input.principals) ? input.principals : [];
  if (rawPrincipals.length === 0 || rawPrincipals.length > LIMITS.maxPrincipals) errors.push(`principals must contain 1–${LIMITS.maxPrincipals} entries.`);
  for (const p of rawPrincipals) {
    if (!isObj(p) || !str(p.id) || !ID.test(p.id) || !str(p.role) || !str(p.tenant) || !str(p.label)) { errors.push('principal entries need id, role, tenant, label.'); continue; }
    if (!roleIds.has(p.role)) errors.push(`principal ${p.id} references unknown role ${p.role}.`);
    if (principalIds.has(p.id)) errors.push(`duplicate principal id ${p.id}.`);
    principalIds.add(p.id);
    principals.push({ id: p.id, role: p.role, tenant: p.tenant, label: p.label });
  }

  const resources: Resource[] = [];
  const resourceIds = new Set<string>();
  const rawResources = Array.isArray(input.resources) ? input.resources : [];
  if (rawResources.length === 0 || rawResources.length > LIMITS.maxResources) errors.push(`resources must contain 1–${LIMITS.maxResources} entries.`);
  for (const r of rawResources) {
    if (!isObj(r) || !str(r.id) || !ID.test(r.id) || !str(r.label) || !Array.isArray(r.records)) { errors.push('resource entries need id, label, records[].'); continue; }
    if (r.records.length > LIMITS.maxRecordsPerResource) errors.push(`resource ${r.id} exceeds ${LIMITS.maxRecordsPerResource} records.`);
    const records: RecordRow[] = [];
    const recordIds = new Set<string>();
    for (const rec of r.records) {
      if (!isObj(rec) || !str(rec.id) || !ID.test(rec.id) || !str(rec.owner) || !str(rec.tenant) || !isObj(rec.fields)) { errors.push(`resource ${r.id} has a malformed record.`); continue; }
      const fields = rec.fields;
      if (Object.keys(fields).length > LIMITS.maxFieldsPerRecord) errors.push(`record ${rec.id} has too many fields.`);
      if (!Object.values(fields).every(isFieldValue) || !Object.keys(fields).every((k) => ID.test(k))) errors.push(`record ${rec.id} has non-scalar or oddly named fields.`);
      if (!principalIds.has(rec.owner)) errors.push(`record ${rec.id} owner ${rec.owner} is not a known principal.`);
      if (recordIds.has(rec.id)) errors.push(`duplicate record id ${rec.id} in resource ${r.id}.`);
      recordIds.add(rec.id);
      records.push({ id: rec.id, owner: rec.owner, tenant: rec.tenant, fields: { ...(fields as RecordRow['fields']) } });
    }
    if (resourceIds.has(r.id)) errors.push(`duplicate resource id ${r.id}.`);
    resourceIds.add(r.id);
    resources.push({ id: r.id, label: r.label, records });
  }

  const endpoints: Endpoint[] = [];
  const endpointIds = new Set<string>();
  const routes = new Set<string>();
  const rawEndpoints = Array.isArray(input.endpoints) ? input.endpoints : [];
  if (rawEndpoints.length === 0 || rawEndpoints.length > LIMITS.maxEndpoints) errors.push(`endpoints must contain 1–${LIMITS.maxEndpoints} entries.`);
  for (const e of rawEndpoints) {
    if (!isObj(e) || !str(e.id) || !ID.test(e.id) || !str(e.method) || !str(e.path) || !str(e.resource) || !isObj(e.access)) { errors.push('endpoint entries need id, method, path, resource, access.'); continue; }
    if (!METHODS.includes(e.method as Method)) errors.push(`endpoint ${e.id} has unsupported method ${e.method}.`);
    const pathIssue = pathProblem(e.path);
    if (pathIssue) errors.push(`endpoint ${e.id} ${pathIssue}`);
    const routeKey = `${e.method} ${e.path}`;
    if (routes.has(routeKey)) errors.push(`endpoint ${e.id}: duplicate route ${routeKey}; each method + path template may appear once so every request maps to exactly one policy.`);
    routes.add(routeKey);
    if (!resourceIds.has(e.resource)) errors.push(`endpoint ${e.id} references unknown resource ${e.resource}.`);
    const access = e.access;
    const accessRoles = Array.isArray(access.roles) ? access.roles : [];
    for (const role of accessRoles) if (!str(role) || !roleIds.has(role)) errors.push(`endpoint ${e.id} references unknown role ${String(role)}.`);
    if (!OWNERSHIPS.includes(access.ownership as Ownership)) errors.push(`endpoint ${e.id} ownership must be any|own|same-tenant.`);
    const lists: Record<'writableFields' | 'sensitiveFields', string[] | undefined> = { writableFields: undefined, sensitiveFields: undefined };
    for (const key of ['writableFields', 'sensitiveFields'] as const) {
      if (e[key] === undefined) continue;
      if (!Array.isArray(e[key]) || !(e[key] as unknown[]).every((f) => str(f) && ID.test(f))) errors.push(`endpoint ${e.id} ${key} must be a list of field names.`);
      else lists[key] = [...(e[key] as string[])];
    }
    if (endpointIds.has(e.id)) errors.push(`duplicate endpoint id ${e.id}.`);
    endpointIds.add(e.id);
    endpoints.push({
      id: e.id, method: e.method as Method, path: e.path, resource: e.resource,
      access: { roles: accessRoles.filter(str), ownership: access.ownership as Ownership },
      ...(lists.writableFields ? { writableFields: lists.writableFields } : {}),
      ...(lists.sensitiveFields ? { sensitiveFields: lists.sensitiveFields } : {}),
    });
  }

  const builds: Contract['builds'] = {};
  const rawBuilds = isObj(input.builds) ? input.builds : {};
  if (Object.keys(rawBuilds).length > LIMITS.maxBuilds) errors.push(`builds must contain at most ${LIMITS.maxBuilds} entries.`);
  for (const [key, b] of Object.entries(rawBuilds)) {
    if (!ID.test(key) || !isObj(b) || !str(b.label) || !Array.isArray(b.flaws)) { errors.push(`build ${key} is malformed.`); continue; }
    if (b.flaws.length > LIMITS.maxFlawsPerBuild) { errors.push(`build ${key} exceeds ${LIMITS.maxFlawsPerBuild} flaws.`); continue; }
    const flaws: Flaw[] = [];
    for (const f of b.flaws) {
      if (!isObj(f) || !str(f.endpoint) || !endpointIds.has(f.endpoint) || !FLAW_KINDS.includes(f.kind as FlawKind)) { errors.push(`build ${key} has an unknown flaw entry.`); continue; }
      flaws.push({ endpoint: f.endpoint, kind: f.kind as FlawKind });
    }
    builds[key] = { label: b.label, flaws };
  }
  if (!builds.fixed) builds.fixed = { label: 'fixed (no seeded flaws)', flaws: [] };

  if (errors.length) return { ok: false, errors };
  return {
    ok: true,
    contract: {
      schema: 'permitmatrix.contract/1', name: input.name as string, version: input.version as string,
      servers: servers as string[], roles, principals, resources, endpoints, builds,
    },
  };
}
