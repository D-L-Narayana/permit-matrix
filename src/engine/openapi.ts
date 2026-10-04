/**
 * Contract import formats: native `permitmatrix.contract/1` JSON and OpenAPI 3.x JSON carrying the
 * `x-permitmatrix` extension. The converter is pure and offline — it never resolves `$ref`s, never fetches
 * anything, and only ever produces a contract by handing its result to `validateContract`, so every
 * engine rule (loopback-only servers, LIMITS, cross-references, duplicate routes) applies to imported
 * documents exactly as it does to hand-written ones. Every walk over untrusted structure is iterative
 * and capped, so a hostile document cannot exhaust the stack.
 */
import { LIMITS, byteLength, validateContract } from './contract';
import type { Contract } from './types';

export type ImportFormat = 'permitmatrix' | 'openapi' | 'unknown';

export type ImportOutcome =
  | { ok: true; contract: Contract; format: ImportFormat; notes: string[] }
  | { ok: false; format: ImportFormat; errors: string[] };

/** Methods the engine can exercise; the mock server has semantics for exactly these. */
const SUPPORTED_METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;
type SupportedMethod = (typeof SUPPORTED_METHODS)[number];
/** Other operation keys a path item may carry (OpenAPI 3.1 fixed fields plus the 3.2 `query` operation). */
const OTHER_METHODS = new Set(['head', 'options', 'trace', 'query']);
/** Only write methods get `writableFields` derived from a request body. */
const WRITE_METHODS = new Set<SupportedMethod>(['post', 'put', 'patch']);
/** Caps for the pre-scan of an untrusted document; the same list ceiling validateContract uses. */
const MAX_PATHS = LIMITS.maxListLength;
const MAX_VALUES = 50_000;
/**
 * A response property schema already sits about ten levels below the root of an OpenAPI document, so the
 * contract's own depth limit cannot apply here; 40 leaves room for deeply nested inline schemas while still
 * bounding how far the pre-scan walks. The converted contract is then subject to LIMITS.maxDepth as usual.
 */
const MAX_DOCUMENT_DEPTH = 40;
/** Same identifier rule as validateContract (not exported there), checked early so the message names the OpenAPI field at fault. */
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const MAX_REPORTED_ERRORS = 40;
/** Schema keywords holding data or prose rather than sub-schemas; a `$ref` key inside them is not a reference. */
const DATA_KEYWORDS = new Set(['example', 'examples', 'default', 'const', 'enum', 'description', 'title', 'externalDocs', 'xml', 'discriminator', '$comment']);
/** Schema keywords whose value is a map of name → sub-schema; a `$ref` key at that level is a property name, not a reference. */
const SCHEMA_MAP_KEYWORDS = new Set(['properties', 'patternProperties', 'dependentSchemas', '$defs', 'definitions']);
/** Path-item fixed fields (OpenAPI 3.1, plus 3.2's additionalOperations) that are not operations. */
const PATH_ITEM_FIELDS = new Set(['$ref', 'summary', 'description', 'servers', 'parameters', 'additionalOperations']);
const JSON_MEDIA_TYPE = /^application\/(?:[a-z0-9!#$&^_.+-]+\+)?json$/i;
const WHOLE_PARAMETER = /^\{[^{}]+\}$/;

const UNKNOWN_FORMAT_MESSAGE =
  'Unrecognised document. Paste either a Permit Matrix contract (a JSON object with "schema": "permitmatrix.contract/1") '
  + 'or an OpenAPI 3.x document as JSON (a JSON object with "openapi": "3.x.y" and a top-level x-permitmatrix extension). YAML is not accepted.';
const X_PERMITMATRIX_REQUIRED =
  'x-permitmatrix is required. OpenAPI describes operations but cannot express who calls the API (principals with roles and tenants) '
  + 'or which records they own, so a top-level x-permitmatrix object must supply roles, principals and resources (with records), and optionally builds.';

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const isStringList = (v: unknown): v is string[] => Array.isArray(v) && v.every((s) => typeof s === 'string');

export function detectFormat(parsed: unknown): ImportFormat {
  if (!isObj(parsed)) return 'unknown';
  if (parsed.schema === 'permitmatrix.contract/1') return 'permitmatrix';
  if (typeof parsed.openapi === 'string' && parsed.openapi.startsWith('3.')) return 'openapi';
  return 'unknown';
}

function fail(format: ImportFormat, errors: string[]): ImportOutcome {
  if (errors.length <= MAX_REPORTED_ERRORS) return { ok: false, format, errors };
  return { ok: false, format, errors: [...errors.slice(0, MAX_REPORTED_ERRORS), `…and ${errors.length - MAX_REPORTED_ERRORS} more problem(s) not shown.`] };
}

/**
 * Iterative structural pre-scan of the whole document (no recursion, no argument spreading): rejects
 * excessive depth, list length, key count, value count and non-finite numbers before anything is read.
 */
function structuralProblem(root: unknown): string | null {
  const stack: { value: unknown; depth: number; where: string }[] = [{ value: root, depth: 0, where: 'document' }];
  let visited = 0;
  while (stack.length) {
    const { value, depth, where } = stack.pop()!;
    if (++visited > MAX_VALUES) return `The document has more than ${MAX_VALUES} values; it is too large to import.`;
    if (depth > MAX_DOCUMENT_DEPTH) return `${where}: nesting exceeds ${MAX_DOCUMENT_DEPTH} levels.`;
    if (Array.isArray(value)) {
      if (value.length > LIMITS.maxListLength) return `${where}: a list exceeds ${LIMITS.maxListLength} entries.`;
      for (let i = 0; i < value.length; i++) stack.push({ value: value[i], depth: depth + 1, where: `${where}[${i}]` });
    } else if (isObj(value)) {
      const keys = Object.keys(value);
      if (keys.length > LIMITS.maxListLength) return `${where}: an object exceeds ${LIMITS.maxListLength} keys.`;
      for (const k of keys) stack.push({ value: value[k], depth: depth + 1, where: `${where}.${k}` });
    } else if (typeof value === 'number' && !Number.isFinite(value)) {
      return `${where}: numbers must be finite.`;
    }
  }
  return null;
}

interface Template { path: string; renamed: boolean; problem: string | null }

/** Permit Matrix routes on a single `{id}`; one parameter of any name is renamed, more than one is refused. */
function convertTemplate(template: string): Template {
  if (!template.startsWith('/')) return { path: template, renamed: false, problem: 'path template must start with "/".' };
  const segments = template.slice(1).split('/');
  if (segments.some((seg) => !WHOLE_PARAMETER.test(seg) && /[{}]/.test(seg))) {
    return { path: template, renamed: false, problem: 'path parameters must occupy a whole segment, as in /invoices/{invoiceId}.' };
  }
  const params = segments.filter((seg) => WHOLE_PARAMETER.test(seg));
  if (params.length > 1) return { path: template, renamed: false, problem: 'at most one path parameter is supported; Permit Matrix routes on a single {id}.' };
  const path = `/${segments.map((seg) => (WHOLE_PARAMETER.test(seg) ? '{id}' : seg)).join('/')}`;
  return { path, renamed: params.length === 1 && params[0] !== '{id}', problem: null };
}

/**
 * Walks one schema tree iteratively (document order) collecting property names flagged
 * `x-permitmatrix-sensitive: true`; any `$ref` in the tree is an error because nothing is ever resolved.
 */
function scanSchema(schema: unknown, label: string, where: string): { fields: string[]; error: string | null } {
  const fields: string[] = [];
  // Entries are pushed in reverse so that popping visits the document in order (stable, deterministic output).
  const stack: { value: unknown; where: string; map: boolean }[] = [{ value: schema, where, map: false }];
  while (stack.length) {
    const { value, where: here, map } = stack.pop()!;
    if (Array.isArray(value)) {
      for (let i = value.length - 1; i >= 0; i--) stack.push({ value: value[i], where: `${here}[${i}]`, map: false });
      continue;
    }
    if (!isObj(value)) continue;
    const keys = Object.keys(value);
    if (map) {
      for (let i = keys.length - 1; i >= 0; i--) stack.push({ value: value[keys[i]], where: `${here}.${keys[i]}`, map: false });
      continue;
    }
    if (Object.hasOwn(value, '$ref')) return { fields, error: `${label}: inline the schema (${here} uses $ref; $ref is not supported).` };
    if (isObj(value.properties)) {
      for (const [name, sub] of Object.entries(value.properties)) {
        if (isObj(sub) && sub['x-permitmatrix-sensitive'] === true && !fields.includes(name)) fields.push(name);
      }
    }
    for (let i = keys.length - 1; i >= 0; i--) {
      const k = keys[i];
      if (DATA_KEYWORDS.has(k)) continue;
      stack.push({ value: value[k], where: `${here}.${k}`, map: SCHEMA_MAP_KEYWORDS.has(k) });
    }
  }
  return { fields, error: null };
}

/** Converts one operation into an unvalidated endpoint object, or returns null after recording the problems. */
function convertOperation(label: string, method: SupportedMethod, raw: unknown, template: Template, errors: string[], notes: string[]): Record<string, unknown> | null {
  if (!isObj(raw)) { errors.push(`${label}: operation must be an object.`); return null; }
  const before = errors.length;
  if ('$ref' in raw) errors.push(`${label}: inline the schema (the operation uses $ref; $ref is not supported).`);
  if (template.problem) errors.push(`${label}: ${template.problem}`);
  else if (template.renamed) notes.push(`${label}: parameter renamed to {id}`);
  if (raw.servers !== undefined) notes.push(`${label}: operation-level servers are ignored; the document-level servers apply`);
  if (typeof raw.operationId !== 'string') errors.push(`${label}: operationId is required; it becomes the endpoint id.`);
  else if (!ID.test(raw.operationId)) {
    const shown = raw.operationId.length > 40 ? `${raw.operationId.slice(0, 40)}…` : raw.operationId;
    errors.push(`${label}: operationId "${shown}" must be 1–64 characters of letters, digits, ".", "_" or "-" starting with a letter or digit; it becomes the endpoint id.`);
  }
  if (typeof raw['x-permitmatrix-resource'] !== 'string') errors.push(`${label}: x-permitmatrix-resource is required (the id of a resource declared in x-permitmatrix.resources).`);
  const rawAccess = raw['x-permitmatrix-access'];
  const access = isObj(rawAccess) && isStringList(rawAccess.roles) && typeof rawAccess.ownership === 'string'
    ? { roles: rawAccess.roles, ownership: rawAccess.ownership }
    : null;
  if (!access) errors.push(`${label}: x-permitmatrix-access is required as { "roles": [role ids], "ownership": "any" | "own" | "same-tenant" }.`);

  let writable: string[] | undefined;
  const explicitWritable = raw['x-permitmatrix-writable'];
  if (explicitWritable !== undefined) {
    if (isStringList(explicitWritable)) writable = [...explicitWritable];
    else errors.push(`${label}: x-permitmatrix-writable must be a list of field names.`);
  }
  let sensitive: string[] | undefined;
  const explicitSensitive = raw['x-permitmatrix-sensitive'];
  if (explicitSensitive !== undefined) {
    if (isStringList(explicitSensitive)) sensitive = [...explicitSensitive];
    else errors.push(`${label}: x-permitmatrix-sensitive must be a list of field names.`);
  }

  const flagged: string[] = [];
  const collect = (schema: unknown, where: string) => {
    const scanned = scanSchema(schema, label, where);
    if (scanned.error) { errors.push(scanned.error); return; }
    for (const f of scanned.fields) if (!flagged.includes(f)) flagged.push(f);
  };

  const body = raw.requestBody;
  if (body !== undefined) {
    if (!isObj(body)) errors.push(`${label}: requestBody must be an object.`);
    else if ('$ref' in body) errors.push(`${label}: inline the schema (requestBody uses $ref; $ref is not supported).`);
    else if (body.content !== undefined) {
      if (!isObj(body.content)) errors.push(`${label}: requestBody.content must be an object keyed by media type.`);
      else {
        const mediaTypes = Object.keys(body.content);
        for (const media of mediaTypes) {
          const mediaObject = body.content[media];
          if (!isObj(mediaObject)) { errors.push(`${label}: requestBody.content.${media} must be an object.`); continue; }
          if (mediaObject.schema !== undefined) collect(mediaObject.schema, `requestBody.content.${media}.schema`);
        }
        // Prefer application/json, else the first +json media type (merge-patch, vnd.api, …).
        const chosen = mediaTypes.includes('application/json') ? 'application/json' : mediaTypes.find((m) => JSON_MEDIA_TYPE.test(m));
        const chosenSchema = chosen !== undefined && isObj(body.content[chosen]) ? (body.content[chosen] as Record<string, unknown>).schema : undefined;
        if (explicitWritable === undefined && WRITE_METHODS.has(method) && isObj(chosenSchema) && isObj(chosenSchema.properties)) {
          const derived = Object.keys(chosenSchema.properties);
          if (derived.length) {
            writable = derived;
            notes.push(`${label}: writableFields derived from the request body schema [${derived.join(', ')}]`);
          }
        }
      }
    }
  }

  const responses = raw.responses;
  if (responses !== undefined) {
    if (!isObj(responses)) errors.push(`${label}: responses must be an object keyed by status code.`);
    else {
      for (const [code, response] of Object.entries(responses)) {
        if (!isObj(response)) { errors.push(`${label}: responses.${code} must be an object.`); continue; }
        if ('$ref' in response) { errors.push(`${label}: inline the schema (responses.${code} uses $ref; $ref is not supported).`); continue; }
        if (response.content === undefined) continue;
        if (!isObj(response.content)) { errors.push(`${label}: responses.${code}.content must be an object keyed by media type.`); continue; }
        for (const [media, mediaObject] of Object.entries(response.content)) {
          if (!isObj(mediaObject)) { errors.push(`${label}: responses.${code}.content.${media} must be an object.`); continue; }
          if (mediaObject.schema !== undefined) collect(mediaObject.schema, `responses.${code}.content.${media}.schema`);
        }
      }
    }
  }

  if (sensitive !== undefined) {
    for (const f of flagged) if (!sensitive.includes(f)) sensitive.push(f);
  } else if (flagged.length) {
    sensitive = flagged;
    notes.push(`${label}: sensitiveFields derived from schema properties flagged x-permitmatrix-sensitive [${flagged.join(', ')}]`);
  }

  if (errors.length > before || !access) return null;
  return {
    id: raw.operationId,
    method: method.toUpperCase(),
    path: template.path,
    resource: raw['x-permitmatrix-resource'],
    access,
    ...(writable ? { writableFields: writable } : {}),
    ...(sensitive ? { sensitiveFields: sensitive } : {}),
  };
}

/** Endpoint sub-paths in validator errors, mapped to the OpenAPI field that produced the value. */
const ENDPOINT_FIELDS: ReadonlyArray<readonly [RegExp, string]> = [
  [/^\.id$/, ' operationId'],
  [/^\.path$/, ' path template'],
  [/^\.resource$/, ' x-permitmatrix-resource'],
  [/^\.access\.roles/, ' x-permitmatrix-access.roles'],
  [/^\.access\.ownership$/, ' x-permitmatrix-access.ownership'],
  [/^\.writableFields/, ' x-permitmatrix-writable'],
  [/^\.sensitiveFields/, ' x-permitmatrix-sensitive'],
];
const TOP_LEVEL_FIELDS: ReadonlyArray<readonly [RegExp, string]> = [
  [/^name: /, 'info.title: '],
  [/^version: /, 'info.version: '],
  [/^(servers\[\d+\]): /, '$1.url: '],
  [/^endpoints: /, 'paths: '],
  [/^(roles|principals|resources|builds)(?=[.[:])/, 'x-permitmatrix.$1'],
];

/**
 * validateContract addresses problems to the converted contract (`endpoints[3].resource: …`); the author is
 * looking at an OpenAPI document, so re-address them to the operation and extension field that produced
 * the value. Errors without a recognised prefix are returned unchanged.
 */
function relocate(error: string, labels: string[]): string {
  const atEndpoint = /^endpoints\[(\d+)\]([^:]*): ([\s\S]*)$/.exec(error);
  if (atEndpoint) {
    const label = labels[Number(atEndpoint[1])];
    if (label === undefined) return error;
    const sub = atEndpoint[2];
    const mapped = ENDPOINT_FIELDS.find(([pattern]) => pattern.test(sub));
    return `${label}${mapped ? sub.replace(mapped[0], mapped[1]) : sub}: ${atEndpoint[3]}`;
  }
  for (const [pattern, replacement] of TOP_LEVEL_FIELDS) if (pattern.test(error)) return error.replace(pattern, replacement);
  return error;
}

/**
 * Converts an OpenAPI 3.x document (with the x-permitmatrix extension) into a validated contract.
 * Problems found while reading the document are reported first; only a cleanly converted candidate is
 * handed to validateContract, whose errors are then re-addressed to the document and returned.
 */
export function openapiToContract(doc: unknown): ImportOutcome {
  const format = detectFormat(doc);
  if (format === 'permitmatrix') return fail(format, ['This is already a permitmatrix.contract/1 contract; load it directly (importAny does this automatically).']);
  if (format !== 'openapi' || !isObj(doc)) return fail('unknown', [UNKNOWN_FORMAT_MESSAGE]);

  // Cheap count before the full scan so a path flood is reported as such rather than as a generic size problem.
  if (isObj(doc.paths) && Object.keys(doc.paths).length > MAX_PATHS) return fail(format, [`paths has ${Object.keys(doc.paths).length} entries; at most ${MAX_PATHS} are accepted.`]);
  const structural = structuralProblem(doc);
  if (structural) return fail(format, [structural]);

  const errors: string[] = [];
  const notes: string[] = [];

  let name: unknown;
  let version: unknown;
  if (!isObj(doc.info)) errors.push('info.title and info.version are required; they become the contract name and version.');
  else {
    if (typeof doc.info.title === 'string') name = doc.info.title; else errors.push('info.title must be a string; it becomes the contract name.');
    if (typeof doc.info.version === 'string') version = doc.info.version; else errors.push('info.version must be a string; it becomes the contract version.');
  }

  const servers: string[] = [];
  if (doc.servers === undefined) errors.push('servers is required: list the mock:// or loopback URL the contract targets (OpenAPI\'s implicit default "/" is not a target Permit Matrix can use).');
  else if (!Array.isArray(doc.servers)) errors.push('servers must be a list of server objects, each with a url.');
  else {
    doc.servers.forEach((server: unknown, i: number) => {
      if (!isObj(server) || typeof server.url !== 'string') { errors.push(`servers[${i}] must be an object with a string url.`); return; }
      if (server.url.includes('{')) { errors.push(`servers[${i}].url uses server variables, which are not expanded; write the literal mock:// or loopback URL.`); return; }
      servers.push(server.url);
    });
  }

  const extension = isObj(doc['x-permitmatrix']) ? doc['x-permitmatrix'] : null;
  if (!extension) errors.push(X_PERMITMATRIX_REQUIRED);
  else if (extension.endpoints !== undefined) notes.push('x-permitmatrix.endpoints is ignored; endpoints come from the operations under paths');

  const endpoints: Record<string, unknown>[] = [];
  const labels: string[] = [];
  if (!isObj(doc.paths)) errors.push('paths is required and must be an object keyed by path template.');
  else {
    for (const [template, item] of Object.entries(doc.paths)) {
      if (template.startsWith('x-')) continue; // specification extension, not a path
      if (!isObj(item)) { errors.push(`${template}: path item must be an object.`); continue; }
      if ('$ref' in item) { errors.push(`${template}: inline the schema (the path item uses $ref; $ref is not supported).`); continue; }
      if (item.servers !== undefined) notes.push(`${template}: path-level servers are ignored; the document-level servers apply`);
      const converted = convertTemplate(template);
      for (const [key, raw] of Object.entries(item)) {
        const label = `${key.toUpperCase()} ${template}`;
        if (OTHER_METHODS.has(key)) { notes.push(`${label}: skipped (method not supported; only GET, POST, PUT, PATCH and DELETE are tested)`); continue; }
        if (!(SUPPORTED_METHODS as readonly string[]).includes(key)) {
          const lower = key.toLowerCase();
          if (lower !== key && ((SUPPORTED_METHODS as readonly string[]).includes(lower) || OTHER_METHODS.has(lower))) {
            notes.push(`${label}: skipped (operation keys must be lowercase in OpenAPI; write "${lower}")`);
          } else if (!PATH_ITEM_FIELDS.has(key) && !key.startsWith('x-')) {
            notes.push(`${template}: key "${key}" ignored (not an OpenAPI path-item field or operation)`);
          }
          continue; // summary, description, parameters, servers and x-… are path-item fields, not operations
        }
        const endpoint = convertOperation(label, key as SupportedMethod, raw, converted, errors, notes);
        if (endpoint) { endpoints.push(endpoint); labels.push(label); }
      }
    }
  }
  if (errors.length) return fail(format, errors);

  const candidate: Record<string, unknown> = {
    schema: 'permitmatrix.contract/1', name, version, servers,
    roles: extension?.roles, principals: extension?.principals, resources: extension?.resources, endpoints,
  };
  if (extension?.builds !== undefined) candidate.builds = extension.builds;
  const result = validateContract(candidate);
  if (!result.ok) return fail(format, result.errors.map((e) => relocate(e, labels)));
  return { ok: true, contract: result.contract, format, notes };
}

/** Byte limit, JSON.parse, format detection and dispatch — the single entry point the import dialog needs. */
export function importAny(text: string): ImportOutcome {
  if (byteLength(text) > LIMITS.maxBytes) return { ok: false, format: 'unknown', errors: [`Contract text exceeds ${LIMITS.maxBytes} bytes (UTF-8).`] };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, format: 'unknown', errors: ['Contract is not valid JSON.'] };
  }
  const format = detectFormat(parsed);
  if (format === 'permitmatrix') {
    const result = validateContract(parsed);
    return result.ok ? { ok: true, contract: result.contract, format, notes: [] } : { ok: false, format, errors: result.errors };
  }
  if (format === 'openapi') return openapiToContract(parsed);
  return { ok: false, format, errors: [UNKNOWN_FORMAT_MESSAGE] };
}
