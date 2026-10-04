import { describe, expect, it } from 'vitest';
// ajv 8 ships the draft 2020-12 class as a separate entry point; the package has no "exports" map,
// so the deep import resolves directly to dist/2020.js (default export = Ajv2020 class).
import Ajv2020 from 'ajv/dist/2020';
import type { ErrorObject, ValidateFunction } from 'ajv/dist/2020';
import schema from '../../../public/schema/permitmatrix.contract-1.schema.json';
import ledgerly from '../../fixtures/ledgerly-contract.json';
import openapiFixture from '../../fixtures/ledgerly-openapi.json';
import { LIMITS, validateContract } from '../contract';
import { openapiToContract } from '../openapi';

type Json = Record<string, unknown>;
type Problem = { path: string; keyword: string };

const SCHEMA_ID = 'https://dln-permit-matrix.vercel.app/schema/permitmatrix.contract-1.schema.json';
const DRAFT = 'https://json-schema.org/draft/2020-12/schema';

// strict mode turns Ajv's strict-schema warnings into errors so a sloppy schema cannot ship;
// allowUnionTypes permits the scalar union used for record field values.
const ajv = new Ajv2020({ strict: true, allowUnionTypes: true, allErrors: true });
let compiled: ValidateFunction | undefined;
const validator = (): ValidateFunction => (compiled ??= ajv.compile(schema));

function problems(data: unknown): Problem[] {
  const validate = validator();
  if (validate(data)) return [];
  return (validate.errors ?? []).map((e: ErrorObject) => ({ path: e.instancePath, keyword: e.keyword }));
}

const fixture = (): Json => structuredClone(ledgerly) as unknown as Json;
const endpoint0 = (patch: Json): Json => {
  const c = fixture();
  const endpoints = c.endpoints as Json[];
  endpoints[0] = { ...endpoints[0], ...patch };
  return c;
};
const record0 = (patch: Json): Json => {
  const c = fixture();
  const resources = c.resources as Json[];
  const records = resources[0].records as Json[];
  records[0] = { ...records[0], ...patch };
  return c;
};

describe('permitmatrix.contract/1 JSON Schema — document', () => {
  it('declares draft 2020-12 and the published $id', () => {
    const meta = schema as Record<string, unknown>;
    expect(meta.$schema).toBe(DRAFT);
    expect(meta.$id).toBe(SCHEMA_ID);
    expect(meta.title).toBe('permitmatrix.contract/1');
    expect(String(meta.description)).toMatch(/necessary/i);
    expect(String(meta.description)).toMatch(/validateContract/);
  });

  it('compiles under Ajv strict mode with the draft 2020-12 vocabulary', () => {
    expect(() => validator()).not.toThrow();
  });

  it('mirrors every LIMITS value it can express', () => {
    const props = (schema as Json).properties as Json;
    const defs = (schema as Json).$defs as Json;
    expect((props.endpoints as Json).maxItems).toBe(LIMITS.maxEndpoints);
    expect((props.roles as Json).maxItems).toBe(LIMITS.maxRoles);
    expect((props.principals as Json).maxItems).toBe(LIMITS.maxPrincipals);
    expect((props.resources as Json).maxItems).toBe(LIMITS.maxResources);
    expect((props.servers as Json).maxItems).toBe(LIMITS.maxServers);
    expect((props.builds as Json).maxProperties).toBe(LIMITS.maxBuilds);
    expect(((defs.resource as Json).properties as Json).records).toMatchObject({ maxItems: LIMITS.maxRecordsPerResource });
    expect(((defs.record as Json).properties as Json).fields).toMatchObject({ maxProperties: LIMITS.maxFieldsPerRecord });
    expect(((defs.build as Json).properties as Json).flaws).toMatchObject({ maxItems: LIMITS.maxFlawsPerBuild });
    expect((defs.text as Json).maxLength).toBe(LIMITS.maxStringLength);
  });
});

describe('permitmatrix.contract/1 JSON Schema — valid documents', () => {
  it('accepts the Ledgerly contract as shipped', () => {
    expect(problems(ledgerly)).toEqual([]);
  });

  it('accepts the normalised output of validateContract', () => {
    const result = validateContract(ledgerly);
    if (!result.ok) throw new Error(result.errors.join('\n'));
    expect(problems(result.contract)).toEqual([]);
  });

  it('accepts the contract converted from the Ledgerly OpenAPI document', () => {
    const result = openapiToContract(openapiFixture);
    if (!result.ok) throw new Error(result.errors.join('\n'));
    expect(problems(result.contract)).toEqual([]);
  });

  it('tolerates $schema and unknown top-level keys, which validateContract ignores', () => {
    expect(problems({ ...fixture(), $schema: SCHEMA_ID, 'x-notes': 'editor metadata' })).toEqual([]);
  });

  it('accepts a contract without builds and with empty optional lists', () => {
    const c = fixture();
    delete c.builds;
    const endpoints = c.endpoints as Json[];
    endpoints[2] = { ...endpoints[2], writableFields: [] };
    expect(problems(c)).toEqual([]);
  });
});

describe('permitmatrix.contract/1 JSON Schema — invalid documents', () => {
  it('rejects a wrong schema marker', () => {
    expect(problems({ ...fixture(), schema: 'permitmatrix.contract/2' })).toContainEqual({ path: '/schema', keyword: 'const' });
  });

  it('rejects missing required sections', () => {
    const c = fixture();
    delete c.roles;
    delete c.endpoints;
    const found = problems(c);
    expect(found.filter((p) => p.path === '' && p.keyword === 'required')).toHaveLength(2);
  });

  it('rejects 41 endpoints', () => {
    const c = fixture();
    const base = (c.endpoints as Json[])[0];
    c.endpoints = Array.from({ length: LIMITS.maxEndpoints + 1 }, (_, i) => ({ ...base, id: `ep-${i}`, path: `/p${i}` }));
    expect(problems(c)).toContainEqual({ path: '/endpoints', keyword: 'maxItems' });
  });

  it('rejects an unsupported method', () => {
    expect(problems(endpoint0({ method: 'HEAD' }))).toContainEqual({ path: '/endpoints/0/method', keyword: 'enum' });
    expect(problems(endpoint0({ method: 'get' }))).toContainEqual({ path: '/endpoints/0/method', keyword: 'enum' });
  });

  it('rejects malformed paths', () => {
    expect(problems(endpoint0({ path: 'invoices' }))).toContainEqual({ path: '/endpoints/0/path', keyword: 'pattern' });
    expect(problems(endpoint0({ path: '/invoices?x=1' }))).toContainEqual({ path: '/endpoints/0/path', keyword: 'pattern' });
    expect(problems(endpoint0({ path: '/invoices/{invoiceId}' }))).toContainEqual({ path: '/endpoints/0/path', keyword: 'pattern' });
    expect(problems(endpoint0({ path: '/tenants/{id}/invoices/{id}' }))).toContainEqual({ path: '/endpoints/0/path', keyword: 'pattern' });
    expect(problems(endpoint0({ path: '/invoices/{id}/' + 'a'.repeat(130) }))).toContainEqual({ path: '/endpoints/0/path', keyword: 'maxLength' });
  });

  it('rejects an invalid ownership rule and an empty access.roles list', () => {
    expect(problems(endpoint0({ access: { roles: ['admin'], ownership: 'owner' } }))).toContainEqual({ path: '/endpoints/0/access/ownership', keyword: 'enum' });
    expect(problems(endpoint0({ access: { roles: [], ownership: 'any' } }))).toContainEqual({ path: '/endpoints/0/access/roles', keyword: 'minItems' });
  });

  it('rejects non-scalar record field values', () => {
    const nested = record0({ fields: { amount: 1, memo: { nested: true } } });
    expect(problems(nested)).toContainEqual({ path: '/resources/0/records/0/fields/memo', keyword: 'type' });
    const list = record0({ fields: { tags: ['a'] } });
    expect(problems(list)).toContainEqual({ path: '/resources/0/records/0/fields/tags', keyword: 'type' });
  });

  it('rejects oddly named and reserved field names', () => {
    expect(problems(record0({ fields: { 'bad key': 1 } }))).toContainEqual({ path: '/resources/0/records/0/fields', keyword: 'propertyNames' });
    expect(problems(record0({ fields: JSON.parse('{"__proto__": 1}') }))).toContainEqual({ path: '/resources/0/records/0/fields', keyword: 'propertyNames' });
    expect(problems(record0({ fields: { constructor: 'x' } }))).toContainEqual({ path: '/resources/0/records/0/fields', keyword: 'propertyNames' });
  });

  it('rejects ids that do not match the id pattern', () => {
    expect(problems(endpoint0({ id: 'has space' }))).toContainEqual({ path: '/endpoints/0/id', keyword: 'pattern' });
    expect(problems(endpoint0({ id: '-leading-dash' }))).toContainEqual({ path: '/endpoints/0/id', keyword: 'pattern' });
    expect(problems(record0({ id: 'x'.repeat(65) }))).toContainEqual({ path: '/resources/0/records/0/id', keyword: 'pattern' });
  });

  it('rejects the reserved role and principal id "anonymous"', () => {
    const c = fixture();
    (c.roles as Json[]).push({ id: 'Anonymous', label: 'Nobody' });
    expect(problems(c)).toContainEqual({ path: '/roles/3/id', keyword: 'not' });
  });

  it('rejects strings longer than the string limit', () => {
    expect(problems({ ...fixture(), name: 'n'.repeat(LIMITS.maxStringLength + 1) })).toContainEqual({ path: '/name', keyword: 'maxLength' });
    expect(problems({ ...fixture(), name: '' })).toContainEqual({ path: '/name', keyword: 'minLength' });
  });

  it('rejects list sizes above LIMITS', () => {
    const roles = Array.from({ length: LIMITS.maxRoles + 1 }, (_, i) => ({ id: `r${i}`, label: 'r' }));
    expect(problems({ ...fixture(), roles })).toContainEqual({ path: '/roles', keyword: 'maxItems' });
    const principals = Array.from({ length: LIMITS.maxPrincipals + 1 }, (_, i) => ({ id: `p${i}`, role: 'admin', tenant: 't.example', label: 'p' }));
    expect(problems({ ...fixture(), principals })).toContainEqual({ path: '/principals', keyword: 'maxItems' });
    const servers = Array.from({ length: LIMITS.maxServers + 1 }, (_, i) => `mock://s${i}.example`);
    expect(problems({ ...fixture(), servers })).toContainEqual({ path: '/servers', keyword: 'maxItems' });
    expect(problems({ ...fixture(), servers: [] })).toContainEqual({ path: '/servers', keyword: 'minItems' });
    const resources = Array.from({ length: LIMITS.maxResources + 1 }, (_, i) => ({ id: `res${i}`, label: 'r', records: [] }));
    expect(problems({ ...fixture(), resources })).toContainEqual({ path: '/resources', keyword: 'maxItems' });
    const c = fixture();
    const invoices = (c.resources as Json[])[0];
    const row = (invoices.records as Json[])[0];
    invoices.records = Array.from({ length: LIMITS.maxRecordsPerResource + 1 }, (_, i) => ({ ...row, id: `inv-${i}` }));
    expect(problems(c)).toContainEqual({ path: '/resources/0/records', keyword: 'maxItems' });
    const fields = Object.fromEntries(Array.from({ length: LIMITS.maxFieldsPerRecord + 1 }, (_, i) => [`f${i}`, i]));
    expect(problems(record0({ fields }))).toContainEqual({ path: '/resources/0/records/0/fields', keyword: 'maxProperties' });
  });

  it('rejects malformed builds: too many, bad key, bad flaw kind, too many flaws', () => {
    const builds = Object.fromEntries(Array.from({ length: LIMITS.maxBuilds + 1 }, (_, i) => [`b${i}`, { label: 'x', flaws: [] }]));
    expect(problems({ ...fixture(), builds })).toContainEqual({ path: '/builds', keyword: 'maxProperties' });
    expect(problems({ ...fixture(), builds: { 'bad key': { label: 'x', flaws: [] } } })).toContainEqual({ path: '/builds', keyword: 'additionalProperties' });
    expect(problems({ ...fixture(), builds: { b: { label: 'x', flaws: [{ endpoint: 'get-invoice', kind: 'skip-everything' }] } } })).toContainEqual({ path: '/builds/b/flaws/0/kind', keyword: 'enum' });
    const flaws = Array.from({ length: LIMITS.maxFlawsPerBuild + 1 }, () => ({ endpoint: 'get-invoice', kind: 'skip-role-check' }));
    expect(problems({ ...fixture(), builds: { b: { label: 'x', flaws } } })).toContainEqual({ path: '/builds/b/flaws', keyword: 'maxItems' });
  });

  it('accepts every flaw kind the engine knows, including skip-authentication', () => {
    const kinds = ['skip-ownership-check', 'skip-role-check', 'accept-all-fields', 'return-sensitive-fields', 'deny-everything', 'skip-authentication'];
    const builds = { b: { label: 'all kinds', flaws: kinds.map((kind) => ({ endpoint: 'get-invoice', kind })) } };
    expect(problems({ ...fixture(), builds })).toEqual([]);
  });

  it('rejects duplicate entries in writableFields and sensitiveFields', () => {
    expect(problems(endpoint0({ writableFields: ['memo', 'memo'] }))).toContainEqual({ path: '/endpoints/0/writableFields', keyword: 'uniqueItems' });
    expect(problems(endpoint0({ sensitiveFields: ['a', 'a'] }))).toContainEqual({ path: '/endpoints/0/sensitiveFields', keyword: 'uniqueItems' });
  });
});
