import { describe, expect, it } from 'vitest';
import ledgerly from '../../fixtures/ledgerly-contract.json';
import openapiFixture from '../../fixtures/ledgerly-openapi.json';
import { LIMITS, validateContract } from '../contract';
import { generateCases } from '../cases';
import { detectFormat, importAny, openapiToContract } from '../openapi';
import type { ImportOutcome } from '../openapi';
import type { Contract } from '../types';

type Json = Record<string, unknown>;

function ledgerlyContract(): Contract {
  const result = validateContract(ledgerly);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
}

/** Fresh mutable copy of the OpenAPI fixture, typed loosely so tests can remove or corrupt keys. */
const doc = (): Json => structuredClone(openapiFixture) as unknown as Json;

function at(root: Json, ...keys: string[]): Json {
  let current: unknown = root;
  for (const key of keys) current = (current as Json)[key];
  return current as Json;
}

function succeeded(outcome: ImportOutcome) {
  if (!outcome.ok) throw new Error(`expected success, got: ${outcome.errors.join(' | ')}`);
  return outcome;
}

function failed(outcome: ImportOutcome) {
  if (outcome.ok) throw new Error('expected the import to fail');
  return outcome;
}

const minimalOperation = (operationId: string, resource = 'invoices'): Json => ({
  operationId,
  'x-permitmatrix-resource': resource,
  'x-permitmatrix-access': { roles: ['admin'], ownership: 'any' },
  responses: { '200': { description: 'ok' } },
});

describe('detectFormat', () => {
  it('recognises a permitmatrix.contract/1 document by its schema field', () => {
    expect(detectFormat(ledgerly)).toBe('permitmatrix');
  });

  it('recognises an OpenAPI 3.x document by its openapi field', () => {
    expect(detectFormat(openapiFixture)).toBe('openapi');
    expect(detectFormat({ openapi: '3.0.3' })).toBe('openapi');
  });

  it('reports anything else as unknown', () => {
    expect(detectFormat({ hello: 1 })).toBe('unknown');
    expect(detectFormat({ openapi: '2.0' })).toBe('unknown');
    expect(detectFormat({ swagger: '2.0' })).toBe('unknown');
    expect(detectFormat({ openapi: 3.1 })).toBe('unknown');
    expect(detectFormat(null)).toBe('unknown');
    expect(detectFormat('openapi: 3.1.0')).toBe('unknown');
    expect(detectFormat([])).toBe('unknown');
  });

  it('prefers the permitmatrix schema marker when both markers are present', () => {
    expect(detectFormat({ schema: 'permitmatrix.contract/1', openapi: '3.1.0' })).toBe('permitmatrix');
  });
});

describe('openapiToContract — Ledgerly OpenAPI fixture', () => {
  it('converts to exactly the validated Ledgerly contract', () => {
    const result = succeeded(openapiToContract(openapiFixture));
    expect(result.format).toBe('openapi');
    expect(result.contract).toEqual(ledgerlyContract());
  });

  it('generates the same cases, in the same order, as the Ledgerly contract', () => {
    const result = succeeded(openapiToContract(openapiFixture));
    expect(generateCases(result.contract)).toEqual(generateCases(ledgerlyContract()));
  });

  it('keeps endpoints in document path/method order', () => {
    const result = succeeded(openapiToContract(openapiFixture));
    expect(result.contract.endpoints.map((e) => e.id)).toEqual(['list-invoices', 'get-invoice', 'patch-invoice', 'get-user', 'patch-user', 'delete-user']);
  });

  it('notes every renamed path parameter and nothing else', () => {
    const result = succeeded(openapiToContract(openapiFixture));
    expect(result.notes).toContain('GET /invoices/{invoiceId}: parameter renamed to {id}');
    expect(result.notes).toContain('PATCH /invoices/{invoiceId}: parameter renamed to {id}');
    // /users/{id} already uses {id}; path-item fields such as parameters/summary are not operations and get no note.
    expect(result.notes).toEqual([
      'GET /invoices/{invoiceId}: parameter renamed to {id}',
      'PATCH /invoices/{invoiceId}: parameter renamed to {id}',
    ]);
  });

  it('is deterministic', () => {
    expect(openapiToContract(openapiFixture)).toEqual(openapiToContract(openapiFixture));
  });
});

describe('openapiToContract — required extensions', () => {
  it('refuses a document without x-permitmatrix and explains that OpenAPI cannot express principals or records', () => {
    const d = doc();
    delete d['x-permitmatrix'];
    const result = failed(openapiToContract(d));
    expect(result.format).toBe('openapi');
    const text = result.errors.join(' ');
    expect(text).toMatch(/x-permitmatrix/);
    expect(text).toMatch(/principals/);
    expect(text).toMatch(/records/);
  });

  it('passes validation errors from the x-permitmatrix block through', () => {
    const d = doc();
    at(d, 'x-permitmatrix').principals = [];
    const result = failed(openapiToContract(d));
    expect(result.errors.join(' ')).toMatch(/principals/);
  });

  it('requires operationId and names the operation', () => {
    const d = doc();
    delete at(d, 'paths', '/invoices/{invoiceId}', 'get').operationId;
    const result = failed(openapiToContract(d));
    const text = result.errors.join(' ');
    expect(text).toMatch(/GET \/invoices\/\{invoiceId\}/);
    expect(text).toMatch(/operationId/);
  });

  it('rejects an operationId that cannot be an endpoint id and names the operation', () => {
    const d = doc();
    at(d, 'paths', '/invoices', 'get').operationId = 'list invoices';
    const result = failed(openapiToContract(d));
    expect(result.errors).toContain('GET /invoices: operationId "list invoices" must be 1–64 characters of letters, digits, ".", "_" or "-" starting with a letter or digit; it becomes the endpoint id.');
    const long = doc();
    at(long, 'paths', '/invoices', 'get').operationId = 'x'.repeat(300);
    const text = failed(openapiToContract(long)).errors.join(' ');
    expect(text).toMatch(/GET \/invoices: operationId "x{40}…" must be/);
  });

  it('requires x-permitmatrix-access with roles and ownership and names the operation', () => {
    const missing = doc();
    delete at(missing, 'paths', '/invoices/{invoiceId}', 'patch')['x-permitmatrix-access'];
    const r1 = failed(openapiToContract(missing));
    expect(r1.errors.join(' ')).toMatch(/PATCH \/invoices\/\{invoiceId\}: x-permitmatrix-access/);

    const malformed = doc();
    at(malformed, 'paths', '/invoices/{invoiceId}', 'patch')['x-permitmatrix-access'] = { roles: 'admin', ownership: 'any' };
    const r2 = failed(openapiToContract(malformed));
    expect(r2.errors.join(' ')).toMatch(/PATCH \/invoices\/\{invoiceId\}: x-permitmatrix-access/);
  });

  it('requires x-permitmatrix-resource and names the operation', () => {
    const d = doc();
    delete at(d, 'paths', '/users/{id}', 'delete')['x-permitmatrix-resource'];
    const result = failed(openapiToContract(d));
    expect(result.errors.join(' ')).toMatch(/DELETE \/users\/\{id\}: x-permitmatrix-resource/);
  });

  it('passes an unknown resource reference through as a validation error', () => {
    const d = doc();
    at(d, 'paths', '/users/{id}', 'delete')['x-permitmatrix-resource'] = 'ghosts';
    const result = failed(openapiToContract(d));
    expect(result.errors.join(' ')).toMatch(/unknown resource ghosts/);
  });

  it('rejects x-permitmatrix-writable and x-permitmatrix-sensitive that are not lists of field names', () => {
    const d = doc();
    at(d, 'paths', '/users/{id}', 'patch')['x-permitmatrix-writable'] = 'displayName';
    at(d, 'paths', '/users/{id}', 'get')['x-permitmatrix-sensitive'] = { passwordHash: true };
    const result = failed(openapiToContract(d));
    const text = result.errors.join(' ');
    expect(text).toMatch(/PATCH \/users\/\{id\}: x-permitmatrix-writable/);
    expect(text).toMatch(/GET \/users\/\{id\}: x-permitmatrix-sensitive/);
  });

  it('reports every operation problem in one pass', () => {
    const d = doc();
    delete at(d, 'paths', '/invoices', 'get').operationId;
    delete at(d, 'paths', '/users/{id}', 'delete')['x-permitmatrix-resource'];
    const result = failed(openapiToContract(d));
    expect(result.errors.some((e) => e.startsWith('GET /invoices:'))).toBe(true);
    expect(result.errors.some((e) => e.startsWith('DELETE /users/{id}:'))).toBe(true);
  });
});

describe('openapiToContract — validation errors are addressed to the OpenAPI document', () => {
  it('names the operation and extension field for endpoint problems', () => {
    const d = doc();
    at(d, 'paths', '/users/{id}', 'delete')['x-permitmatrix-resource'] = 'ghosts';
    at(d, 'paths', '/invoices', 'get')['x-permitmatrix-access'] = { roles: ['admin', 'superuser'], ownership: 'any' };
    const result = failed(openapiToContract(d));
    expect(result.errors).toContain('DELETE /users/{id} x-permitmatrix-resource: endpoint delete-user references unknown resource ghosts.');
    expect(result.errors.some((e) => e.startsWith('GET /invoices x-permitmatrix-access.roles[1]: ') && /superuser/.test(e))).toBe(true);
  });

  it('re-addresses info, servers and x-permitmatrix problems', () => {
    const d = doc();
    (d.info as Json).title = 't'.repeat(LIMITS.maxStringLength + 1);
    d.servers = [{ url: 'mock://ledgerly.example' }, { url: 'https://api.victim.example' }];
    at(d, 'x-permitmatrix').principals = [];
    at(d, 'x-permitmatrix', 'builds', 'vulnerable', 'flaws')[0] = { endpoint: 'get-invoice', kind: 'skip-everything' };
    const result = failed(openapiToContract(d));
    expect(result.errors.some((e) => e.startsWith('info.title: '))).toBe(true);
    expect(result.errors.some((e) => e.startsWith('servers[1].url: ') && /External target refused/.test(e))).toBe(true);
    expect(result.errors.some((e) => e.startsWith('x-permitmatrix.principals: '))).toBe(true);
    expect(result.errors.some((e) => e.startsWith('x-permitmatrix.builds.vulnerable.flaws[0].kind: '))).toBe(true);
  });
});

describe('openapiToContract — path templates', () => {
  it('rejects two or more path parameters and names the operation', () => {
    const d = doc();
    (d.paths as Json)['/tenants/{tenantId}/invoices/{invoiceId}'] = { get: minimalOperation('get-tenant-invoice') };
    const result = failed(openapiToContract(d));
    expect(result.errors.join(' ')).toMatch(/GET \/tenants\/\{tenantId\}\/invoices\/\{invoiceId\}: at most one path parameter/);
  });

  it('surfaces a duplicate route when two templates differ only by parameter name', () => {
    const d = doc();
    (d.paths as Json)['/users/{userId}'] = { get: minimalOperation('get-user-by-user-id', 'users') };
    const result = failed(openapiToContract(d));
    expect(result.errors.join(' ')).toMatch(/duplicate route GET \/users\/\{id\}/);
  });

  it('rejects templates that do not start with a slash', () => {
    const d = doc();
    (d.paths as Json)['invoices/export'] = { get: minimalOperation('export-invoices') };
    const result = failed(openapiToContract(d));
    expect(result.errors.join(' ')).toMatch(/GET invoices\/export/);
  });
});

describe('openapiToContract — schemas', () => {
  it('refuses a $ref in a response schema and asks for an inline schema', () => {
    const d = doc();
    at(d, 'paths', '/users/{id}', 'get', 'responses', '200', 'content', 'application/json').schema = { $ref: '#/components/schemas/User' };
    const result = failed(openapiToContract(d));
    const text = result.errors.join(' ');
    expect(text).toMatch(/GET \/users\/\{id\}/);
    expect(text).toMatch(/inline the schema/);
    expect(text).toMatch(/\$ref is not supported/);
  });

  it('refuses a $ref request body', () => {
    const d = doc();
    at(d, 'paths', '/users/{id}', 'patch').requestBody = { $ref: '#/components/requestBodies/UserPatch' };
    const result = failed(openapiToContract(d));
    const text = result.errors.join(' ');
    expect(text).toMatch(/PATCH \/users\/\{id\}/);
    expect(text).toMatch(/\$ref is not supported/);
  });

  it('refuses a $ref path item', () => {
    const d = doc();
    (d.paths as Json)['/invoices/export'] = { $ref: '#/components/pathItems/Export' };
    const result = failed(openapiToContract(d));
    expect(result.errors.join(' ')).toMatch(/\/invoices\/export.*\$ref is not supported/);
  });

  it('derives writableFields from an inline JSON request body when x-permitmatrix-writable is absent', () => {
    const d = doc();
    at(d, 'paths', '/invoices').post = {
      operationId: 'create-invoice',
      'x-permitmatrix-resource': 'invoices',
      'x-permitmatrix-access': { roles: ['admin', 'manager'], ownership: 'any' },
      requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { memo: { type: 'string' }, amount: { type: 'number' } } } } } },
      responses: { '201': { description: 'created' } },
    };
    const result = succeeded(openapiToContract(d));
    const created = result.contract.endpoints.find((e) => e.id === 'create-invoice');
    expect(created?.method).toBe('POST');
    expect(created?.path).toBe('/invoices');
    expect(created?.writableFields).toEqual(['memo', 'amount']);
    expect(result.contract.endpoints[1]?.id).toBe('create-invoice');
    expect(result.notes).toContain('POST /invoices: writableFields derived from the request body schema [memo, amount]');
  });

  it('accepts +json media types such as merge-patch when deriving writableFields', () => {
    const d = doc();
    delete at(d, 'paths', '/invoices/{invoiceId}', 'patch')['x-permitmatrix-writable'];
    delete at(d, 'paths', '/users/{id}', 'patch')['x-permitmatrix-writable'];
    const result = succeeded(openapiToContract(d));
    expect(result.contract).toEqual(ledgerlyContract());
    expect(result.notes).toContain('PATCH /invoices/{invoiceId}: writableFields derived from the request body schema [memo]');
  });

  it('does not derive writableFields for GET or DELETE operations', () => {
    const d = doc();
    at(d, 'paths', '/users/{id}', 'delete').requestBody = { content: { 'application/json': { schema: { type: 'object', properties: { reason: { type: 'string' } } } } } };
    const result = succeeded(openapiToContract(d));
    expect(result.contract.endpoints.find((e) => e.id === 'delete-user')?.writableFields).toBeUndefined();
  });

  it('collects sensitiveFields from properties flagged x-permitmatrix-sensitive: true when the list is absent', () => {
    const d = doc();
    delete at(d, 'paths', '/users/{id}', 'get')['x-permitmatrix-sensitive'];
    const result = succeeded(openapiToContract(d));
    expect(result.contract.endpoints.find((e) => e.id === 'get-user')?.sensitiveFields).toEqual(['passwordHash']);
    expect(result.contract).toEqual(ledgerlyContract());
  });

  it('merges the list and the flagged properties without duplicates, list first', () => {
    const d = doc();
    const properties = at(d, 'paths', '/users/{id}', 'get', 'responses', '200', 'content', 'application/json', 'schema', 'properties');
    properties.email = { type: 'string', 'x-permitmatrix-sensitive': true };
    const result = succeeded(openapiToContract(d));
    expect(result.contract.endpoints.find((e) => e.id === 'get-user')?.sensitiveFields).toEqual(['passwordHash', 'email']);
  });
});

describe('openapiToContract — servers and methods', () => {
  it('refuses an external server URL', () => {
    const d = doc();
    d.servers = [{ url: 'https://api.victim.example' }];
    const result = failed(openapiToContract(d));
    expect(result.errors.join(' ')).toMatch(/External target refused/);
  });

  it('refuses a document without servers', () => {
    const d = doc();
    delete d.servers;
    const result = failed(openapiToContract(d));
    expect(result.errors.join(' ')).toMatch(/servers/);
  });

  it('maps info.title, info.version and servers[].url', () => {
    const d = doc();
    (d.info as Json).title = 'Renamed API';
    (d.info as Json).version = '2.0.0';
    d.servers = [{ url: 'http://localhost:6110/api' }, { url: 'mock://ledgerly.example' }];
    const result = succeeded(openapiToContract(d));
    expect(result.contract.name).toBe('Renamed API');
    expect(result.contract.version).toBe('2.0.0');
    expect(result.contract.servers).toEqual(['http://localhost:6110/api', 'mock://ledgerly.example']);
  });

  it('skips unsupported HTTP methods with a note and keeps the other operations', () => {
    const d = doc();
    at(d, 'paths', '/invoices').head = { operationId: 'head-invoices', responses: { '200': { description: 'ok' } } };
    at(d, 'paths', '/invoices').options = { responses: { '200': { description: 'ok' } } };
    const result = succeeded(openapiToContract(d));
    expect(result.contract.endpoints).toHaveLength(6);
    expect(result.notes.some((n) => /^HEAD \/invoices: skipped/.test(n))).toBe(true);
    expect(result.notes.some((n) => /^OPTIONS \/invoices: skipped/.test(n))).toBe(true);
  });

  it('notes upper-case method keys and unknown path-item keys instead of silently dropping them', () => {
    const d = doc();
    at(d, 'paths', '/invoices').POST = minimalOperation('create-invoice');
    at(d, 'paths', '/invoices').pathc = minimalOperation('typo');
    at(d, 'paths', '/invoices')['x-internal'] = true;
    const result = succeeded(openapiToContract(d));
    expect(result.contract.endpoints).toHaveLength(6);
    expect(result.notes).toContain('POST /invoices: skipped (operation keys must be lowercase in OpenAPI; write "post")');
    expect(result.notes).toContain('/invoices: key "pathc" ignored (not an OpenAPI path-item field or operation)');
    expect(result.notes.some((n) => n.includes('x-internal'))).toBe(false);
  });

  it('does not mistake a property named $ref for a reference', () => {
    const d = doc();
    at(d, 'paths', '/users/{id}', 'get', 'responses', '200', 'content', 'application/json', 'schema', 'properties').$ref = { type: 'string' };
    expect(succeeded(openapiToContract(d)).contract).toEqual(ledgerlyContract());
  });

  it('refuses a non-OpenAPI document', () => {
    const r1 = failed(openapiToContract({ hello: 1 }));
    expect(r1.format).toBe('unknown');
    const r2 = failed(openapiToContract(null));
    expect(r2.format).toBe('unknown');
    const r3 = failed(openapiToContract({ openapi: '2.0', paths: {} }));
    expect(r3.format).toBe('unknown');
  });
});

describe('openapiToContract — documented minimal example', () => {
  // Mirrors the "Minimal example" in docs/CONTRACT.md; keep the two in step.
  const example = {
    openapi: '3.1.0',
    info: { title: 'Notes API (synthetic)', version: '0.1.0' },
    servers: [{ url: 'mock://notes.example' }],
    'x-permitmatrix': {
      roles: [{ id: 'member', label: 'Member' }],
      principals: [
        { id: 'p-1', role: 'member', tenant: 'acme.example', label: 'Ana' },
        { id: 'p-2', role: 'member', tenant: 'globex.example', label: 'Bo' },
      ],
      resources: [{
        id: 'notes', label: 'Notes',
        records: [
          { id: 'n-1', owner: 'p-1', tenant: 'acme.example', fields: { title: 'Plan', secret: 's1' } },
          { id: 'n-2', owner: 'p-2', tenant: 'globex.example', fields: { title: 'Draft', secret: 's2' } },
        ],
      }],
      builds: { leaky: { label: 'build 7 (leaky)', flaws: [{ endpoint: 'get-note', kind: 'skip-ownership-check' }] } },
    },
    paths: {
      '/notes/{noteId}': {
        get: {
          operationId: 'get-note',
          'x-permitmatrix-resource': 'notes',
          'x-permitmatrix-access': { roles: ['member'], ownership: 'own' },
          responses: { '200': { description: 'The note', content: { 'application/json': { schema: {
            type: 'object',
            properties: { title: { type: 'string' }, secret: { type: 'string', 'x-permitmatrix-sensitive': true } },
          } } } } },
        },
        patch: {
          operationId: 'patch-note',
          'x-permitmatrix-resource': 'notes',
          'x-permitmatrix-access': { roles: ['member'], ownership: 'own' },
          requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { title: { type: 'string' } } } } } },
          responses: { '200': { description: 'Updated' } },
        },
      },
    },
  };

  it('converts with the endpoints and notes the documentation describes', () => {
    const result = succeeded(openapiToContract(example));
    expect(result.contract.endpoints).toEqual([
      { id: 'get-note', method: 'GET', path: '/notes/{id}', resource: 'notes', access: { roles: ['member'], ownership: 'own' }, sensitiveFields: ['secret'] },
      { id: 'patch-note', method: 'PATCH', path: '/notes/{id}', resource: 'notes', access: { roles: ['member'], ownership: 'own' }, writableFields: ['title'] },
    ]);
    expect(result.contract.builds.fixed).toEqual({ label: 'fixed (no seeded flaws)', flaws: [] });
    expect(result.notes).toEqual([
      'GET /notes/{noteId}: parameter renamed to {id}',
      'GET /notes/{noteId}: sensitiveFields derived from schema properties flagged x-permitmatrix-sensitive [secret]',
      'PATCH /notes/{noteId}: parameter renamed to {id}',
      'PATCH /notes/{noteId}: writableFields derived from the request body schema [title]',
    ]);
  });
});

describe('importAny', () => {
  it('loads permitmatrix.contract/1 text through validateContract', () => {
    const result = succeeded(importAny(JSON.stringify(ledgerly)));
    expect(result.format).toBe('permitmatrix');
    expect(result.notes).toEqual([]);
    expect(result.contract).toEqual(ledgerlyContract());
  });

  it('loads OpenAPI text through the converter', () => {
    const result = succeeded(importAny(JSON.stringify(openapiFixture)));
    expect(result.format).toBe('openapi');
    expect(result.contract).toEqual(ledgerlyContract());
    expect(result.notes).toContain('GET /invoices/{invoiceId}: parameter renamed to {id}');
  });

  it('passes validation failures of permitmatrix text through with their format', () => {
    const result = failed(importAny(JSON.stringify({ ...ledgerly, servers: ['https://api.victim.example'] })));
    expect(result.format).toBe('permitmatrix');
    expect(result.errors.join(' ')).toMatch(/External target refused/);
  });

  it('refuses oversized text before parsing it', () => {
    const huge = JSON.stringify(openapiFixture) + ' '.repeat(LIMITS.maxBytes);
    const result = failed(importAny(huge));
    expect(result.errors.join(' ')).toMatch(/bytes/);
  });

  it('refuses text that is not JSON', () => {
    const result = failed(importAny('{ not json'));
    expect(result.errors).toEqual(['Contract is not valid JSON.']);
  });

  it('explains both accepted formats for an unrecognised document', () => {
    const result = failed(importAny('{"hello":1}'));
    expect(result.format).toBe('unknown');
    const text = result.errors.join(' ');
    expect(text).toMatch(/permitmatrix\.contract\/1/);
    expect(text).toMatch(/OpenAPI/);
  });
});

describe('openapiToContract — hostile documents', () => {
  it('refuses 5000 paths without throwing', () => {
    const d = doc();
    const paths: Json = {};
    for (let i = 0; i < 5000; i++) paths[`/p${i}`] = { get: minimalOperation(`op-${i}`) };
    d.paths = paths;
    let result: ImportOutcome | undefined;
    expect(() => { result = openapiToContract(d); }).not.toThrow();
    expect(result?.ok).toBe(false);
    if (result && !result.ok) expect(result.errors.join(' ')).toMatch(/paths/);
  });

  it('refuses absurdly deep nesting without recursing', () => {
    const d = doc();
    let nested: Json = { type: 'string' };
    for (let i = 0; i < 50_000; i++) nested = { properties: { leaf: nested } };
    at(d, 'paths', '/invoices', 'get', 'responses', '200', 'content', 'application/json').schema = nested;
    let result: ImportOutcome | undefined;
    expect(() => { result = openapiToContract(d); }).not.toThrow();
    expect(result?.ok).toBe(false);
  });

  it('refuses malformed paths and operations without throwing', () => {
    const asArray = doc();
    asArray.paths = [{ get: minimalOperation('x') }];
    expect(failed(openapiToContract(asArray)).errors.join(' ')).toMatch(/paths/);

    const badItem = doc();
    (badItem.paths as Json)['/broken'] = 'not an object';
    expect(failed(openapiToContract(badItem)).errors.join(' ')).toMatch(/\/broken/);

    const badOp = doc();
    (badOp.paths as Json)['/broken'] = { get: 42 };
    expect(failed(openapiToContract(badOp)).errors.join(' ')).toMatch(/GET \/broken/);
  });

  it('caps the number of reported errors', () => {
    const d = doc();
    const paths: Json = {};
    for (let i = 0; i < 200; i++) paths[`/p${i}`] = { get: { responses: {} } };
    d.paths = paths;
    const result = failed(openapiToContract(d));
    expect(result.errors.length).toBeLessThanOrEqual(41);
    expect(result.errors.at(-1)).toMatch(/more/);
  });
});
