import { probeValue } from './cases';
import { createMockServer } from './mockServer';
import type { MockServer } from './mockServer';
import { ANONYMOUS_PRINCIPAL, ANONYMOUS_ROLE } from './types';
import type { CaseResult, Contract, Coverage, Endpoint, FieldValue, Finding, FindingKind, Flaw, MockRequest, MockResponse, Principal, RecordRow, Resource, Severity, SuiteRun, TestCase, Verdict } from './types';

const SECRET_LIKE = /password|secret|token|hash|ssn|key/i;
const PRIVILEGE_LIKE = /role|admin|status|owner|tenant|price|amount/i;
const hasOwn = (target: object, key: string): boolean => Object.prototype.hasOwnProperty.call(target, key);

const OWASP: Record<FindingKind, Finding['owaspApi']> = {
  'object-bypass': 'API1:2023',
  'function-bypass': 'API5:2023',
  'mass-assignment': 'API3:2023',
  'sensitive-exposure': 'API3:2023',
  'over-deny': 'n/a',
  'auth-bypass': 'API2:2023',
};

const TITLES: Record<FindingKind, string> = {
  'object-bypass': 'Broken Object Level Authorization',
  'function-bypass': 'Broken Function Level Authorization',
  'mass-assignment': 'Broken Object Property Level Authorization (mass assignment)',
  'sensitive-exposure': 'Broken Object Property Level Authorization (excessive data exposure)',
  'over-deny': 'Over-restrictive authorization (functional regression)',
  'auth-bypass': 'Broken Authentication (endpoint reachable without credentials)',
};

const REMEDIATION: Record<FindingKind, string> = {
  'object-bypass': 'Resolve the record first, then compare its owner/tenant to the authenticated subject before any read or write. Centralize this in one authorization helper and add a negative test per endpoint.',
  'function-bypass': 'Enforce the role list from the contract in middleware that runs before the handler; deny by default for any route without an explicit policy.',
  'mass-assignment': 'Bind request bodies to an explicit allow-list DTO (writableFields) and discard everything else; never spread the raw body onto the entity.',
  'sensitive-exposure': 'Project responses through a view model that omits sensitive fields; strip at the serializer so every endpoint inherits the rule.',
  'over-deny': 'Not a security weakness: the server denies traffic the contract says should succeed. Fix the policy or the contract so expectations agree.',
  'auth-bypass': 'Authenticate in global middleware that runs before routing to any handler and denies by default; no route may opt out without an explicit, reviewed allow-list entry.',
};

/** The severity rubric in plain sentences; `severityFor` is the executable form of the same rules. */
export const SEVERITY_RUBRIC: ReadonlyArray<{ kind: FindingKind; severity: Severity; when: string }> = [
  { kind: 'object-bypass', severity: 'high', when: 'Always: a caller read or changed a record outside its ownership or tenant scope.' },
  { kind: 'function-bypass', severity: 'high', when: 'Always: a role outside the endpoint’s allow-list was served.' },
  { kind: 'auth-bypass', severity: 'high', when: 'Always: the endpoint served a request that carried no credentials.' },
  { kind: 'mass-assignment', severity: 'high', when: 'When the persisted non-writable field name contains role, admin, status, owner, tenant, price or amount (any letter case), because such fields change privileges, ownership or money.' },
  { kind: 'mass-assignment', severity: 'medium', when: 'When the persisted non-writable field has any other name.' },
  { kind: 'sensitive-exposure', severity: 'high', when: 'When the exposed field name contains password, secret, token, hash, ssn or key (any letter case), because such fields are credentials or identifiers.' },
  { kind: 'sensitive-exposure', severity: 'medium', when: 'When the exposed field is any other field the contract marks sensitive.' },
  { kind: 'over-deny', severity: 'low', when: 'Always: the server refused traffic the contract allows, which is a functional regression rather than a security weakness.' },
];

export function severityFor(kind: FindingKind, probeFields: readonly string[] = []): Severity {
  if (kind === 'over-deny') return 'low';
  if (kind === 'sensitive-exposure') return probeFields.some((f) => SECRET_LIKE.test(f)) ? 'high' : 'medium';
  if (kind === 'mass-assignment') return probeFields.some((f) => PRIVILEGE_LIKE.test(f)) ? 'high' : 'medium';
  return 'high';
}

/** A create probe is typed from the first record that has the field, so numbers stay numbers and booleans flip. */
function seedValue(resource: Resource | undefined, field: string): FieldValue | undefined {
  return resource?.records.find((r) => hasOwn(r.fields, field))?.fields[field];
}

function buildRequest(endpoint: Endpoint, testCase: TestCase, before: RecordRow | undefined, resource: Resource | undefined): MockRequest {
  const path = testCase.targetRecord ? endpoint.path.replace('{id}', testCase.targetRecord) : endpoint.path;
  const request: MockRequest = { method: endpoint.method, path, principal: testCase.principal };
  if (endpoint.method === 'PATCH' || endpoint.method === 'PUT' || endpoint.method === 'POST') {
    const current = before?.fields ?? {};
    const body: Record<string, FieldValue> = {};
    const first = endpoint.writableFields?.[0];
    if (first) body[first] = probeValue(current[first]);
    if (testCase.probeField) {
      body[testCase.probeField] = probeValue(endpoint.method === 'POST' ? seedValue(resource, testCase.probeField) : current[testCase.probeField]);
    }
    request.body = body;
  }
  return request;
}

/** An anonymous case models a request with no credentials at all, so it carries no Authorization header. */
function headersFor(testCase: TestCase): Record<string, string> {
  if (testCase.principal === ANONYMOUS_PRINCIPAL) return { 'Content-Type': 'application/json' };
  return { Authorization: `Bearer mock-token-${testCase.principal}`, 'Content-Type': 'application/json' };
}

interface Evaluation { verdict: Verdict; explanation: string }

function evaluate(
  testCase: TestCase, endpoint: Endpoint, principal: Principal | undefined, server: MockServer, before: RecordRow | undefined, response: MockResponse,
): Evaluation {
  const ok = response.status >= 200 && response.status < 300;
  const field = testCase.probeField;
  const unexpected: Evaluation = { verdict: 'error', explanation: `Unexpected ${response.status}; the case could not be evaluated.` };

  if (testCase.category === 'authentication') {
    if (response.status === 401) return { verdict: 'pass', explanation: 'Rejected with 401 before any policy ran, as required for a caller without credentials.' };
    if (response.status === 403) return { verdict: 'pass', explanation: 'Rejected with 403, so the request was refused; 401 is the precise status for a caller without credentials.' };
    if (ok) return { verdict: 'bypass', explanation: `Expected 401 but the server answered ${response.status} without authentication; the endpoint is reachable with no credentials.` };
    return unexpected;
  }
  if (response.status === 401 || response.status === 404 || response.status >= 500 || response.status === 400 || response.status === 405) return unexpected;
  // Only an authentication case may run without a principal; any other case naming an unknown principal is malformed.
  if (!principal) return { verdict: 'error', explanation: `Principal "${testCase.principal}" is not defined in the contract; the case could not be evaluated.` };
  if (testCase.expected === 'deny') {
    return ok
      ? { verdict: 'bypass', explanation: `Expected a denial but the server answered ${response.status}.` }
      : { verdict: 'pass', explanation: `Denied with ${response.status} as the contract requires.` };
  }
  if (!ok) return { verdict: 'over-deny', explanation: `Contract expects success but the server answered ${response.status}.` };

  if (field && (endpoint.method === 'PATCH' || endpoint.method === 'PUT')) {
    const after = server.inspect(endpoint.resource, testCase.targetRecord!);
    if (after && before && after.fields[field] !== before.fields[field]) {
      return { verdict: 'mass-assignment', explanation: `Server state shows "${field}" changed from ${JSON.stringify(before.fields[field])} to ${JSON.stringify(after.fields[field])}.` };
    }
    return { verdict: 'pass', explanation: `"${field}" was ignored; state unchanged.` };
  }
  if (field && endpoint.method === 'GET' && testCase.targetKind === 'collection') {
    const items = response.body?.items ?? [];
    const exposed = items.filter((item) => hasOwn(item.fields, field));
    return exposed.length
      ? { verdict: 'exposure', explanation: `Listing exposes sensitive field "${field}" on ${exposed.length} of ${items.length} record(s).` }
      : { verdict: 'pass', explanation: `Sensitive field "${field}" absent from all ${items.length} listed record(s).` };
  }
  if (field && endpoint.method === 'GET') {
    const leaked = response.body?.fields !== undefined && hasOwn(response.body.fields, field);
    return leaked
      ? { verdict: 'exposure', explanation: `Response body includes sensitive field "${field}".` }
      : { verdict: 'pass', explanation: `Sensitive field "${field}" absent from the response.` };
  }
  if (field && testCase.targetKind === 'create') {
    // The response echoes only presented fields, so the oracle reads the stored record like an integration test would.
    const id = response.body?.id;
    const created = id ? server.inspect(endpoint.resource, id) : undefined;
    if (!created) return { verdict: 'error', explanation: `Create answered ${response.status} without a readable record id; the probe could not be verified.` };
    return hasOwn(created.fields, field)
      ? { verdict: 'mass-assignment', explanation: `Server state shows created record "${created.id}" carries "${field}" = ${JSON.stringify(created.fields[field])}, which is not a writable field.` }
      : { verdict: 'pass', explanation: `"${field}" was discarded; created record "${created.id}" does not carry it.` };
  }
  if (testCase.targetKind === 'collection' && endpoint.method === 'GET' && response.body?.items) {
    const outOfScope = response.body.items.filter((item) =>
      endpoint.access.ownership === 'own' ? item.owner !== principal.id : endpoint.access.ownership === 'same-tenant' ? item.tenant !== principal.tenant : false,
    );
    return outOfScope.length
      ? { verdict: 'bypass', explanation: `Listing returned ${outOfScope.length} record(s) outside the caller’s scope: ${outOfScope.map((i) => i.id).join(', ')}.` }
      : { verdict: 'pass', explanation: `All ${response.body.items.length} listed records are inside the caller’s scope.` };
  }
  return { verdict: 'pass', explanation: `Allowed with ${response.status} as the contract requires.` };
}

/** Runs every case against a fresh server so that destructive cases cannot influence each other. */
export function runSuite(contract: Contract, cases: TestCase[], flaws: Flaw[]): SuiteRun {
  const endpoints = new Map(contract.endpoints.map((e) => [e.id, e]));
  const principals = new Map(contract.principals.map((p) => [p.id, p]));
  const resources = new Map(contract.resources.map((r) => [r.id, r]));
  const results: CaseResult[] = [];

  for (const testCase of cases) {
    const endpoint = endpoints.get(testCase.endpoint)!;
    const principal = testCase.principal === ANONYMOUS_PRINCIPAL ? undefined : principals.get(testCase.principal);
    const server = createMockServer(contract, flaws);
    const before = testCase.targetRecord ? server.inspect(endpoint.resource, testCase.targetRecord) : undefined;
    const request = buildRequest(endpoint, testCase, before, resources.get(endpoint.resource));
    const response = server.handle(request);
    const { verdict, explanation } = evaluate(testCase, endpoint, principal, server, before, response);

    results.push({
      caseId: testCase.id, endpoint: endpoint.id, role: testCase.role, principal: testCase.principal,
      targetKind: testCase.targetKind, expected: testCase.expected, verdict,
      request: { ...request, headers: headersFor(testCase) },
      response, explanation,
    });
  }

  const findings = aggregateFindings(contract, cases, results);
  const coverage = buildCoverage(contract, results);
  return { results, findings, coverage };
}

function aggregateFindings(contract: Contract, cases: TestCase[], results: CaseResult[]): Finding[] {
  const caseById = new Map(cases.map((c) => [c.id, c]));
  const endpoints = new Map(contract.endpoints.map((e) => [e.id, e]));
  const groups = new Map<string, { kind: FindingKind; endpoint: Endpoint; cases: string[]; probeFields: string[] }>();
  for (const r of results) {
    const c = caseById.get(r.caseId)!;
    let kind: FindingKind | null = null;
    if (r.verdict === 'bypass') kind = c.category === 'authentication' ? 'auth-bypass' : c.category === 'function' ? 'function-bypass' : 'object-bypass';
    else if (r.verdict === 'mass-assignment') kind = 'mass-assignment';
    else if (r.verdict === 'exposure') kind = 'sensitive-exposure';
    else if (r.verdict === 'over-deny') kind = 'over-deny';
    if (!kind) continue;
    const key = `${r.endpoint}:${kind}`;
    const group = groups.get(key) ?? { kind, endpoint: endpoints.get(r.endpoint)!, cases: [], probeFields: [] };
    group.cases.push(r.caseId);
    if (c.probeField) group.probeFields.push(c.probeField);
    groups.set(key, group);
  }
  return [...groups.entries()].map(([key, g]) => ({
    id: key,
    endpoint: g.endpoint.id,
    kind: g.kind,
    owaspApi: OWASP[g.kind],
    title: TITLES[g.kind],
    severity: severityFor(g.kind, g.probeFields),
    evidenceCases: g.cases,
    remediation: REMEDIATION[g.kind],
  }));
}

/** One column per contract role plus the anonymous caller, so unauthenticated results are always counted. */
function buildCoverage(contract: Contract, results: CaseResult[]): Coverage {
  const coverage: Coverage = {};
  for (const e of contract.endpoints) {
    coverage[e.id] = {};
    for (const role of [...contract.roles, ANONYMOUS_ROLE]) coverage[e.id][role.id] = { total: 0, pass: 0, failed: 0 };
  }
  for (const r of results) {
    const cell = coverage[r.endpoint]?.[r.role];
    if (!cell) continue;
    cell.total += 1;
    if (r.verdict === 'pass') cell.pass += 1;
    else cell.failed += 1;
  }
  return coverage;
}
