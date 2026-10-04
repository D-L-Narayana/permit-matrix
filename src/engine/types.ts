export type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export type Ownership = 'any' | 'own' | 'same-tenant';
export type FieldValue = string | number | boolean | null;

export interface Role { id: string; label: string }
export interface Principal { id: string; role: string; tenant: string; label: string }
export interface RecordRow { id: string; owner: string; tenant: string; fields: Record<string, FieldValue> }
export interface Resource { id: string; label: string; records: RecordRow[] }
export interface Endpoint {
  id: string;
  method: Method;
  path: string;
  resource: string;
  access: { roles: string[]; ownership: Ownership };
  writableFields?: string[];
  sensitiveFields?: string[];
}

export type FlawKind =
  | 'skip-ownership-check'
  | 'skip-role-check'
  | 'accept-all-fields'
  | 'return-sensitive-fields'
  | 'deny-everything'
  | 'skip-authentication';
export interface Flaw { endpoint: string; kind: FlawKind }
export interface Build { label: string; flaws: Flaw[] }

export interface Contract {
  schema: 'permitmatrix.contract/1';
  name: string;
  version: string;
  servers: string[];
  roles: Role[];
  principals: Principal[];
  resources: Resource[];
  endpoints: Endpoint[];
  builds: Record<string, Build>;
}

/** Which authorization dimension a case probes (OWASP API Security Top 10:2023 vocabulary). */
export type CaseCategory = 'object' | 'function' | 'property' | 'authentication';
export type TargetKind = 'own' | 'peer' | 'cross-tenant' | 'collection' | 'create';
export type Expectation = 'allow' | 'deny';

/** Synthetic caller with no credentials; every endpoint is expected to refuse it before any policy runs. */
export const ANONYMOUS_PRINCIPAL = 'anonymous';
export const ANONYMOUS_ROLE: Role = { id: 'anonymous', label: 'Anonymous (no credentials)' };

/** A validation failure addressed to the offending location, e.g. `endpoints[2].access.roles`. */
export interface ValidationIssue { path: string; message: string }
/** A non-fatal contract health warning produced by the linter. */
export interface ContractWarning { code: string; severity: 'info' | 'warn'; path: string; message: string }

export interface TestCase {
  id: string;
  endpoint: string;
  principal: string;
  role: string;
  targetKind: TargetKind;
  targetRecord?: string;
  category: CaseCategory;
  expected: Expectation;
  /** For property cases: the field being probed (written or looked for in the response). */
  probeField?: string;
  rationale: string;
}

export interface MockRequest {
  method: Method;
  path: string;
  principal: string;
  body?: Record<string, FieldValue>;
}
export interface MockResponse {
  status: number;
  body?: { id?: string; fields?: Record<string, FieldValue>; items?: RecordRow[]; error?: string };
}

export type Verdict = 'pass' | 'bypass' | 'over-deny' | 'exposure' | 'mass-assignment' | 'error';
export type FindingKind = 'object-bypass' | 'function-bypass' | 'mass-assignment' | 'sensitive-exposure' | 'over-deny' | 'auth-bypass';
export type OwaspApi = 'API1:2023' | 'API2:2023' | 'API3:2023' | 'API5:2023' | 'n/a';
export type Severity = 'high' | 'medium' | 'low';

export interface CaseResult {
  caseId: string;
  endpoint: string;
  role: string;
  principal: string;
  targetKind: TargetKind;
  expected: Expectation;
  verdict: Verdict;
  request: MockRequest & { headers: Record<string, string> };
  response: MockResponse;
  explanation: string;
}

export interface Finding {
  id: string;
  endpoint: string;
  kind: FindingKind;
  owaspApi: OwaspApi;
  title: string;
  severity: Severity;
  evidenceCases: string[];
  remediation: string;
}

export interface CoverageCell { total: number; pass: number; failed: number }
export type Coverage = Record<string, Record<string, CoverageCell>>;

export interface SuiteRun {
  results: CaseResult[];
  findings: Finding[];
  coverage: Coverage;
}
