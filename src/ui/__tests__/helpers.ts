// Shared fixtures for the src/ui component tests (not a test file itself: no `.test.` in the name).
import fixture from '../../fixtures/ledgerly-contract.json';
import { validateContract } from '../../engine/contract';
import { runSuite } from '../../engine/runner';
import { ANONYMOUS_PRINCIPAL, ANONYMOUS_ROLE } from '../../engine/types';
import type { CaseResult, Contract, Flaw, Role, SuiteRun, TestCase, Verdict } from '../../engine/types';

export function ledgerly(): Contract {
  const result = validateContract(fixture);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
}

export const vulnerableFlaws = (): Flaw[] => fixture.builds.vulnerable.flaws as Flaw[];

export function suite(contract: Contract, cases: TestCase[], flaws: Flaw[] = []): { run: SuiteRun; results: Map<string, CaseResult> } {
  const run = runSuite(contract, cases, flaws);
  return { run, results: new Map(run.results.map((r) => [r.caseId, r])) };
}

/** Column order the app passes to the matrix: contract roles followed by the synthetic anonymous caller. */
export const matrixRoles = (contract: Contract): Role[] => [...contract.roles, ANONYMOUS_ROLE];

export const cellCases = (cases: TestCase[], endpoint: string, role: string): TestCase[] =>
  cases.filter((c) => c.endpoint === endpoint && c.role === role);

/** An anonymous-row case in the shape the case generator is specified to emit. */
export function anonymousCase(endpointId: string, targetKind: 'collection' | 'cross-tenant', targetRecord?: string): TestCase {
  return {
    id: `${endpointId}|anonymous|${targetKind}`,
    endpoint: endpointId,
    principal: ANONYMOUS_PRINCIPAL,
    role: ANONYMOUS_ROLE.id,
    targetKind,
    ...(targetRecord ? { targetRecord } : {}),
    category: 'authentication',
    expected: 'deny',
    rationale: 'No credentials are presented; the endpoint must reject the request (401) before any policy is evaluated.',
  };
}

/** What the runner is specified to record for an anonymous call: no Authorization header; 401 → pass, 2xx → bypass. */
export function anonymousResult(c: TestCase, path: string, verdict: Verdict = 'pass'): CaseResult {
  return {
    caseId: c.id,
    endpoint: c.endpoint,
    role: c.role,
    principal: c.principal,
    targetKind: c.targetKind,
    expected: c.expected,
    verdict,
    request: { method: 'GET', path, principal: c.principal, headers: { 'Content-Type': 'application/json' } },
    response: verdict === 'pass' ? { status: 401, body: { error: 'unauthenticated' } } : { status: 200, body: { id: 'inv-1001', fields: {} } },
    explanation: verdict === 'pass' ? 'Rejected with 401 before any policy was evaluated.' : 'Expected a denial but the server answered 200.',
  };
}
