import { describe, expect, it } from 'vitest';
import fixture from '../../fixtures/ledgerly-contract.json';
import { validateContract } from '../contract';
import { generateCases } from '../cases';
import { runSuite } from '../runner';
import { diffRuns, summarizeDiff } from '../diff';
import type { RunRef } from '../diff';
import type { CaseResult, Contract, Finding, FindingKind, Flaw, SuiteRun, Verdict } from '../types';

const contract = (input: unknown = fixture): Contract => {
  const result = validateContract(input);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
};
const vulnerableFlaws = (): Flaw[] => fixture.builds.vulnerable.flaws as Flaw[];

const VULNERABLE: RunRef = { label: fixture.builds.vulnerable.label, build: 'vulnerable', flaws: vulnerableFlaws() };
const FIXED: RunRef = { label: fixture.builds.fixed.label, build: 'fixed', flaws: [] };

// Measured once on the frozen Ledgerly fixture: the four seeded flaws turn exactly 31 verdicts non-pass
// (7 object bypasses, 8 function bypasses, 12 mass assignments, 4 exposures). Re-measure if the fixture changes.
// Case totals are never hard-coded below: they derive from `cases.length`, so the file holds whether or not the
// generator emits the anonymous row by default (Ledgerly seeds no skip-authentication flaw, so anonymous cases
// pass on both builds and leave the 31 untouched).
const LEDGERLY_VULNERABLE_NON_PASS = 31;
// Finding ids are `${endpoint}:${kind}`; the diff reports them sorted by id.
const LEDGERLY_FINDING_IDS = ['delete-user:function-bypass', 'get-invoice:object-bypass', 'get-user:sensitive-exposure', 'patch-user:mass-assignment'];

function ledgerlyRuns() {
  const c = contract();
  const cases = generateCases(c);
  const vulnerable = runSuite(c, cases, vulnerableFlaws());
  const fixed = runSuite(c, cases, []);
  // Guard the derivation: every result set covers exactly the generated cases, so `cases.length` is the total.
  expect(vulnerable.results).toHaveLength(cases.length);
  expect(fixed.results).toHaveLength(cases.length);
  return { c, cases, vulnerable, fixed };
}

// Hand-built minimal runs for the classification rules (independent of the generator).
const result = (caseId: string, verdict: Verdict, endpoint = 'get-thing', role = 'member'): CaseResult => ({
  caseId, endpoint, role, principal: 'p-1', targetKind: 'own', expected: 'allow', verdict,
  request: { method: 'GET', path: '/things/t-1', principal: 'p-1', headers: {} },
  response: { status: 200 },
  explanation: 'hand-built',
});
const finding = (endpoint: string, kind: FindingKind): Finding => ({
  id: `${endpoint}:${kind}`, endpoint, kind, owaspApi: 'n/a', title: `title ${kind}`, severity: 'low', evidenceCases: [], remediation: '',
});
const suite = (results: CaseResult[], findings: Finding[] = []): SuiteRun => ({ results, findings, coverage: {} });
const REF_A: RunRef = { label: 'A', build: 'a', flaws: [] };
const REF_B: RunRef = { label: 'B', build: 'b', flaws: [{ endpoint: 'get-thing', kind: 'deny-everything' }] };

describe('diffRuns on the Ledgerly fixture', () => {
  it('vulnerable → fixed: the four seeded findings are fixed and every non-pass verdict improves', () => {
    const { cases, vulnerable, fixed } = ledgerlyRuns();
    const nonPass = vulnerable.results.filter((r) => r.verdict !== 'pass').length;
    expect(nonPass).toBe(LEDGERLY_VULNERABLE_NON_PASS);

    const diff = diffRuns(vulnerable, fixed, { before: VULNERABLE, after: FIXED });
    expect(diff.findings.fixed.map((f) => f.id)).toEqual(LEDGERLY_FINDING_IDS);
    expect(diff.findings.introduced).toEqual([]);
    expect(diff.findings.persisting).toEqual([]);
    expect(diff.summary).toEqual({ improved: LEDGERLY_VULNERABLE_NON_PASS, regressed: 0, changed: 0, fixedFindings: 4, newFindings: 0 });
    expect(diff.changed).toHaveLength(nonPass);
    expect(diff.changed.every((ch) => ch.direction === 'improved' && ch.after === 'pass' && ch.before !== 'pass')).toBe(true);
    expect(diff.changed.map((ch) => ch.caseId)).toEqual([...diff.changed.map((ch) => ch.caseId)].sort());
    expect(diff.unchanged).toBe(cases.length - nonPass);
    expect(diff.added).toEqual([]);
    expect(diff.removed).toEqual([]);
    expect(diff.before).toEqual(VULNERABLE);
    expect(diff.after).toEqual(FIXED);

    // Each change points at a real case and carries its endpoint/role, which is what the matrix selection needs.
    const caseById = new Map(cases.map((c) => [c.id, c]));
    for (const ch of diff.changed) {
      const c = caseById.get(ch.caseId);
      expect(c?.endpoint).toBe(ch.endpoint);
      expect(c?.role).toBe(ch.role);
    }
    // Every fixed finding was evidenced only by cases that improved.
    const improved = new Set(diff.changed.map((ch) => ch.caseId));
    for (const f of diff.findings.fixed) for (const id of f.evidenceCases) expect(improved.has(id)).toBe(true);
  });

  it('fixed → vulnerable: the mirror introduces the same four findings and regresses the same cases', () => {
    const { cases, vulnerable, fixed } = ledgerlyRuns();
    const diff = diffRuns(fixed, vulnerable, { before: FIXED, after: VULNERABLE });
    expect(diff.findings.introduced.map((f) => f.id)).toEqual(LEDGERLY_FINDING_IDS);
    expect(diff.findings.fixed).toEqual([]);
    expect(diff.findings.persisting).toEqual([]);
    expect(diff.summary).toEqual({ improved: 0, regressed: LEDGERLY_VULNERABLE_NON_PASS, changed: 0, fixedFindings: 0, newFindings: 4 });
    expect(diff.changed).toHaveLength(LEDGERLY_VULNERABLE_NON_PASS);
    expect(diff.changed.every((ch) => ch.direction === 'regressed' && ch.before === 'pass' && ch.after !== 'pass')).toBe(true);
    expect(diff.unchanged).toBe(cases.length - LEDGERLY_VULNERABLE_NON_PASS);
    // Introduced findings are the after run's own objects, not copies.
    for (const f of diff.findings.introduced) expect(vulnerable.findings.includes(f)).toBe(true);
  });

  it('identical runs: nothing changes, lists are empty, and persisting findings are taken from the after run', () => {
    const { c, cases, vulnerable, fixed } = ledgerlyRuns();
    const same = diffRuns(fixed, fixed, { before: FIXED, after: FIXED });
    expect(same.changed).toEqual([]);
    expect(same.added).toEqual([]);
    expect(same.removed).toEqual([]);
    expect(same.unchanged).toBe(cases.length);
    expect(same.findings).toEqual({ fixed: [], introduced: [], persisting: [] });
    expect(same.summary).toEqual({ improved: 0, regressed: 0, changed: 0, fixedFindings: 0, newFindings: 0 });

    const again = runSuite(c, cases, vulnerableFlaws());
    const persist = diffRuns(vulnerable, again, { before: VULNERABLE, after: VULNERABLE });
    expect(persist.changed).toEqual([]);
    expect(persist.unchanged).toBe(cases.length);
    expect(persist.findings.fixed).toEqual([]);
    expect(persist.findings.introduced).toEqual([]);
    expect(persist.findings.persisting.map((f) => f.id)).toEqual(LEDGERLY_FINDING_IDS);
    for (const f of persist.findings.persisting) {
      expect(again.findings.includes(f)).toBe(true);
      expect(vulnerable.findings.includes(f)).toBe(false);
    }
    expect(persist.summary).toEqual({ improved: 0, regressed: 0, changed: 0, fixedFindings: 0, newFindings: 0 });
  });

  it('differing case sets: an endpoint added to the contract appears as added cases, and as removed when the runs swap', () => {
    const original = contract();
    const extra = { id: 'export-invoices', method: 'GET', path: '/invoices/export', resource: 'invoices', access: { roles: ['admin'], ownership: 'any' } };
    const mutated = contract({ ...fixture, endpoints: [...fixture.endpoints, extra] });
    const originalCases = generateCases(original);
    const mutatedCases = generateCases(mutated);
    const originalIds = new Set(originalCases.map((c) => c.id));
    const expectedAdded = mutatedCases.filter((c) => !originalIds.has(c.id)).map((c) => c.id).sort();
    expect(expectedAdded.length).toBeGreaterThan(0);
    expect(expectedAdded.every((id) => id.startsWith('export-invoices|'))).toBe(true);

    const before = runSuite(original, originalCases, []);
    const after = runSuite(mutated, mutatedCases, []);
    const grown: RunRef = { ...FIXED, label: 'release/1.5.0 (export route)' };
    const forward = diffRuns(before, after, { before: FIXED, after: grown });
    expect(forward.added).toEqual(expectedAdded);
    expect(forward.removed).toEqual([]);
    expect(forward.changed).toEqual([]);
    expect(forward.unchanged).toBe(originalCases.length);
    expect(forward.findings).toEqual({ fixed: [], introduced: [], persisting: [] });

    const backward = diffRuns(after, before, { before: grown, after: FIXED });
    expect(backward.removed).toEqual(expectedAdded);
    expect(backward.added).toEqual([]);
    expect(backward.changed).toEqual([]);
    expect(backward.unchanged).toBe(originalCases.length);
  });

  it('is deterministic, independent of input order, and leaves its inputs untouched', () => {
    const { c, cases, vulnerable, fixed } = ledgerlyRuns();
    const snapshot = JSON.stringify([vulnerable, fixed, VULNERABLE, FIXED]);
    const first = diffRuns(vulnerable, fixed, { before: VULNERABLE, after: FIXED });
    expect(first.changed.length).toBeGreaterThan(0);
    expect(diffRuns(vulnerable, fixed, { before: VULNERABLE, after: FIXED })).toEqual(first);

    const freshBefore = runSuite(c, cases, vulnerableFlaws());
    const freshAfter = runSuite(c, cases, []);
    expect(diffRuns(freshBefore, freshAfter, { before: VULNERABLE, after: FIXED })).toEqual(first);

    const reversed = (run: SuiteRun): SuiteRun => ({ ...run, results: [...run.results].reverse(), findings: [...run.findings].reverse() });
    expect(diffRuns(reversed(vulnerable), reversed(fixed), { before: VULNERABLE, after: FIXED })).toEqual(first);

    expect(JSON.stringify([vulnerable, fixed, VULNERABLE, FIXED])).toBe(snapshot);
  });

  it('summarises the comparison in one sentence', () => {
    const { vulnerable, fixed } = ledgerlyRuns();
    expect(summarizeDiff(diffRuns(vulnerable, fixed, { before: VULNERABLE, after: FIXED }))).toBe('4 findings fixed, 0 introduced; 31 cases improved, 0 regressed');
    expect(summarizeDiff(diffRuns(fixed, vulnerable, { before: FIXED, after: VULNERABLE }))).toBe('0 findings fixed, 4 introduced; 0 cases improved, 31 regressed');
    expect(summarizeDiff(diffRuns(fixed, fixed, { before: FIXED, after: FIXED }))).toBe('0 findings fixed, 0 introduced; 0 cases improved, 0 regressed');
  });
});

describe('diffRuns direction classification (hand-built runs)', () => {
  it('classifies improved / regressed / changed, counts unchanged, and sorts changed, added and removed by case id', () => {
    const before = suite([
      result('k', 'bypass'), // only in before → removed
      result('j', 'error'), // → mass-assignment: changed
      result('i', 'pass'), // → over-deny: regressed
      result('h', 'over-deny'), // → pass: improved
      result('e', 'bypass'), // same verdict: unchanged
      result('d', 'pass'), // same verdict: unchanged
      result('c', 'exposure'), // → error: changed
      result('b', 'pass'), // → bypass: regressed
      result('a', 'bypass'), // → pass: improved
    ]);
    const after = suite([
      result('z', 'pass'), // only in after → added
      result('j', 'mass-assignment'),
      result('i', 'over-deny'),
      result('h', 'pass'),
      result('g', 'pass'), // only in after → added
      result('e', 'bypass'),
      result('d', 'pass'),
      result('c', 'error'),
      result('b', 'bypass'),
      result('a', 'pass'),
    ]);
    const diff = diffRuns(before, after, { before: REF_A, after: REF_B });
    expect(diff.changed.map((ch) => ch.caseId)).toEqual(['a', 'b', 'c', 'h', 'i', 'j']);
    expect(diff.changed.map((ch) => ch.direction)).toEqual(['improved', 'regressed', 'changed', 'improved', 'regressed', 'changed']);
    expect(diff.changed[0]).toEqual({ caseId: 'a', endpoint: 'get-thing', role: 'member', before: 'bypass', after: 'pass', direction: 'improved' });
    expect(diff.changed[2]).toEqual({ caseId: 'c', endpoint: 'get-thing', role: 'member', before: 'exposure', after: 'error', direction: 'changed' });
    expect(diff.unchanged).toBe(2);
    expect(diff.added).toEqual(['g', 'z']);
    expect(diff.removed).toEqual(['k']);
    expect(diff.summary).toEqual({ improved: 2, regressed: 2, changed: 2, fixedFindings: 0, newFindings: 0 });
    expect(diff.summary.improved + diff.summary.regressed + diff.summary.changed).toBe(diff.changed.length);
    expect(diff.before).toEqual(REF_A);
    expect(diff.after).toEqual(REF_B);
    expect(summarizeDiff(diff)).toBe('0 findings fixed, 0 introduced; 2 cases improved, 2 regressed, 2 changed (still failing); 2 cases added, 1 removed');
  });

  it('treats over-deny like any other failure: reaching pass improves, leaving pass regresses', () => {
    const before = suite([result('x', 'over-deny'), result('y', 'pass')], [finding('get-thing', 'over-deny')]);
    const after = suite([result('x', 'pass'), result('y', 'over-deny')], [finding('get-thing', 'over-deny')]);
    const diff = diffRuns(before, after, { before: REF_A, after: REF_B });
    expect(diff.changed).toEqual([
      { caseId: 'x', endpoint: 'get-thing', role: 'member', before: 'over-deny', after: 'pass', direction: 'improved' },
      { caseId: 'y', endpoint: 'get-thing', role: 'member', before: 'pass', after: 'over-deny', direction: 'regressed' },
    ]);
    expect(diff.findings.persisting).toHaveLength(1);
    expect(diff.summary).toEqual({ improved: 1, regressed: 1, changed: 0, fixedFindings: 0, newFindings: 0 });
  });

  it('matches findings by endpoint and kind, sorts them by id, and keeps the after object for persisting findings', () => {
    const before = suite([], [finding('z-endpoint', 'over-deny'), finding('get-thing', 'object-bypass'), finding('m-endpoint', 'mass-assignment')]);
    const persisted = finding('m-endpoint', 'mass-assignment');
    const after = suite([], [persisted, finding('a-endpoint', 'auth-bypass')]);
    const diff = diffRuns(before, after, { before: REF_A, after: REF_B });
    expect(diff.findings.fixed.map((f) => f.id)).toEqual(['get-thing:object-bypass', 'z-endpoint:over-deny']);
    expect(diff.findings.introduced.map((f) => f.id)).toEqual(['a-endpoint:auth-bypass']);
    expect(diff.findings.persisting).toHaveLength(1);
    expect(diff.findings.persisting[0]).toBe(persisted);
    expect(diff.findings.persisting[0]).not.toBe(before.findings[2]);
    expect(diff.summary.fixedFindings).toBe(2);
    expect(diff.summary.newFindings).toBe(1);
    expect(diff.unchanged).toBe(0);
  });

  it('uses singular nouns in the summary when exactly one finding or case changed', () => {
    const before = suite([result('a', 'bypass'), result('b', 'pass')], [finding('get-thing', 'object-bypass')]);
    const after = suite([result('a', 'pass'), result('b', 'pass')]);
    const diff = diffRuns(before, after, { before: REF_B, after: REF_A });
    expect(summarizeDiff(diff)).toBe('1 finding fixed, 0 introduced; 1 case improved, 0 regressed');
    expect(diff.unchanged).toBe(1);
  });
});
