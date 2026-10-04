import type { Finding, Flaw, SuiteRun, Verdict } from './types';

/** Identifies the run being compared: the selected build and the flaws that were actually active. */
export interface RunRef { label: string; build: string; flaws: Flaw[] }

/**
 * `improved`: the case now passes. `regressed`: the case used to pass and no longer does.
 * `changed`: the verdict moved between two non-pass values (e.g. exposure → error), so it is still failing.
 */
export type ChangeDirection = 'improved' | 'regressed' | 'changed';

export interface CaseChange {
  caseId: string;
  endpoint: string;
  role: string;
  before: Verdict;
  after: Verdict;
  direction: ChangeDirection;
}

export interface RunDiff {
  before: RunRef;
  after: RunRef;
  /** Cases present in both runs whose verdict differs, sorted by case id. */
  changed: CaseChange[];
  /** Case ids only present in the after run (sorted). */
  added: string[];
  /** Case ids only present in the before run (sorted). */
  removed: string[];
  /** Cases present in both runs with the same verdict. */
  unchanged: number;
  /** Matched by `${endpoint}:${kind}`; `persisting` holds the after run's objects so evidence links stay current. */
  findings: { fixed: Finding[]; introduced: Finding[]; persisting: Finding[] };
  /** `improved + regressed + changed === changed.length`; `changed` counts the non-pass → non-pass moves. */
  summary: { improved: number; regressed: number; changed: number; fixedFindings: number; newFindings: number };
}

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

// A finding is "the same" across runs when it is the same weakness class on the same endpoint; this is also
// how the runner constructs `Finding.id`, but deriving it here keeps the diff independent of that detail.
const findingKey = (f: Finding): string => `${f.endpoint}:${f.kind}`;
const byKey = (a: Finding, b: Finding): number => compare(findingKey(a), findingKey(b));

function directionOf(before: Verdict, after: Verdict): ChangeDirection {
  if (after === 'pass') return 'improved';
  if (before === 'pass') return 'regressed';
  return 'changed';
}

const copyRef = (ref: RunRef): RunRef => ({ label: ref.label, build: ref.build, flaws: ref.flaws.map((f) => ({ endpoint: f.endpoint, kind: f.kind })) });

/**
 * Compares two suite runs case by case (matched on case id) and finding by finding. Output lists are sorted so
 * the result depends only on the two runs, never on result order; inputs are not modified.
 */
export function diffRuns(before: SuiteRun, after: SuiteRun, refs: { before: RunRef; after: RunRef }): RunDiff {
  const beforeById = new Map(before.results.map((r) => [r.caseId, r]));
  const afterById = new Map(after.results.map((r) => [r.caseId, r]));

  const changed: CaseChange[] = [];
  const removed: string[] = [];
  let unchanged = 0;
  for (const [caseId, b] of beforeById) {
    const a = afterById.get(caseId);
    if (!a) { removed.push(caseId); continue; }
    if (a.verdict === b.verdict) { unchanged += 1; continue; }
    changed.push({ caseId, endpoint: a.endpoint, role: a.role, before: b.verdict, after: a.verdict, direction: directionOf(b.verdict, a.verdict) });
  }
  const added = [...afterById.keys()].filter((id) => !beforeById.has(id));
  changed.sort((x, y) => compare(x.caseId, y.caseId));
  added.sort(compare);
  removed.sort(compare);

  const beforeFindings = new Map(before.findings.map((f) => [findingKey(f), f]));
  const afterFindings = new Map(after.findings.map((f) => [findingKey(f), f]));
  const fixed = [...beforeFindings.values()].filter((f) => !afterFindings.has(findingKey(f))).sort(byKey);
  const introduced = [...afterFindings.values()].filter((f) => !beforeFindings.has(findingKey(f))).sort(byKey);
  const persisting = [...afterFindings.values()].filter((f) => beforeFindings.has(findingKey(f))).sort(byKey);

  const tally = (direction: ChangeDirection): number => changed.filter((c) => c.direction === direction).length;
  return {
    before: copyRef(refs.before),
    after: copyRef(refs.after),
    changed,
    added,
    removed,
    unchanged,
    findings: { fixed, introduced, persisting },
    summary: { improved: tally('improved'), regressed: tally('regressed'), changed: tally('changed'), fixedFindings: fixed.length, newFindings: introduced.length },
  };
}

const plural = (n: number, noun: string): string => `${n} ${noun}${n === 1 ? '' : 's'}`;

/** One sentence for the panel and for logs, e.g. "4 findings fixed, 0 introduced; 31 cases improved, 0 regressed". */
export function summarizeDiff(diff: RunDiff): string {
  const s = diff.summary;
  let text = `${plural(s.fixedFindings, 'finding')} fixed, ${s.newFindings} introduced; ${plural(s.improved, 'case')} improved, ${s.regressed} regressed`;
  if (s.changed > 0) text += `, ${s.changed} changed (still failing)`;
  if (diff.added.length > 0 || diff.removed.length > 0) text += `; ${plural(diff.added.length, 'case')} added, ${diff.removed.length} removed`;
  return text;
}
