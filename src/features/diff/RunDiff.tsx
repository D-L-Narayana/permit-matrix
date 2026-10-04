import type { ReactElement } from 'react';
import type { CaseChange, RunDiff } from '../../engine/diff';
import { summarizeDiff } from '../../engine/diff';
import './diff.css';

// Regressions are listed first because they are the signal a remediation loop exists to catch.
// Ties keep the diff's case-id order (Array.prototype.sort is stable).
const DIRECTION_RANK: Record<CaseChange['direction'], number> = { regressed: 0, changed: 1, improved: 2 };

const count = (n: number, noun: string): string => `${n} ${noun}${n === 1 ? '' : 's'}`;

/** Compares the latest run with the previous one; collapses to a single line when nothing changed. */
export function RunDiffPanel(props: { diff: RunDiff; onSelectCase: (caseId: string) => void }): ReactElement {
  const { diff, onSelectCase } = props;
  const { fixed, introduced, persisting } = diff.findings;
  const hasChanges = diff.changed.length > 0 || fixed.length > 0 || introduced.length > 0 || diff.added.length > 0 || diff.removed.length > 0;
  const ordered = [...diff.changed].sort((a, b) => DIRECTION_RANK[a.direction] - DIRECTION_RANK[b.direction]);
  const persistNote = persisting.length > 0
    ? `${count(persisting.length, 'finding')} persist${persisting.length === 1 ? 's' : ''} in both runs.`
    : 'No findings in either run.';

  return (
    <section className="run-diff" aria-label="Run comparison">
      <h2 className="section">Changes since previous run</h2>
      <p className="run-diff-refs">{`${diff.before.label} (${count(diff.before.flaws.length, 'active flaw')}) → ${diff.after.label} (${count(diff.after.flaws.length, 'active flaw')})`}</p>
      {!hasChanges && <p className="run-diff-none">{`No changes — ${count(diff.unchanged, 'case')} kept the same verdict. ${persistNote}`}</p>}
      {hasChanges && (
        <>
          <p className="run-diff-summary">{summarizeDiff(diff)}</p>
          {fixed.length > 0 && (
            <div className="run-diff-group">
              <h3>Fixed findings</h3>
              <ul className="run-diff-findings fixed">
                {fixed.map((f) => <li key={f.id}>{f.title} · <code>{f.endpoint}</code></li>)}
              </ul>
            </div>
          )}
          {introduced.length > 0 && (
            <div className="run-diff-group">
              <h3>Introduced findings</h3>
              <ul className="run-diff-findings introduced">
                {introduced.map((f) => <li key={f.id}>{f.title} · <code>{f.endpoint}</code></li>)}
              </ul>
            </div>
          )}
          {persisting.length > 0 && <p className="run-diff-note">{persistNote}</p>}
          {ordered.length > 0 && (
            <div className="run-diff-group">
              <h3>Changed cases</h3>
              <ul className="run-diff-cases">
                {ordered.map((ch) => (
                  <li key={ch.caseId}>
                    <button type="button" className={`dir-${ch.direction}`} onClick={() => onSelectCase(ch.caseId)}>
                      {`${ch.caseId}: ${ch.before} → ${ch.after}`}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {diff.added.length > 0 && <p className="run-diff-ids">{`Added cases (${diff.added.length}): ${diff.added.join(', ')}`}</p>}
          {diff.removed.length > 0 && <p className="run-diff-ids">{`Removed cases (${diff.removed.length}): ${diff.removed.join(', ')}`}</p>}
        </>
      )}
    </section>
  );
}
