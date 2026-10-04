import type { ContractWarning } from '../../engine/types';
import './lint.css';

export interface LintPanelProps {
  warnings: ContractWarning[];
  /** Tighter spacing for the contract rail. */
  compact?: boolean;
}

function countLine(warn: number, info: number): string {
  const parts: string[] = [];
  if (warn) parts.push(`${warn} warning${warn === 1 ? '' : 's'}`);
  if (info) parts.push(`${info} note${info === 1 ? '' : 's'}`);
  return parts.join(' · ');
}

/**
 * Advisory contract-health list. Renders text nodes only; severities use attention/neutral tones rather than
 * verdict colours so an authoring note is never mistaken for a test result.
 */
export function LintPanel({ warnings, compact = false }: LintPanelProps) {
  const warn = warnings.filter((w) => w.severity === 'warn').length;
  const info = warnings.length - warn;
  return (
    <section className={compact ? 'lint-panel compact' : 'lint-panel'} aria-label="Contract health">
      <h2 className="section">Contract health</h2>
      {warnings.length === 0 ? (
        <p className="lint-clean">No warnings. Every lint rule passed for this contract.</p>
      ) : (
        <>
          <p className="lint-summary">{countLine(warn, info)}. Advisory only: lint never blocks a run.</p>
          <ul className="lint-list">
            {warnings.map((w, i) => (
              <li key={`${i}|${w.path}|${w.code}`} className={`lint-item sev-${w.severity}`}>
                <div className="lint-head">
                  <span className={`lint-badge sev-${w.severity}`}>{w.severity}</span>
                  <code className="lint-code">{w.code}</code>
                  <code className="lint-path">{w.path}</code>
                </div>
                <p className="lint-message">{w.message}</p>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
