import type { SuiteRun, TestCase } from '../engine/types';

export interface FindingsProps {
  run: SuiteRun | null;
  caseById: Map<string, TestCase>;
  onSelectCase: (caseId: string) => void;
}

const MAX_EVIDENCE = 12;

export function Findings({ run, caseById, onSelectCase }: FindingsProps) {
  return (
    <>
      <h2 className="section">Findings {run ? `· ${run.findings.length}` : ''}</h2>
      {!run && <p className="empty">Findings appear after a run, grouped by endpoint and OWASP API Security Top 10 (2023) category.</p>}
      {run && run.findings.length === 0 && <p className="empty good">No findings. Every one of {run.results.length} cases matched the contract on this build.</p>}
      <div className="findings">
        {run?.findings.map((f) => (
          <article className={`finding sev-${f.severity}`} key={f.id}>
            <div className="head">
              <strong>{f.title}</strong>
              <span className="meta">{f.owaspApi} · {f.severity} · {f.endpoint}</span>
            </div>
            <p>{f.remediation}</p>
            <div className="evidence" role="group" aria-label="Evidence cases">
              {f.evidenceCases.slice(0, MAX_EVIDENCE).map((id) => {
                const c = caseById.get(id);
                if (!c) return null; // a finding from another contract's run has nothing to open
                return <button key={id} onClick={() => onSelectCase(id)}>{c.principal} · {c.targetKind}{c.probeField ? ` · ${c.probeField}` : ''}</button>;
              })}
              {f.evidenceCases.length > MAX_EVIDENCE && <span className="meta">+{f.evidenceCases.length - MAX_EVIDENCE} more</span>}
            </div>
          </article>
        ))}
      </div>
    </>
  );
}
