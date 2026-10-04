import { redactHeaders } from '../engine/report';
import type { CaseResult, TestCase } from '../engine/types';
import type { MatrixCell } from './Matrix';

export interface CaseLedgerProps {
  selected: MatrixCell | null;
  /** Either the full case list or the pre-filtered cell list; the ledger filters by `selected` itself. */
  cases: TestCase[];
  results: Map<string, CaseResult>;
  activeCase: TestCase | undefined;
  onSelectCase: (caseId: string) => void;
}

export interface CaseDetailProps {
  testCase: TestCase;
  result?: CaseResult;
}

const hasAuthorization = (headers: Record<string, string>): boolean => Object.keys(headers).some((k) => k.toLowerCase() === 'authorization');

/** Rationale, verdict and the recorded exchange. The bearer token is redacted; the response body is evidence and stays as recorded. */
export function CaseDetail({ testCase, result }: CaseDetailProps) {
  return (
    <div className="exchange">
      <p className="why"><strong>Expectation: {testCase.expected}.</strong> {testCase.rationale}</p>
      {result ? (
        <>
          <p className="why"><strong>Verdict: {result.verdict}.</strong> {result.explanation}</p>
          <div>
            <div className="label"><span>Request</span><span>{hasAuthorization(result.request.headers) ? 'Authorization header redacted' : 'No Authorization header (anonymous)'}</span></div>
            <pre tabIndex={0}>{`${result.request.method} ${result.request.path}\n${Object.entries(redactHeaders(result.request.headers)).map(([k, v]) => `${k}: ${v}`).join('\n')}${result.request.body ? `\n\n${JSON.stringify(result.request.body, null, 2)}` : ''}`}</pre>
          </div>
          <div>
            <div className="label"><span>Response</span><span>{result.response.status}</span></div>
            <pre tabIndex={0}>{result.response.body ? JSON.stringify(result.response.body, null, 2) : '(no body)'}</pre>
          </div>
        </>
      ) : (
        <p className="empty">Not yet executed. Run the suite to see the exchange.</p>
      )}
    </div>
  );
}

export function CaseLedger({ selected, cases, results, activeCase, onSelectCase }: CaseLedgerProps) {
  const cellCases = selected ? cases.filter((c) => c.endpoint === selected.endpoint && c.role === selected.role) : [];
  return (
    <aside className="ledger" aria-label="Case ledger">
      <h2 className="section">Case ledger {selected ? `· ${selected.endpoint} as ${selected.role}` : ''}</h2>
      {!selected && <p className="empty">Select a matrix cell to inspect its cases, requests and responses.</p>}
      {selected && (
        <ul className="case-list">
          {cellCases.map((c) => {
            const r = results.get(c.id);
            return (
              <li key={c.id}>
                <button aria-pressed={activeCase?.id === c.id} onClick={() => onSelectCase(c.id)}>
                  <i className={`pin ${r ? `v-${r.verdict}` : ''} exp-${c.expected}${c.probeField ? ' prop' : ''}${c.category === 'authentication' ? ' auth' : ''}`} aria-hidden />
                  <span className="k">{c.principal} · {c.targetKind}{c.probeField ? ` · ${c.probeField}` : ''}</span>
                  {r ? <span className={`verdict v-${r.verdict}`}>{r.verdict}</span> : <span className="verdict">expect {c.expected}</span>}
                </button>
              </li>
            );
          })}
        </ul>
      )}
      {activeCase && <CaseDetail testCase={activeCase} result={results.get(activeCase.id)} />}
    </aside>
  );
}
