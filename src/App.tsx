import { useMemo, useState } from 'react';
import * as Switch from '@radix-ui/react-switch';
import * as Dialog from '@radix-ui/react-dialog';
import fixture from './fixtures/ledgerly-contract.json';
import { LIMITS, parseContract, validateContract } from './engine/contract';
import { generateCases } from './engine/cases';
import { runSuite } from './engine/runner';
import { buildReport, redactHeaders, reportToMarkdown } from './engine/report';
import type { CaseResult, Contract, Flaw, FlawKind, SuiteRun, TestCase } from './engine/types';

const FLAW_LABELS: Record<FlawKind, string> = {
  'skip-ownership-check': 'skip ownership check',
  'skip-role-check': 'skip role check',
  'accept-all-fields': 'accept all body fields',
  'return-sensitive-fields': 'return sensitive fields',
  'deny-everything': 'deny everything',
};

function loadFixture(): Contract {
  const result = validateContract(fixture);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
}

function download(name: string, text: string, type: string) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

const flawKey = (f: Flaw) => `${f.endpoint}:${f.kind}`;

export default function App() {
  const [contract, setContract] = useState<Contract>(loadFixture);
  const [buildId, setBuildId] = useState<string>(() => (contract.builds.vulnerable ? 'vulnerable' : 'fixed'));
  const [flaws, setFlaws] = useState<Flaw[]>(() => contract.builds[buildId]?.flaws ?? []);
  const [run, setRun] = useState<SuiteRun | null>(null);
  const [runLabel, setRunLabel] = useState<string>('');
  const [selectedCell, setSelectedCell] = useState<{ endpoint: string; role: string } | null>(null);
  const [selectedCase, setSelectedCase] = useState<string | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [draft, setDraft] = useState('');
  const [importErrors, setImportErrors] = useState<string[]>([]);
  const [notice, setNotice] = useState<string>('Demo data: synthetic Ledgerly contract loaded. Nothing leaves this browser tab.');

  const cases = useMemo(() => generateCases(contract), [contract]);
  const caseById = useMemo(() => new Map(cases.map((c) => [c.id, c])), [cases]);
  const resultById = useMemo(() => new Map((run?.results ?? []).map((r) => [r.caseId, r])), [run]);
  const stale = run !== null && runLabel !== JSON.stringify({ build: buildId, flaws: flaws.map(flawKey).sort(), contract: contract.name + contract.version });

  // All possible flaw switches: every seeded flaw in any build, plus the deny-everything regression probe per endpoint.
  const flawOptions = useMemo(() => {
    const seen = new Map<string, Flaw>();
    for (const build of Object.values(contract.builds)) for (const f of build.flaws) seen.set(flawKey(f), f);
    return [...seen.values()];
  }, [contract]);

  function execute() {
    const result = runSuite(contract, cases, flaws);
    setRun(result);
    setRunLabel(JSON.stringify({ build: buildId, flaws: flaws.map(flawKey).sort(), contract: contract.name + contract.version }));
    setNotice(`Ran ${result.results.length} cases against "${contract.builds[buildId]?.label ?? buildId}" with ${flaws.length} active flaw(s): ${result.findings.length} finding(s).`);
    if (!selectedCell) setSelectedCell({ endpoint: contract.endpoints[0].id, role: contract.roles[0].id });
  }

  function chooseBuild(id: string) {
    setBuildId(id);
    setFlaws(contract.builds[id]?.flaws ?? []);
  }

  function toggleFlaw(f: Flaw, on: boolean) {
    setFlaws((current) => (on ? [...current.filter((x) => flawKey(x) !== flawKey(f)), f] : current.filter((x) => flawKey(x) !== flawKey(f))));
  }

  function applyImport() {
    const parsed = parseContract(draft);
    if (!parsed.ok) { setImportErrors(parsed.errors); return; }
    setContract(parsed.contract);
    const firstBuild = parsed.contract.builds.vulnerable ? 'vulnerable' : Object.keys(parsed.contract.builds)[0];
    setBuildId(firstBuild);
    setFlaws(parsed.contract.builds[firstBuild]?.flaws ?? []);
    setRun(null);
    setSelectedCell(null);
    setSelectedCase(null);
    setImportErrors([]);
    setImportOpen(false);
    setNotice(`Imported "${parsed.contract.name}" ${parsed.contract.version}: ${parsed.contract.endpoints.length} endpoints, ${parsed.contract.roles.length} roles. Run the suite to evaluate it.`);
  }

  async function onFile(file: File | undefined) {
    if (!file) return;
    if (file.size > LIMITS.maxBytes) { setImportErrors([`File is ${file.size} bytes; the limit is ${LIMITS.maxBytes}.`]); return; }
    setDraft(await file.text());
    setImportErrors([]);
  }

  function exportJson() {
    if (!run) return;
    const report = buildReport(contract, run, { build: buildId });
    download(`permitmatrix-${contract.version}-${buildId}.json`, JSON.stringify(report, null, 2), 'application/json');
  }
  function exportMarkdown() {
    if (!run) return;
    const report = buildReport(contract, run, { build: buildId });
    download(`permitmatrix-${contract.version}-${buildId}.md`, reportToMarkdown(report), 'text/markdown');
  }

  const cellCases = selectedCell ? cases.filter((c) => c.endpoint === selectedCell.endpoint && c.role === selectedCell.role) : [];
  const activeCase = selectedCase ? caseById.get(selectedCase) : cellCases[0];
  const activeResult = activeCase ? resultById.get(activeCase.id) : undefined;

  return (
    <div className="app">
      <header>
        <div className="masthead">
          <h1>Permit Matrix <span>· API authorization contract tester</span></h1>
          <span className="contract-id">{contract.name} · v{contract.version} · {contract.servers.join(', ')}</span>
          <span className="badge">Educational prototype · browser-local mock · not a penetration test</span>
        </div>
        <div className="toolbar" role="group" aria-label="Run controls">
          <div className="group">
            <label className="inline" htmlFor="build">Server build</label>
            <select id="build" value={buildId} onChange={(e) => chooseBuild(e.target.value)}>
              {Object.entries(contract.builds).map(([id, b]) => <option key={id} value={id}>{b.label}</option>)}
            </select>
          </div>
          <div className="flaws" role="group" aria-label="Seeded server flaws">
            {flawOptions.length === 0 && <span className="flaw">No seeded flaws in this contract.</span>}
            {flawOptions.map((f) => {
              const id = `flaw-${flawKey(f)}`;
              const on = flaws.some((x) => flawKey(x) === flawKey(f));
              return (
                <span className="flaw" key={id}>
                  <Switch.Root id={id} className="switch" checked={on} onCheckedChange={(v) => toggleFlaw(f, v)}>
                    <Switch.Thumb className="thumb" />
                  </Switch.Root>
                  <label htmlFor={id}><code>{f.endpoint}</code> {FLAW_LABELS[f.kind]}</label>
                </span>
              );
            })}
          </div>
          <span className="spacer" />
          <button className="btn" onClick={() => { setDraft(JSON.stringify(contract, null, 2)); setImportErrors([]); setImportOpen(true); }}>Import contract…</button>
          <button className="btn primary" onClick={execute}>{run ? (stale ? 'Re-run' : 'Run again') : 'Run'} {cases.length} cases</button>
          <button className="btn" onClick={exportJson} disabled={!run || stale}>Export JSON</button>
          <button className="btn" onClick={exportMarkdown} disabled={!run || stale}>Export memo (.md)</button>
        </div>
      </header>

      <div className="workspace">
        <aside className="rail" aria-label="Contract outline">
          <h2 className="section">Roles</h2>
          <ul>{contract.roles.map((r) => <li key={r.id}><code>{r.id}</code><span className="muted">{r.label}</span></li>)}</ul>
          <h2 className="section">Principals</h2>
          <ul>{contract.principals.map((p) => <li key={p.id}><code>{p.id}</code><span className="muted">{p.role} · {p.tenant}</span></li>)}</ul>
          <h2 className="section">Endpoints</h2>
          <ul>{contract.endpoints.map((e) => (
            <li key={e.id}><span className={`pill method-${e.method}`}>{e.method}</span><code>{e.path}</code></li>
          ))}</ul>
          <h2 className="section">Resources</h2>
          <ul>{contract.resources.map((r) => <li key={r.id}><code>{r.id}</code><span className="muted">{r.records.length} records</span></li>)}</ul>
          <p className="notice" role="status">{notice}</p>
        </aside>

        <main className="main">
          <h2 className="section">Role × endpoint matrix {run ? `· ${run.results.length} cases` : '· not yet run'}{stale ? ' · inputs changed since last run' : ''}</h2>
          {!run && <p className="empty">Press <strong>Run {cases.length} cases</strong> to evaluate the selected server build. Each cell will show a pin per target: own record, a peer's record in the same tenant, and a record in another tenant, plus a dot per property probe.</p>}
          <div className="matrix-wrap">
            <table className="matrix">
              <caption className="sr-only">Authorization test results by endpoint and role</caption>
              <thead>
                <tr>
                  <th scope="col">Endpoint</th>
                  {contract.roles.map((r) => <th key={r.id} scope="col">{r.label}</th>)}
                </tr>
              </thead>
              <tbody>
                {contract.endpoints.map((e) => (
                  <tr key={e.id}>
                    <th scope="row">
                      <span className="path"><span className={`pill method-${e.method}`}>{e.method}</span> {e.path}</span>
                      <span className="rule">roles: {e.access.roles.join(', ')} · scope: {e.access.ownership}{e.writableFields ? ` · writable: ${e.writableFields.join(', ')}` : ''}{e.sensitiveFields ? ` · sensitive: ${e.sensitiveFields.join(', ')}` : ''}</span>
                    </th>
                    {contract.roles.map((r) => {
                      const cellSet = cases.filter((c) => c.endpoint === e.id && c.role === r.id);
                      const failed = cellSet.filter((c) => { const v = resultById.get(c.id)?.verdict; return v && v !== 'pass'; }).length;
                      const pressed = selectedCell?.endpoint === e.id && selectedCell.role === r.id;
                      return (
                        <td key={r.id}>
                          <button
                            className="cell"
                            aria-pressed={pressed}
                            aria-label={`${e.method} ${e.path} as ${r.label}: ${cellSet.length} cases${run ? `, ${failed} failed` : ''}`}
                            onClick={() => { setSelectedCell({ endpoint: e.id, role: r.id }); setSelectedCase(null); }}
                          >
                            <Pins cases={cellSet} results={resultById} />
                            <span className={`count${failed ? ' bad' : ''}`}>{run ? `${cellSet.length - failed}/${cellSet.length} ok` : `${cellSet.length} cases`}</span>
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="legend" aria-label="Legend">
            <span><i className="pin v-pass exp-allow" /> allowed as expected</span>
            <span><i className="pin v-pass exp-deny" /> denied as expected</span>
            <span><i className="pin v-bypass" /> bypass</span>
            <span><i className="pin v-over-deny" /> over-deny</span>
            <span><i className="pin v-exposure" /> exposure</span>
            <span><i className="pin v-mass-assignment" /> mass assignment</span>
            <span><i className="pin absent" /> no record for this target</span>
            <span>pins: own · peer · cross-tenant | property probes</span>
          </p>

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
                <div className="evidence" aria-label="Evidence cases">
                  {f.evidenceCases.slice(0, 12).map((id) => {
                    const c = caseById.get(id)!;
                    return <button key={id} onClick={() => { setSelectedCell({ endpoint: c.endpoint, role: c.role }); setSelectedCase(id); }}>{c.principal} · {c.targetKind}{c.probeField ? ` · ${c.probeField}` : ''}</button>;
                  })}
                  {f.evidenceCases.length > 12 && <span className="meta">+{f.evidenceCases.length - 12} more</span>}
                </div>
              </article>
            ))}
          </div>
        </main>

        <aside className="ledger" aria-label="Case ledger">
          <h2 className="section">Case ledger {selectedCell ? `· ${selectedCell.endpoint} as ${selectedCell.role}` : ''}</h2>
          {!selectedCell && <p className="empty">Select a matrix cell to inspect its cases, requests and responses.</p>}
          {selectedCell && (
            <ul className="case-list">
              {cellCases.map((c) => {
                const r = resultById.get(c.id);
                return (
                  <li key={c.id}>
                    <button aria-pressed={activeCase?.id === c.id} onClick={() => setSelectedCase(c.id)}>
                      <i className={`pin ${r ? `v-${r.verdict}` : ''} exp-${c.expected}${c.probeField ? ' prop' : ''}`} aria-hidden />
                      <span className="k">{c.principal} · {c.targetKind}{c.probeField ? ` · ${c.probeField}` : ''}</span>
                      {r ? <span className={`verdict v-${r.verdict}`}>{r.verdict}</span> : <span className="verdict">expect {c.expected}</span>}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
          {activeCase && <CaseDetail testCase={activeCase} result={activeResult} />}
        </aside>
      </div>

      <footer className="foot">
        Permit Matrix generates role × object × property authorization cases from a local contract and executes them against a deterministic in-browser mock. It never sends traffic to any network host; contracts naming non-local servers are refused. Session state is in memory and resets on refresh — export the report to keep it.
      </footer>

      <Dialog.Root open={importOpen} onOpenChange={setImportOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="overlay" />
          <Dialog.Content className="dialog" aria-describedby="import-desc">
            <Dialog.Title asChild><h2>Import a contract</h2></Dialog.Title>
            <Dialog.Description id="import-desc">Paste or choose a <code>permitmatrix.contract/1</code> JSON file (max {Math.round(LIMITS.maxBytes / 1024)} KB, {LIMITS.maxEndpoints} endpoints, {LIMITS.maxRoles} roles). Servers must be <code>mock://</code> or localhost; anything else is refused. Use synthetic data only.</Dialog.Description>
            <label className="sr-only" htmlFor="contract-text">Contract JSON</label>
            <textarea id="contract-text" value={draft} onChange={(e) => setDraft(e.target.value)} spellCheck={false} />
            <div className="row">
              <label className="btn small" htmlFor="contract-file">Choose file…<input id="contract-file" type="file" accept="application/json,.json" className="sr-only" onChange={(e) => void onFile(e.target.files?.[0])} /></label>
              <button className="btn small" onClick={() => { setDraft(JSON.stringify(fixture, null, 2)); setImportErrors([]); }}>Reset to demo contract</button>
              <span className="spacer" />
              <Dialog.Close asChild><button className="btn small">Cancel</button></Dialog.Close>
              <button className="btn small primary" onClick={applyImport}>Validate and load</button>
            </div>
            {importErrors.length > 0 && (
              <ul className="errors" role="alert">{importErrors.slice(0, 12).map((e, i) => <li key={i}>{e}</li>)}{importErrors.length > 12 && <li>+{importErrors.length - 12} more</li>}</ul>
            )}
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}

function Pins({ cases, results }: { cases: TestCase[]; results: Map<string, CaseResult> }) {
  const base = ['own', 'peer', 'cross-tenant', 'collection'] as const;
  const objectCases = cases.filter((c) => !c.probeField);
  const propCases = cases.filter((c) => c.probeField);
  const isCollection = objectCases.length > 0 && objectCases.every((c) => c.targetKind === 'collection');
  return (
    <span className="pins" aria-hidden>
      {base.map((kind) => {
        const c = objectCases.find((x) => x.targetKind === kind);
        if (!c) return kind === 'collection' || isCollection ? null : <i key={kind} className="pin absent" title={`no ${kind} record`} />;
        const r = results.get(c.id);
        return <i key={kind} className={`pin ${r ? `v-${r.verdict}` : ''} exp-${c.expected}`} title={`${kind}: ${r?.verdict ?? `expect ${c.expected}`}`} />;
      })}
      {propCases.length > 0 && <span className="sep" />}
      {propCases.map((c) => {
        const r = results.get(c.id);
        return <i key={c.id} className={`pin prop ${r ? `v-${r.verdict}` : ''} exp-allow`} title={`${c.probeField}: ${r?.verdict ?? 'pending'}`} />;
      })}
    </span>
  );
}

function CaseDetail({ testCase, result }: { testCase: TestCase; result?: CaseResult }) {
  return (
    <div className="exchange">
      <p className="why"><strong>Expectation: {testCase.expected}.</strong> {testCase.rationale}</p>
      {result ? (
        <>
          <p className="why"><strong>Verdict: {result.verdict}.</strong> {result.explanation}</p>
          <div>
            <div className="label"><span>Request</span><span>Authorization header redacted</span></div>
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
