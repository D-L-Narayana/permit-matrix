import { useMemo, useState } from 'react';
import ledgerlyFixture from './fixtures/ledgerly-contract.json';
import helpdeskFixture from './fixtures/helpdesk-contract.json';
import { LIMITS, validateContract } from './engine/contract';
import { generateCases } from './engine/cases';
import { runSuite } from './engine/runner';
import { buildReport, reportToMarkdown } from './engine/report';
import { reportToSarif } from './engine/sarif';
import { lintContract } from './engine/lint';
import { importAny } from './engine/openapi';
import { diffRuns } from './engine/diff';
import type { RunRef } from './engine/diff';
import { ANONYMOUS_ROLE } from './engine/types';
import type { Contract, Flaw, FlawKind, SuiteRun } from './engine/types';
import { CaseLedger, ContractRail, Findings, ImportDialog, Matrix, Toolbar } from './ui';
import { LintPanel } from './features/lint/LintPanel';
import { RunDiffPanel } from './features/diff/RunDiff';

const FLAW_LABELS: Record<FlawKind, string> = {
  'skip-ownership-check': 'skip ownership check',
  'skip-role-check': 'skip role check',
  'accept-all-fields': 'accept all body fields',
  'return-sensitive-fields': 'return sensitive fields',
  'deny-everything': 'deny everything',
  'skip-authentication': 'skip authentication',
};

/** Bundled synthetic demo contracts. Every identity and domain in them is fictional. */
const FIXTURES: { id: string; label: string; raw: unknown }[] = [
  { id: 'ledgerly', label: 'Ledgerly Billing API (synthetic demo)', raw: ledgerlyFixture },
  { id: 'helpdesk', label: 'Helpdesk Desk API (synthetic demo)', raw: helpdeskFixture },
];
/** Pseudo fixture id used while a user-imported contract is loaded. */
const IMPORTED = 'imported';

function loadFixture(raw: unknown): Contract {
  const result = validateContract(raw);
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
const inputsLabel = (contract: Contract, buildId: string, flaws: Flaw[]) =>
  JSON.stringify({ build: buildId, flaws: flaws.map(flawKey).sort(), contract: contract.name + contract.version });
const firstBuildOf = (contract: Contract) => (contract.builds.vulnerable ? 'vulnerable' : Object.keys(contract.builds)[0]);

export default function App() {
  const [fixtureId, setFixtureId] = useState<string>(FIXTURES[0].id);
  const [contract, setContract] = useState<Contract>(() => loadFixture(FIXTURES[0].raw));
  const [buildId, setBuildId] = useState<string>(() => firstBuildOf(contract));
  const [flaws, setFlaws] = useState<Flaw[]>(() => contract.builds[buildId]?.flaws ?? []);
  const [run, setRun] = useState<SuiteRun | null>(null);
  const [runRef, setRunRef] = useState<RunRef | null>(null);
  const [runLabel, setRunLabel] = useState<string>('');
  const [previous, setPrevious] = useState<{ run: SuiteRun; ref: RunRef } | null>(null);
  const [selectedCell, setSelectedCell] = useState<{ endpoint: string; role: string } | null>(null);
  const [selectedCase, setSelectedCase] = useState<string | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [draft, setDraft] = useState('');
  const [importErrors, setImportErrors] = useState<string[]>([]);
  const [importNotes, setImportNotes] = useState<string[]>([]);
  const [notice, setNotice] = useState<string>('Demo data: synthetic Ledgerly contract loaded. Nothing leaves this browser tab.');

  const cases = useMemo(() => generateCases(contract), [contract]);
  const warnings = useMemo(() => lintContract(contract), [contract]);
  const caseById = useMemo(() => new Map(cases.map((c) => [c.id, c])), [cases]);
  const resultById = useMemo(() => new Map((run?.results ?? []).map((r) => [r.caseId, r])), [run]);
  // The anonymous column is synthetic: it is not a contract role, so it is appended only for display.
  const matrixRoles = useMemo(() => [...contract.roles, ANONYMOUS_ROLE], [contract]);
  const stale = run !== null && runLabel !== inputsLabel(contract, buildId, flaws);

  // All possible flaw switches: every seeded flaw in any build of the loaded contract.
  const flawOptions = useMemo(() => {
    const seen = new Map<string, Flaw>();
    for (const build of Object.values(contract.builds)) for (const f of build.flaws) seen.set(flawKey(f), f);
    return [...seen.values()];
  }, [contract]);

  const diff = useMemo(
    () => (run && runRef && previous ? diffRuns(previous.run, run, { before: previous.ref, after: runRef }) : null),
    [run, runRef, previous],
  );

  const fixtureOptions = useMemo(() => {
    const options = FIXTURES.map(({ id, label }) => ({ id, label }));
    return fixtureId === IMPORTED ? [...options, { id: IMPORTED, label: `Imported: ${contract.name} ${contract.version}` }] : options;
  }, [fixtureId, contract]);

  function execute() {
    const result = runSuite(contract, cases, flaws);
    const ref: RunRef = { label: contract.builds[buildId]?.label ?? buildId, build: buildId, flaws: [...flaws] };
    if (run && runRef) setPrevious({ run, ref: runRef });
    setRun(result);
    setRunRef(ref);
    setRunLabel(inputsLabel(contract, buildId, flaws));
    setNotice(`Ran ${result.results.length} cases against "${ref.label}" with ${flaws.length} active flaw(s): ${result.findings.length} finding(s).`);
    if (!selectedCell) setSelectedCell({ endpoint: contract.endpoints[0].id, role: contract.roles[0].id });
  }

  /** Replaces the loaded contract and clears everything derived from the previous one. */
  function loadContract(next: Contract, id: string, message: string) {
    const build = firstBuildOf(next);
    setFixtureId(id);
    setContract(next);
    setBuildId(build);
    setFlaws(next.builds[build]?.flaws ?? []);
    setRun(null);
    setRunRef(null);
    setPrevious(null);
    setRunLabel('');
    setSelectedCell(null);
    setSelectedCase(null);
    setNotice(message);
  }

  function chooseFixture(id: string) {
    const fixture = FIXTURES.find((f) => f.id === id);
    if (!fixture) return;
    const next = loadFixture(fixture.raw);
    loadContract(next, id, `Demo data: synthetic contract "${next.name}" ${next.version} loaded. Nothing leaves this browser tab.`);
  }

  function chooseBuild(id: string) {
    setBuildId(id);
    setFlaws(contract.builds[id]?.flaws ?? []);
  }

  function toggleFlaw(f: Flaw, on: boolean) {
    setFlaws((current) => (on ? [...current.filter((x) => flawKey(x) !== flawKey(f)), f] : current.filter((x) => flawKey(x) !== flawKey(f))));
  }

  function applyImport() {
    const outcome = importAny(draft);
    if (!outcome.ok) {
      setImportErrors(outcome.errors);
      setImportNotes([]);
      return;
    }
    const next = outcome.contract;
    const origin = outcome.format === 'openapi' ? ' (converted from OpenAPI)' : '';
    const notes = outcome.notes.length ? ` ${outcome.notes.length} conversion note(s) are listed in the import dialog.` : '';
    loadContract(next, IMPORTED, `Imported "${next.name}" ${next.version}${origin}: ${next.endpoints.length} endpoints, ${next.roles.length} roles. Run the suite to evaluate it.${notes}`);
    setImportErrors([]);
    setImportNotes(outcome.notes);
    setImportOpen(false);
  }

  async function onFile(file: File | undefined) {
    if (!file) return;
    if (file.size > LIMITS.maxBytes) {
      setImportErrors([`File is ${file.size} bytes; the limit is ${LIMITS.maxBytes}.`]);
      return;
    }
    setDraft(await file.text());
    setImportErrors([]);
  }

  function openImport() {
    setDraft(JSON.stringify(contract, null, 2));
    setImportErrors([]);
    setImportOpen(true);
  }

  function resetDraft() {
    const fixture = FIXTURES.find((f) => f.id === fixtureId) ?? FIXTURES[0];
    setDraft(JSON.stringify(fixture.raw, null, 2));
    setImportErrors([]);
    setImportNotes([]);
  }

  function currentReport() {
    return run ? buildReport(contract, run, { build: buildId, flaws, warnings }) : null;
  }
  function exportJson() {
    const report = currentReport();
    if (report) download(`permitmatrix-${contract.version}-${buildId}.json`, JSON.stringify(report, null, 2), 'application/json');
  }
  function exportMarkdown() {
    const report = currentReport();
    if (report) download(`permitmatrix-${contract.version}-${buildId}.md`, reportToMarkdown(report), 'text/markdown');
  }
  function exportSarif() {
    const report = currentReport();
    if (report) download(`permitmatrix-${contract.version}-${buildId}.sarif.json`, JSON.stringify(reportToSarif(report), null, 2), 'application/sarif+json');
  }

  function jumpToCase(caseId: string) {
    const c = caseById.get(caseId);
    if (!c) return;
    setSelectedCell({ endpoint: c.endpoint, role: c.role });
    setSelectedCase(caseId);
  }

  const cellCases = selectedCell ? cases.filter((c) => c.endpoint === selectedCell.endpoint && c.role === selectedCell.role) : [];
  const activeCase = selectedCase ? caseById.get(selectedCase) : cellCases[0];

  return (
    <div className="app">
      <header>
        <div className="masthead">
          <h1>Permit Matrix <span>· API authorization contract tester</span></h1>
          <span className="contract-id">{contract.name} · v{contract.version} · {contract.servers.join(', ')}</span>
          <span className="badge">Educational prototype · browser-local mock · not a penetration test</span>
        </div>
        <Toolbar
          contract={contract}
          fixtures={fixtureOptions}
          fixtureId={fixtureId}
          onFixture={chooseFixture}
          buildId={buildId}
          onBuild={chooseBuild}
          flawOptions={flawOptions}
          activeFlaws={flaws}
          onToggleFlaw={toggleFlaw}
          flawLabels={FLAW_LABELS}
          caseCount={cases.length}
          run={run}
          stale={stale}
          onRun={execute}
          onImport={openImport}
          onExportJson={exportJson}
          onExportMarkdown={exportMarkdown}
          onExportSarif={exportSarif}
        />
      </header>

      <div className="workspace">
        <ContractRail contract={contract} notice={notice} health={<LintPanel warnings={warnings} compact />} />

        <main className="main">
          <Matrix
            contract={contract}
            roles={matrixRoles}
            cases={cases}
            results={resultById}
            run={run}
            stale={stale}
            selected={selectedCell}
            onSelect={(cell) => {
              setSelectedCell(cell);
              setSelectedCase(null);
            }}
          />
          {diff && <RunDiffPanel diff={diff} onSelectCase={jumpToCase} />}
          <Findings run={run} caseById={caseById} onSelectCase={jumpToCase} />
        </main>

        <CaseLedger selected={selectedCell} cases={cellCases} results={resultById} activeCase={activeCase} onSelectCase={setSelectedCase} />
      </div>

      <footer className="foot">
        Permit Matrix generates role × object × property authorization cases from a local contract and executes them against a deterministic in-browser mock. It never sends traffic to any network host; contracts naming non-local servers are refused. Session state is in memory and resets on refresh — export the report to keep it.
      </footer>

      <ImportDialog
        open={importOpen}
        onOpenChange={setImportOpen}
        draft={draft}
        onDraft={setDraft}
        onFile={(file) => void onFile(file)}
        onReset={resetDraft}
        onValidate={applyImport}
        errors={importErrors}
        notes={importNotes}
        returnFocusId="import-contract"
        maxBytes={LIMITS.maxBytes}
        maxEndpoints={LIMITS.maxEndpoints}
        maxRoles={LIMITS.maxRoles}
      />
    </div>
  );
}
