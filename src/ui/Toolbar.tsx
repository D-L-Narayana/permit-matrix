import * as Switch from '@radix-ui/react-switch';
import type { Contract, Flaw, FlawKind, SuiteRun } from '../engine/types';

export interface ToolbarProps {
  contract: Contract;
  fixtures: { id: string; label: string }[];
  fixtureId: string;
  onFixture: (id: string) => void;
  buildId: string;
  onBuild: (id: string) => void;
  flawOptions: Flaw[];
  activeFlaws: Flaw[];
  onToggleFlaw: (flaw: Flaw, on: boolean) => void;
  flawLabels: Record<FlawKind, string>;
  caseCount: number;
  run: SuiteRun | null;
  stale: boolean;
  onRun: () => void;
  onImport: () => void;
  onExportJson: () => void;
  onExportMarkdown: () => void;
  onExportSarif: () => void;
}

/** Identity of a flaw switch; the same key the app uses to de-duplicate active flaws. */
export const flawKey = (f: Flaw): string => `${f.endpoint}:${f.kind}`;

export function Toolbar({
  contract, fixtures, fixtureId, onFixture, buildId, onBuild, flawOptions, activeFlaws, onToggleFlaw, flawLabels,
  caseCount, run, stale, onRun, onImport, onExportJson, onExportMarkdown, onExportSarif,
}: ToolbarProps) {
  const active = new Set(activeFlaws.map(flawKey));
  const exportsDisabled = !run || stale;
  // An imported contract is not one of the shipped demos; keep the select honest instead of showing the first demo.
  const imported = !fixtures.some((f) => f.id === fixtureId);
  return (
    <div className="toolbar" role="group" aria-label="Run controls">
      <div className="group">
        <label className="inline" htmlFor="fixture">Demo contract</label>
        <select id="fixture" value={fixtureId} onChange={(e) => onFixture(e.target.value)}>
          {fixtures.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
          {imported && <option value={fixtureId}>Imported contract</option>}
        </select>
      </div>
      <div className="group">
        <label className="inline" htmlFor="build">Server build</label>
        <select id="build" value={buildId} onChange={(e) => onBuild(e.target.value)}>
          {Object.entries(contract.builds).map(([id, b]) => <option key={id} value={id}>{b.label}</option>)}
        </select>
      </div>
      <div className="flaws" role="group" aria-label="Seeded server flaws">
        {flawOptions.length === 0 && <span className="flaw">No seeded flaws in this contract.</span>}
        {flawOptions.map((f) => {
          const id = `flaw-${flawKey(f)}`;
          const on = active.has(flawKey(f));
          return (
            <span className="flaw" key={id}>
              <Switch.Root id={id} className="switch" checked={on} onCheckedChange={(v) => onToggleFlaw(f, v)}>
                <Switch.Thumb className="thumb" />
              </Switch.Root>
              <label htmlFor={id}><code>{f.endpoint}</code> {flawLabels[f.kind]}</label>
            </span>
          );
        })}
      </div>
      <span className="spacer" />
      {/* Not a Dialog.Trigger: the ImportDialog returns focus here by id (returnFocusId="import-contract") when it closes. */}
      <button id="import-contract" className="btn" onClick={onImport}>Import contract…</button>
      <button className="btn primary" onClick={onRun}>{run ? (stale ? 'Re-run' : 'Run again') : 'Run'} {caseCount} cases</button>
      <button className="btn" onClick={onExportJson} disabled={exportsDisabled}>Export JSON</button>
      <button className="btn" onClick={onExportMarkdown} disabled={exportsDisabled}>Export memo (.md)</button>
      <button className="btn" onClick={onExportSarif} disabled={exportsDisabled}>Export SARIF</button>
    </div>
  );
}
