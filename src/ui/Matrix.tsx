import { useMemo, useRef } from 'react';
import type { KeyboardEvent } from 'react';
import { ANONYMOUS_ROLE } from '../engine/types';
import type { CaseResult, Contract, Role, SuiteRun, TestCase } from '../engine/types';
import { Pins } from './Pins';

export interface MatrixCell {
  endpoint: string;
  role: string;
}

export interface MatrixProps {
  contract: Contract;
  /** Column order; the app passes `[...contract.roles, ANONYMOUS_ROLE]`. */
  roles: Role[];
  cases: TestCase[];
  results: Map<string, CaseResult>;
  run: SuiteRun | null;
  stale: boolean;
  selected: MatrixCell | null;
  onSelect: (cell: MatrixCell) => void;
}

// Endpoint and role ids are validated against /^[a-z0-9][a-z0-9._-]*$/, so "|" cannot occur inside either.
const cellKey = (endpoint: string, role: string) => `${endpoint}|${role}`;

export function Matrix({ contract, roles, cases, results, run, stale, selected, onSelect }: MatrixProps) {
  const tableRef = useRef<HTMLTableElement>(null);

  const byCell = useMemo(() => {
    const map = new Map<string, TestCase[]>();
    for (const c of cases) {
      const key = cellKey(c.endpoint, c.role);
      const list = map.get(key);
      if (list) list.push(c);
      else map.set(key, [c]);
    }
    return map;
  }, [cases]);

  // Roving tabindex: exactly one cell is a tab stop — the selected cell, or the first cell when nothing is
  // selected or the selection points outside the current table (for example after a contract import).
  const active = selected && contract.endpoints.some((e) => e.id === selected.endpoint) && roles.some((r) => r.id === selected.role) ? selected : null;
  const isTabStop = (endpointId: string, roleId: string, row: number, col: number): boolean =>
    active ? active.endpoint === endpointId && active.role === roleId : row === 0 && col === 0;

  const focusCell = (row: number, col: number) => {
    tableRef.current?.querySelector<HTMLButtonElement>(`button.cell[data-row="${row}"][data-col="${col}"]`)?.focus();
  };

  // Arrow keys move focus (clamped at the edges); Home/End jump within the row, Ctrl+Home/End across the grid.
  // Enter and Space are left to the native button, so they select the focused cell.
  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>, row: number, col: number) => {
    const lastRow = contract.endpoints.length - 1;
    const lastCol = roles.length - 1;
    const jump = event.ctrlKey || event.metaKey;
    let next: [number, number];
    switch (event.key) {
      case 'ArrowLeft': next = [row, Math.max(0, col - 1)]; break;
      case 'ArrowRight': next = [row, Math.min(lastCol, col + 1)]; break;
      case 'ArrowUp': next = [Math.max(0, row - 1), col]; break;
      case 'ArrowDown': next = [Math.min(lastRow, row + 1), col]; break;
      case 'Home': next = jump ? [0, 0] : [row, 0]; break;
      case 'End': next = jump ? [lastRow, lastCol] : [row, lastCol]; break;
      default: return;
    }
    event.preventDefault(); // the scrolling wrapper must not pan while the user navigates cells
    if (next[0] !== row || next[1] !== col) focusCell(next[0], next[1]);
  };

  return (
    <>
      <h2 className="section">Role × endpoint matrix {run ? `· ${run.results.length} cases` : '· not yet run'}{stale ? ' · inputs changed since last run' : ''}</h2>
      {!run && (
        <p className="empty">
          Press <strong>Run {cases.length} cases</strong> to evaluate the selected server build. Each cell shows a pin per target — own record, a peer's record in the same tenant, a record in another tenant — or a single pin for collection, create and no-credentials calls, plus a dot per property probe.
        </p>
      )}
      <div className="matrix-wrap">
        <table className="matrix" ref={tableRef}>
          <caption className="sr-only">Authorization test results by endpoint and role</caption>
          <thead>
            <tr>
              <th scope="col">Endpoint</th>
              {roles.map((r) => (
                <th key={r.id} scope="col" className={r.id === ANONYMOUS_ROLE.id ? 'anon' : undefined}>{r.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {contract.endpoints.map((e, row) => (
              <tr key={e.id}>
                <th scope="row">
                  <span className="path"><span className={`pill method-${e.method}`}>{e.method}</span> {e.path}</span>
                  <span className="rule">roles: {e.access.roles.join(', ')} · scope: {e.access.ownership}{e.writableFields ? ` · writable: ${e.writableFields.join(', ')}` : ''}{e.sensitiveFields ? ` · sensitive: ${e.sensitiveFields.join(', ')}` : ''}</span>
                </th>
                {roles.map((r, col) => {
                  const cellSet = byCell.get(cellKey(e.id, r.id)) ?? [];
                  const failed = cellSet.filter((c) => { const v = results.get(c.id)?.verdict; return v !== undefined && v !== 'pass'; }).length;
                  const pressed = selected?.endpoint === e.id && selected.role === r.id;
                  const anon = r.id === ANONYMOUS_ROLE.id;
                  return (
                    <td key={r.id} className={anon ? 'anon' : undefined}>
                      <button
                        className="cell"
                        aria-pressed={pressed}
                        aria-label={`${e.method} ${e.path} as ${r.label}: ${cellSet.length} cases${run ? `, ${failed} failed` : ''}`}
                        tabIndex={isTabStop(e.id, r.id, row, col) ? 0 : -1}
                        data-row={row}
                        data-col={col}
                        onClick={() => onSelect({ endpoint: e.id, role: r.id })}
                        onKeyDown={(event) => onKeyDown(event, row, col)}
                      >
                        {cellSet.length === 0 ? (
                          <span className="none">no cases</span>
                        ) : (
                          <>
                            <Pins cases={cellSet} results={results} />
                            <span className={`count${failed ? ' bad' : ''}`}>{run ? `${cellSet.length - failed}/${cellSet.length} ok` : `${cellSet.length} cases`}</span>
                          </>
                        )}
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
        <span><i className="pin auth v-pass exp-deny" /> rejected without credentials as expected</span>
        <span><i className="pin v-bypass" /> bypass</span>
        <span><i className="pin v-over-deny" /> over-deny</span>
        <span><i className="pin v-exposure" /> exposure</span>
        <span><i className="pin v-mass-assignment" /> mass assignment</span>
        <span><i className="pin v-error" /> error (could not be evaluated)</span>
        <span><i className="pin absent" /> no record for this target</span>
        <span>pins: own · peer · cross-tenant | property probes · one pin for collection, create and no-credentials calls</span>
      </p>
    </>
  );
}
