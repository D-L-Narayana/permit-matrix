// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { generateCases } from '../../engine/cases';
import { ANONYMOUS_ROLE } from '../../engine/types';
import type { CaseResult, SuiteRun } from '../../engine/types';
import { Matrix } from '../Matrix';
import type { MatrixProps } from '../Matrix';
import { cellCases, ledgerly, matrixRoles, suite, vulnerableFlaws } from './helpers';

afterEach(cleanup);

const contract = ledgerly();
const cases = generateCases(contract);
const roles = matrixRoles(contract);

function renderMatrix(overrides: Partial<MatrixProps> = {}) {
  const props: MatrixProps = { contract, roles, cases, results: new Map(), run: null, stale: false, selected: null, onSelect: vi.fn(), ...overrides };
  return { ...render(<Matrix {...props} />), props };
}

/** The accessible name the stable contract promises for a cell, derived from the same inputs the component gets. */
function cellName(endpointId: string, roleId: string, run: SuiteRun | null = null, results: Map<string, CaseResult> = new Map(), pool = cases): string {
  const endpoint = contract.endpoints.find((e) => e.id === endpointId)!;
  const role = roles.find((r) => r.id === roleId)!;
  const set = cellCases(pool, endpointId, roleId);
  const failed = set.filter((c) => { const v = results.get(c.id)?.verdict; return v !== undefined && v !== 'pass'; }).length;
  return `${endpoint.method} ${endpoint.path} as ${role.label}: ${set.length} cases${run ? `, ${failed} failed` : ''}`;
}

const allCells = (container: HTMLElement) => [...container.querySelectorAll<HTMLButtonElement>('button.cell')];
const activeName = () => document.activeElement?.getAttribute('aria-label');

describe('Matrix', () => {
  it('renders a captioned table with one column header per role, including "Anonymous (no credentials)"', () => {
    const { container } = renderMatrix();
    expect(container.querySelector('caption')).toHaveTextContent('Authorization test results by endpoint and role');
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Endpoint', 'Admin', 'Tenant manager', 'Member', 'Anonymous (no credentials)']);
    expect(screen.getAllByRole('rowheader')).toHaveLength(contract.endpoints.length);
    expect(allCells(container)).toHaveLength(contract.endpoints.length * roles.length);
  });

  it('names every cell "{METHOD} {path} as {roleLabel}: {n} cases" and marks cells that have no cases', () => {
    // Drop any anonymous-row cases so the last column is guaranteed empty whatever the generator emits.
    const pool = cases.filter((c) => c.role !== ANONYMOUS_ROLE.id);
    const { container } = renderMatrix({ cases: pool });
    expect(screen.getByRole('button', { name: cellName('list-invoices', 'admin', null, new Map(), pool) })).toBeInTheDocument();
    expect(cellName('get-invoice', 'member', null, new Map(), pool)).toMatch(/^GET \/invoices\/\{id\} as Member: [1-9]\d* cases$/);
    const anonymous = screen.getByRole('button', { name: 'GET /invoices as Anonymous (no credentials): 0 cases' });
    expect(anonymous).toHaveTextContent('no cases');
    expect(anonymous.querySelector('.pin')).toBeNull();
    expect(container.querySelectorAll('.cell .none')).toHaveLength(contract.endpoints.length);
    // Populated cells carry pins and a count instead.
    const populated = screen.getByRole('button', { name: cellName('get-invoice', 'member', null, new Map(), pool) });
    expect(populated.querySelectorAll('.pin').length).toBeGreaterThan(0);
    expect(populated.querySelector('.count')).toHaveTextContent(/^\d+ cases$/);
  });

  it('appends ", {f} failed" to cell names after a run and flags failing counts', () => {
    const { run, results } = suite(contract, cases, vulnerableFlaws());
    renderMatrix({ run, results });
    const name = cellName('get-invoice', 'member', run, results);
    expect(name).toMatch(/, [1-9]\d* failed$/); // the seeded BOLA flaw makes this cell fail
    const cell = screen.getByRole('button', { name });
    expect(cell.querySelector('.count')).toHaveClass('bad');
    expect(screen.getByRole('button', { name: cellName('list-invoices', 'admin', run, results) })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent(`Role × endpoint matrix · ${run.results.length} cases`);
  });

  it('roving tabindex: exactly one cell is a tab stop — the first cell when nothing is selected', () => {
    const { container } = renderMatrix();
    const stops = allCells(container).filter((b) => b.tabIndex === 0);
    expect(stops).toHaveLength(1);
    expect(stops[0]).toHaveAttribute('aria-label', cellName('list-invoices', 'admin'));
    expect(allCells(container).filter((b) => b.tabIndex === -1)).toHaveLength(contract.endpoints.length * roles.length - 1);
  });

  it('roving tabindex: the selected cell is the tab stop and the only aria-pressed cell', () => {
    const { container } = renderMatrix({ selected: { endpoint: 'get-user', role: 'member' } });
    const stops = allCells(container).filter((b) => b.tabIndex === 0);
    expect(stops).toHaveLength(1);
    expect(stops[0]).toHaveAttribute('aria-label', cellName('get-user', 'member'));
    expect(stops[0]).toHaveAttribute('aria-pressed', 'true');
    expect(allCells(container).filter((b) => b.getAttribute('aria-pressed') === 'true')).toHaveLength(1);
  });

  it('Arrow keys move focus between cells (clamped at the edges); Home/End jump within the row', async () => {
    const user = userEvent.setup();
    const { container } = renderMatrix();
    allCells(container)[0].focus();
    expect(activeName()).toBe(cellName('list-invoices', 'admin'));
    await user.keyboard('{ArrowRight}');
    expect(activeName()).toBe(cellName('list-invoices', 'manager'));
    await user.keyboard('{ArrowDown}');
    expect(activeName()).toBe(cellName('get-invoice', 'manager'));
    await user.keyboard('{End}');
    expect(activeName()).toBe(cellName('get-invoice', 'anonymous'));
    await user.keyboard('{ArrowRight}');
    expect(activeName()).toBe(cellName('get-invoice', 'anonymous'));
    await user.keyboard('{Home}');
    expect(activeName()).toBe(cellName('get-invoice', 'admin'));
    await user.keyboard('{ArrowLeft}');
    expect(activeName()).toBe(cellName('get-invoice', 'admin'));
    await user.keyboard('{ArrowUp}');
    expect(activeName()).toBe(cellName('list-invoices', 'admin'));
    await user.keyboard('{ArrowUp}');
    expect(activeName()).toBe(cellName('list-invoices', 'admin'));
    await user.keyboard('{Control>}{End}{/Control}');
    expect(activeName()).toBe(cellName('delete-user', 'anonymous'));
    await user.keyboard('{Control>}{Home}{/Control}');
    expect(activeName()).toBe(cellName('list-invoices', 'admin'));
  });

  it('clicking a cell reports its endpoint and role', async () => {
    const user = userEvent.setup();
    const { props } = renderMatrix();
    await user.click(screen.getByRole('button', { name: cellName('patch-invoice', 'manager') }));
    expect(props.onSelect).toHaveBeenCalledTimes(1);
    expect(props.onSelect).toHaveBeenCalledWith({ endpoint: 'patch-invoice', role: 'manager' });
  });

  it('shows the pre-run empty state, the legend, and the stale suffix', () => {
    const { rerender, props } = renderMatrix();
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('Role × endpoint matrix · not yet run');
    expect(screen.getByText(/Press/)).toHaveTextContent(`Run ${cases.length} cases`);
    const legend = screen.getByLabelText('Legend');
    expect(legend).toHaveTextContent('allowed as expected');
    expect(legend.querySelector('.pin.auth')).not.toBeNull();
    const { run, results } = suite(contract, cases);
    rerender(<Matrix {...props} run={run} results={results} stale />);
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('inputs changed since last run');
    expect(screen.queryByText(/Press/)).toBeNull();
  });
});
