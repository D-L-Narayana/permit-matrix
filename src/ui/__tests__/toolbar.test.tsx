// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { generateCases } from '../../engine/cases';
import type { FlawKind } from '../../engine/types';
import { Toolbar, flawKey } from '../Toolbar';
import type { ToolbarProps } from '../Toolbar';
import { ledgerly, suite, vulnerableFlaws } from './helpers';

afterEach(cleanup);

const FLAW_LABELS: Record<FlawKind, string> = {
  'skip-ownership-check': 'skip ownership check',
  'skip-role-check': 'skip role check',
  'accept-all-fields': 'accept all body fields',
  'return-sensitive-fields': 'return sensitive fields',
  'deny-everything': 'deny everything',
  'skip-authentication': 'skip authentication',
};

const contract = ledgerly();
const cases = generateCases(contract);
const fixtures = [
  { id: 'ledgerly', label: 'Ledgerly Billing API (synthetic demo)' },
  { id: 'helpdesk', label: 'Helpdesk Desk API (synthetic demo)' },
];

function renderToolbar(overrides: Partial<ToolbarProps> = {}) {
  const props: ToolbarProps = {
    contract, fixtures, fixtureId: 'ledgerly', onFixture: vi.fn(), buildId: 'vulnerable', onBuild: vi.fn(),
    flawOptions: vulnerableFlaws(), activeFlaws: vulnerableFlaws(), onToggleFlaw: vi.fn(), flawLabels: FLAW_LABELS,
    caseCount: cases.length, run: null, stale: false,
    onRun: vi.fn(), onImport: vi.fn(), onExportJson: vi.fn(), onExportMarkdown: vi.fn(), onExportSarif: vi.fn(),
    ...overrides,
  };
  return { ...render(<Toolbar {...props} />), props };
}

const exportButtons = () => ['Export JSON', 'Export memo (.md)', 'Export SARIF'].map((name) => screen.getByRole('button', { name }));

describe('Toolbar', () => {
  it('is the "Run controls" group with a Demo contract select, a Server build select and the flaw switches', () => {
    renderToolbar();
    const group = screen.getByRole('group', { name: 'Run controls' });
    const demo = within(group).getByLabelText('Demo contract');
    expect(demo).toHaveValue('ledgerly');
    expect(within(demo).getAllByRole('option').map((o) => o.textContent)).toEqual(fixtures.map((f) => f.label));
    const build = within(group).getByLabelText('Server build');
    expect(build).toHaveAttribute('id', 'build');
    expect(build).toHaveValue('vulnerable');
    expect(within(build).getAllByRole('option').map((o) => o.textContent)).toEqual(['release/1.4.0 (vulnerable)', 'release/1.4.1 (remediated)']);
    const flaws = within(group).getByRole('group', { name: 'Seeded server flaws' });
    expect(within(flaws).getAllByRole('switch')).toHaveLength(4);
    expect(within(flaws).getByRole('switch', { name: 'get-invoice skip ownership check' })).toBeChecked();
    // The import button is not a Dialog.Trigger; the dialog returns focus to it by id when it closes.
    expect(within(group).getByRole('button', { name: 'Import contract…' })).toHaveAttribute('id', 'import-contract');
  });

  it('run button reads "Run n cases", "Re-run n cases" when stale and "Run again n cases" after a fresh run', () => {
    const { run } = suite(contract, cases);
    const { rerender, props } = renderToolbar();
    expect(screen.getByRole('button', { name: `Run ${cases.length} cases` })).toBeInTheDocument();
    rerender(<Toolbar {...props} run={run} stale />);
    expect(screen.getByRole('button', { name: `Re-run ${cases.length} cases` })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: `Run ${cases.length} cases` })).toBeNull();
    rerender(<Toolbar {...props} run={run} stale={false} />);
    expect(screen.getByRole('button', { name: `Run again ${cases.length} cases` })).toBeInTheDocument();
  });

  it('disables the three exports until there is a fresh (non-stale) run, then forwards clicks', async () => {
    const user = userEvent.setup();
    const { run } = suite(contract, cases);
    const { rerender, props } = renderToolbar();
    expect(exportButtons()).toHaveLength(3);
    for (const b of exportButtons()) expect(b).toBeDisabled();
    rerender(<Toolbar {...props} run={run} stale />);
    for (const b of exportButtons()) expect(b).toBeDisabled();
    rerender(<Toolbar {...props} run={run} stale={false} />);
    for (const b of exportButtons()) expect(b).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Export JSON' }));
    await user.click(screen.getByRole('button', { name: 'Export memo (.md)' }));
    await user.click(screen.getByRole('button', { name: 'Export SARIF' }));
    expect(props.onExportJson).toHaveBeenCalledTimes(1);
    expect(props.onExportMarkdown).toHaveBeenCalledTimes(1);
    expect(props.onExportSarif).toHaveBeenCalledTimes(1);
  });

  it('Demo contract select calls onFixture; Server build select calls onBuild', async () => {
    const user = userEvent.setup();
    const { props } = renderToolbar();
    await user.selectOptions(screen.getByLabelText('Demo contract'), 'helpdesk');
    expect(props.onFixture).toHaveBeenCalledWith('helpdesk');
    await user.selectOptions(screen.getByLabelText('Server build'), 'fixed');
    expect(props.onBuild).toHaveBeenCalledWith('fixed');
  });

  it('flaw switches report toggles with the flaw and its new state; Run and Import fire their callbacks', async () => {
    const user = userEvent.setup();
    const [first] = vulnerableFlaws();
    const { props } = renderToolbar({ activeFlaws: [first] });
    expect(screen.getByRole('switch', { name: 'get-invoice skip ownership check' })).toBeChecked();
    expect(screen.getByRole('switch', { name: 'delete-user skip role check' })).not.toBeChecked();
    await user.click(screen.getByRole('switch', { name: 'delete-user skip role check' }));
    expect(props.onToggleFlaw).toHaveBeenCalledWith({ endpoint: 'delete-user', kind: 'skip-role-check' }, true);
    await user.click(screen.getByRole('switch', { name: 'get-invoice skip ownership check' }));
    expect(props.onToggleFlaw).toHaveBeenCalledWith(first, false);
    await user.click(screen.getByRole('button', { name: `Run ${cases.length} cases` }));
    expect(props.onRun).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole('button', { name: 'Import contract…' }));
    expect(props.onImport).toHaveBeenCalledTimes(1);
    expect(flawKey(first)).toBe('get-invoice:skip-ownership-check');
  });

  it('says so when the contract seeds no flaws', () => {
    renderToolbar({ flawOptions: [], activeFlaws: [] });
    const flaws = screen.getByRole('group', { name: 'Seeded server flaws' });
    expect(flaws).toHaveTextContent('No seeded flaws in this contract.');
    expect(within(flaws).queryAllByRole('switch')).toHaveLength(0);
  });
});
