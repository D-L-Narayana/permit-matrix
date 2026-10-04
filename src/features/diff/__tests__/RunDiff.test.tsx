// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import fixture from '../../../fixtures/ledgerly-contract.json';
import { validateContract } from '../../../engine/contract';
import { generateCases } from '../../../engine/cases';
import { runSuite } from '../../../engine/runner';
import { diffRuns } from '../../../engine/diff';
import type { RunRef } from '../../../engine/diff';
import type { Contract, Flaw } from '../../../engine/types';
import { RunDiffPanel } from '../RunDiff';

afterEach(cleanup);

const contract = (): Contract => {
  const result = validateContract(fixture);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
};
const VULNERABLE: RunRef = { label: fixture.builds.vulnerable.label, build: 'vulnerable', flaws: fixture.builds.vulnerable.flaws as Flaw[] };
const FIXED: RunRef = { label: fixture.builds.fixed.label, build: 'fixed', flaws: [] };

function ledgerlyDiff(direction: 'remediate' | 'same') {
  const c = contract();
  const cases = generateCases(c);
  const vulnerable = runSuite(c, cases, VULNERABLE.flaws);
  const fixed = runSuite(c, cases, []);
  return direction === 'remediate'
    ? diffRuns(vulnerable, fixed, { before: VULNERABLE, after: FIXED })
    : diffRuns(fixed, fixed, { before: FIXED, after: FIXED });
}

describe('RunDiffPanel', () => {
  it('names the section, states the summary, lists fixed findings and exposes every changed case as a button', async () => {
    const onSelectCase = vi.fn();
    const diff = ledgerlyDiff('remediate');
    render(<RunDiffPanel diff={diff} onSelectCase={onSelectCase} />);

    const section = screen.getByRole('region', { name: 'Run comparison' });
    expect(within(section).getByRole('heading', { level: 2, name: 'Changes since previous run' })).toBeTruthy();
    expect(within(section).getByText(`4 findings fixed, 0 introduced; ${diff.summary.improved} cases improved, 0 regressed`)).toBeTruthy();
    expect(within(section).getByRole('heading', { level: 3, name: 'Fixed findings' })).toBeTruthy();
    expect(within(section).queryByRole('heading', { level: 3, name: 'Introduced findings' })).toBeNull();

    const buttons = within(section).getAllByRole('button');
    expect(diff.changed.length).toBeGreaterThan(0);
    expect(buttons).toHaveLength(diff.changed.length);
    for (const b of buttons) expect(b.textContent).toMatch(/^.+\|.+: (bypass|mass-assignment|exposure) → pass$/);

    const first = within(section).getByRole('button', { name: `${diff.changed[0].caseId}: ${diff.changed[0].before} → ${diff.changed[0].after}` });
    await userEvent.click(first);
    expect(onSelectCase).toHaveBeenCalledWith(diff.changed[0].caseId);
  });

  it('collapses to a "No changes" line when the runs are identical', () => {
    render(<RunDiffPanel diff={ledgerlyDiff('same')} onSelectCase={() => undefined} />);
    const section = screen.getByRole('region', { name: 'Run comparison' });
    expect(within(section).getByText(/^No changes/)).toBeTruthy();
    expect(within(section).queryAllByRole('button')).toHaveLength(0);
  });
});
