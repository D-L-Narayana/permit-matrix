// @vitest-environment jsdom
import './setup';
import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import {
  getAllCells,
  getBuildSelect,
  getCell,
  getExportButton,
  getFindingArticles,
  getLedger,
  getLedgerHeading,
  getRunButton,
  getStatus,
  renderApp,
} from './helpers';

describe('App run flow (Ledgerly demo contract)', () => {
  it('starts with the demo contract loaded and nothing run', () => {
    const { container } = renderApp();

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(/^Permit Matrix/);
    expect(getStatus()).toHaveTextContent(/demo/i);
    expect(getRunButton()).toHaveTextContent(/^Run \d+ cases$/);

    // Before a run no cell reports failures, there are no findings and nothing can be exported.
    const cells = getAllCells();
    expect(cells.length).toBeGreaterThan(0);
    for (const cell of cells) expect(cell.getAttribute('aria-label')).not.toMatch(/failed/);
    expect(getFindingArticles(container)).toHaveLength(0);
    expect(getExportButton('json')).toBeDisabled();
    expect(getExportButton('markdown')).toBeDisabled();
  });

  it('runs the vulnerable build, inspects a cell, follows evidence, re-runs remediated and flags stale inputs', async () => {
    const { user, container } = renderApp();

    await user.click(getRunButton());
    expect(getStatus()).toHaveTextContent(/4 finding\(s\)/);
    const articles = getFindingArticles(container);
    expect(articles).toHaveLength(4);

    // Cell → ledger shows the cell's cases with a redacted request and a response.
    await user.click(getCell('GET', '/invoices/{id}', 'Member'));
    expect(getLedgerHeading()).toHaveTextContent('Case ledger · get-invoice as member');
    const pres = Array.from(getLedger().querySelectorAll('pre'));
    expect(pres.length).toBeGreaterThanOrEqual(2);
    const [request, response] = pres;
    expect(request).toHaveTextContent('Bearer [redacted:');
    expect(request.textContent).not.toContain('mock-token-');
    expect(response.textContent?.trim().length ?? 0).toBeGreaterThan(0);

    // Evidence chip on the first finding (get-invoice BOLA) → ledger selects exactly that case.
    const evidence = within(articles[0]).getByRole('button', { name: /^p-admin-1 · peer/ });
    await user.click(evidence);
    expect(getLedgerHeading()).toHaveTextContent('Case ledger · get-invoice as admin');
    const pressed = within(getLedger()).getAllByRole('button', { pressed: true });
    expect(pressed).toHaveLength(1);
    expect(pressed[0]).toHaveTextContent(/^p-admin-1 · peer/);

    // Remediated build → the button announces a re-run → zero findings.
    await user.selectOptions(getBuildSelect(), screen.getByRole('option', { name: 'release/1.4.1 (remediated)' }));
    expect(getRunButton()).toHaveTextContent(/^Re-run \d+ cases$/);
    await user.click(getRunButton());
    expect(screen.getByText(/^No findings\./)).toBeInTheDocument();
    expect(getStatus()).toHaveTextContent(/0 finding\(s\)/);
    expect(getFindingArticles(container)).toHaveLength(0);
    expect(getExportButton('json')).toBeEnabled();

    // Toggling a flaw invalidates the last run until it is repeated.
    const switches = screen.getAllByRole('switch');
    expect(switches.length).toBeGreaterThan(0);
    await user.click(switches[0]);
    expect(switches[0]).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByText(/inputs changed since last run/)).toBeInTheDocument();
    expect(getRunButton()).toHaveTextContent(/^Re-run \d+ cases$/);
    expect(getExportButton('json')).toBeDisabled();
    expect(getExportButton('markdown')).toBeDisabled();
  }, 30_000); // two full suite runs plus several role queries: ~2 s warm, longer when files run in parallel
});
