// @vitest-environment jsdom
import './setup';
import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import fixture from '../fixtures/ledgerly-contract.json';
import { getContractTextarea, getRunButton, getStatus, openImportDialog, renderApp, setTextareaValue } from './helpers';
import type { AppRender } from './helpers';

const externalServer = JSON.stringify({ ...fixture, servers: ['https://api.victim.example'] });
const duplicateRoute = JSON.stringify({
  ...fixture,
  endpoints: [...fixture.endpoints, { ...fixture.endpoints[1], id: 'get-invoice-copy' }],
});
const modified = JSON.stringify({ ...fixture, name: 'Modified Billing API (synthetic demo)', version: '9.9.9' });

async function submit(app: AppRender, text: string): Promise<HTMLElement> {
  const dialog = await openImportDialog(app.user);
  setTextareaValue(getContractTextarea(dialog), text);
  await app.user.click(within(dialog).getByRole('button', { name: 'Validate and load' }));
  return dialog;
}

describe('Import dialog', () => {
  it('opens pre-filled with the current contract', async () => {
    const app = renderApp();
    const dialog = await openImportDialog(app.user);
    expect(dialog).toHaveTextContent('Import a contract');
    expect(getContractTextarea(dialog).value).toContain('Ledgerly');
  });

  it('refuses a contract that targets an external server and keeps the dialog open', async () => {
    const app = renderApp();
    await submit(app, externalServer);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('External target refused');
    expect(screen.getByRole('dialog', { name: 'Import a contract' })).toBeInTheDocument();
  });

  it('refuses a duplicated GET /invoices/{id} route', async () => {
    const app = renderApp();
    await submit(app, duplicateRoute);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('duplicate route');
    expect(screen.getByRole('dialog', { name: 'Import a contract' })).toBeInTheDocument();
  });

  it('loads a valid contract, closes the dialog and announces the import', async () => {
    const app = renderApp();
    await submit(app, modified);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(getStatus()).toHaveTextContent(/Imported/));
    expect(getStatus()).toHaveTextContent('9.9.9');
    expect(getRunButton()).toHaveTextContent(/^Run \d+ cases$/);
  });

  it('"Reset to demo contract" restores the fixture text', async () => {
    const app = renderApp();
    await submit(app, modified);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    const dialog = await openImportDialog(app.user);
    const textarea = getContractTextarea(dialog);
    expect(textarea.value).toContain('Modified Billing API');
    await app.user.click(within(dialog).getByRole('button', { name: 'Reset to demo contract' }));
    expect(textarea.value).toContain('Ledgerly');
    expect(textarea.value).toContain('"version": "1.4.0"');
  });
});
