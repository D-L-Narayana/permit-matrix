// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ImportDialog } from '../ImportDialog';
import type { ImportDialogProps } from '../ImportDialog';

afterEach(cleanup);

/** The app opens the dialog from a plain toolbar button (not a Dialog.Trigger), so closing must hand focus back explicitly. */
function Harness({ returnFocusId }: { returnFocusId?: string }) {
  const [open, setOpen] = useState(true);
  return (
    <>
      <button id="import-contract" onClick={() => setOpen(true)}>Import contract…</button>
      <ImportDialog
        open={open} onOpenChange={setOpen} draft="" onDraft={() => undefined} onFile={() => undefined} onReset={() => undefined} onValidate={() => undefined}
        errors={[]} maxBytes={64 * 1024} maxEndpoints={40} maxRoles={8} returnFocusId={returnFocusId}
      />
    </>
  );
}

function renderDialog(overrides: Partial<ImportDialogProps> = {}) {
  const props: ImportDialogProps = {
    open: true, onOpenChange: vi.fn(), draft: '{}', onDraft: vi.fn(), onFile: vi.fn(), onReset: vi.fn(), onValidate: vi.fn(),
    errors: [], maxBytes: 64 * 1024, maxEndpoints: 40, maxRoles: 8, ...overrides,
  };
  return { ...render(<ImportDialog {...props} />), props };
}

describe('ImportDialog', () => {
  it('renders the titled dialog, the limits + OpenAPI description, the labelled textarea and the action buttons', () => {
    renderDialog();
    const dialog = screen.getByRole('dialog', { name: 'Import a contract' });
    expect(dialog).toHaveAccessibleDescription(/max 64 KB, 40 endpoints, 8 roles/);
    expect(dialog).toHaveAccessibleDescription(/OpenAPI 3\.1 documents with x-permitmatrix extensions are also accepted/);
    expect(dialog).toHaveAccessibleDescription(/mock:\/\/ or localhost/);
    expect(screen.getByLabelText('Contract JSON')).toBeInstanceOf(HTMLTextAreaElement);
    expect(screen.getByLabelText('Contract JSON')).toHaveValue('{}');
    for (const name of ['Reset to demo contract', 'Cancel', 'Validate and load']) expect(screen.getByRole('button', { name })).toBeInTheDocument();
    const file = screen.getByLabelText('Choose file…');
    expect(file).toHaveAttribute('type', 'file');
    expect(file).toHaveAttribute('accept', 'application/json,.json');
  });

  it('errors render inside a persistent alert live region: first 12, then "+n more"', () => {
    const { rerender, props } = renderDialog();
    const alert = screen.getByRole('alert');
    expect(alert).toBeEmptyDOMElement();
    const errors = Array.from({ length: 14 }, (_, i) => `endpoints[${i}].access.roles: must list at least one role.`);
    rerender(<ImportDialog {...props} errors={errors} />);
    const live = screen.getByRole('alert');
    expect(live).toBe(alert); // the region exists before the errors arrive, so the announcement fires
    const items = within(live).getAllByRole('listitem');
    expect(items).toHaveLength(13);
    expect(items[0]).toHaveTextContent('endpoints[0].access.roles: must list at least one role.');
    expect(items[11]).toHaveTextContent('endpoints[11].access.roles');
    expect(items[12]).toHaveTextContent('+2 more');
    expect(within(live).getByRole('list')).toHaveClass('errors');
    expect(live).not.toHaveAttribute('class', 'errors'); // role="alert" sits on the wrapper, not the list
  });

  it('a single error renders without the overflow item', () => {
    renderDialog({ errors: ['External target refused: "https://api.victim.example". Only mock:// or localhost targets are allowed.'] });
    const live = screen.getByRole('alert');
    expect(live).toHaveTextContent('External target refused');
    expect(within(live).getAllByRole('listitem')).toHaveLength(1);
    expect(live).not.toHaveTextContent('more');
  });

  it('renders importer notes in their own list, outside the alert', () => {
    renderDialog({ notes: ['Renamed path parameter {ticketId} to {id}.', 'Skipped HEAD /tickets: unsupported method.'] });
    const note = screen.getByText('Renamed path parameter {ticketId} to {id}.');
    expect(note.closest('ul')).toHaveClass('notes');
    expect(within(note.closest('ul') as HTMLElement).getAllByRole('listitem')).toHaveLength(2);
    expect(screen.getByRole('alert')).not.toContainElement(note);
    expect(screen.getByRole('alert')).toBeEmptyDOMElement();
  });

  it('omits the notes list when there are none', () => {
    const { container } = renderDialog({ notes: [] });
    expect(container.ownerDocument.querySelector('ul.notes')).toBeNull();
  });

  it('wires the actions: Validate and load, Reset, Cancel, typing and choosing a file', async () => {
    const user = userEvent.setup();
    const { props } = renderDialog();
    await user.click(screen.getByRole('button', { name: 'Validate and load' }));
    expect(props.onValidate).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole('button', { name: 'Reset to demo contract' }));
    expect(props.onReset).toHaveBeenCalledTimes(1);
    await user.type(screen.getByLabelText('Contract JSON'), '!');
    expect(props.onDraft).toHaveBeenCalledWith('{}!');
    const file = new File(['{"schema":"permitmatrix.contract/1"}'], 'contract.json', { type: 'application/json' });
    await user.upload(screen.getByLabelText('Choose file…'), file);
    expect(props.onFile).toHaveBeenCalledTimes(1);
    expect(vi.mocked(props.onFile).mock.calls[0][0]).toBe(file);
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(props.onOpenChange).toHaveBeenCalledWith(false);
  });
});

describe('ImportDialog focus return', () => {
  it('returns focus to the element named by returnFocusId when closed with Cancel', async () => {
    const user = userEvent.setup();
    render(<Harness returnFocusId="import-contract" />);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await waitFor(() => expect(document.getElementById('import-contract')).toHaveFocus());
  });

  it('returns focus to the element named by returnFocusId when closed with Escape', async () => {
    const user = userEvent.setup();
    render(<Harness returnFocusId="import-contract" />);
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await waitFor(() => expect(document.getElementById('import-contract')).toHaveFocus());
  });

  it('without returnFocusId, closing a trigger-less dialog drops focus to the body (the gap the prop closes)', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    // Radix defers the unmount focus handling by a macrotask; let it run before asserting.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(document.activeElement).toBe(document.body);
    expect(document.getElementById('import-contract')).not.toHaveFocus();
  });
});
