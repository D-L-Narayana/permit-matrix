// Queries for the stable accessibility contract of the App (see PLAN §5 W08). Tests go through these
// helpers so a component split that keeps the labels, roles and button texts keeps the tests green.
import { createElement } from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import type { RenderResult } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { UserEvent } from '@testing-library/user-event';
import App from '../App';

export type AppRender = RenderResult & { user: UserEvent };

export function renderApp(): AppRender {
  const user = userEvent.setup();
  const utils = render(createElement(App));
  return { ...utils, user };
}

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** "Run {n} cases" before the first run, "Re-run {n} cases" once inputs changed, "Run again {n} cases" otherwise. */
export const RUN_BUTTON = /^(Run|Re-run|Run again) \d+ cases$/;

export function getRunButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: RUN_BUTTON }) as HTMLButtonElement;
}

export function getBuildSelect(): HTMLSelectElement {
  return screen.getByLabelText('Server build') as HTMLSelectElement;
}

export function getImportButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Import contract…' }) as HTMLButtonElement;
}

export function getExportButton(kind: 'json' | 'markdown'): HTMLButtonElement {
  const name = kind === 'json' ? 'Export JSON' : 'Export memo (.md)';
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

/** The contract rail (`aria-label="Contract outline"`); the status notice lives inside it. */
export function getRail(): HTMLElement {
  return screen.getByLabelText('Contract outline');
}

export function getStatus(): HTMLElement {
  return within(getRail()).getByRole('status');
}

/** The case ledger (`aria-label="Case ledger"`) and its heading `Case ledger · {endpointId} as {roleId}`. */
export function getLedger(): HTMLElement {
  return screen.getByLabelText('Case ledger');
}

export function getLedgerHeading(): HTMLElement {
  return within(getLedger()).getByRole('heading', { name: /^Case ledger/ });
}

/** A matrix cell by its label prefix `{METHOD} {path} as {roleLabel}:`. */
export function getCell(method: string, path: string, roleLabel: string): HTMLButtonElement {
  const prefix = new RegExp(`^${escapeRegExp(`${method} ${path} as ${roleLabel}:`)}`);
  return screen.getByRole('button', { name: prefix }) as HTMLButtonElement;
}

export function getAllCells(): HTMLButtonElement[] {
  return screen.getAllByRole('button', { name: /^(GET|POST|PUT|PATCH|DELETE) \/\S* as .+: \d+ cases/ }) as HTMLButtonElement[];
}

export function getFindingArticles(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll('article'));
}

export async function openImportDialog(user: UserEvent): Promise<HTMLElement> {
  await user.click(getImportButton());
  return screen.getByRole('dialog', { name: 'Import a contract' });
}

export function getContractTextarea(dialog: HTMLElement): HTMLTextAreaElement {
  return within(dialog).getByLabelText('Contract JSON') as HTMLTextAreaElement;
}

/** Replaces the textarea value in one change event; typing a 3 KB contract character by character is far too slow. */
export function setTextareaValue(textarea: HTMLTextAreaElement, text: string): void {
  fireEvent.change(textarea, { target: { value: text } });
}
