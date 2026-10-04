// @vitest-environment jsdom
import './setup';
import axe from 'axe-core';
import { describe, expect, it } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { getImportButton, getRunButton, openImportDialog, renderApp } from './helpers';

const AXE_OPTIONS: axe.RunOptions = {
  runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] },
  // jsdom has no layout engine, so colour contrast cannot be computed here; it is checked in a real browser.
  rules: { 'color-contrast': { enabled: false } },
};

/** Rule id, impact and offending markup only — enough to locate a problem from the assertion diff. */
async function violationsIn(container: HTMLElement) {
  const results = await axe.run(container, AXE_OPTIONS);
  return results.violations.map((v) => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.map((n) => n.html) }));
}

describe('Accessibility', () => {
  it('has no axe violations before and after a run', async () => {
    const { user, container } = renderApp();
    expect(await violationsIn(container)).toEqual([]);
    await user.click(getRunButton());
    expect(await violationsIn(container)).toEqual([]);
  }, 60_000);

  it('reaches the Run button by pressing Tab from the document body', async () => {
    const { user } = renderApp();
    expect(document.activeElement).toBe(document.body);
    const run = getRunButton();
    let reached = false;
    for (let presses = 0; presses < 40 && !reached; presses += 1) {
      await user.tab();
      reached = document.activeElement === run;
    }
    expect(reached).toBe(true);
  });

  it('moves focus into the import dialog, closes it with Escape and returns focus to the trigger', async () => {
    const { user } = renderApp();
    const dialog = await openImportDialog(user);
    await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    // The opener is a plain toolbar button rather than a Radix Dialog.Trigger, so the dialog returns focus by id.
    await waitFor(() => expect(document.activeElement).toBe(getImportButton()));
  });
});
