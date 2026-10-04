// @vitest-environment jsdom
import { capturedBlobs, readBlob } from './setup';
import { describe, expect, it } from 'vitest';
import { getExportButton, getRunButton, renderApp } from './helpers';

describe('Report export', () => {
  it('keeps both exports disabled before any run', () => {
    renderApp();
    expect(getExportButton('json')).toBeDisabled();
    expect(getExportButton('markdown')).toBeDisabled();
    expect(capturedBlobs).toHaveLength(0);
  });

  it('downloads a redacted JSON report after a run', async () => {
    const { user } = renderApp();
    await user.click(getRunButton());
    await user.click(getExportButton('json'));

    expect(capturedBlobs).toHaveLength(1);
    expect(capturedBlobs[0].type).toBe('application/json');
    const text = await readBlob(capturedBlobs[0]);
    const report = JSON.parse(text) as { schema: unknown; summary: { findings: unknown } };
    expect(report.schema).toBe('permitmatrix.report/1');
    expect(report.summary.findings).toBe(4);
    expect(text).not.toContain('mock-token-');
    expect(text).toContain('Bearer [redacted:');
  });

  it('downloads a Markdown memo after a run', async () => {
    const { user } = renderApp();
    await user.click(getRunButton());
    await user.click(getExportButton('markdown'));

    expect(capturedBlobs).toHaveLength(1);
    expect(capturedBlobs[0].type).toBe('text/markdown');
    const text = await readBlob(capturedBlobs[0]);
    expect(text.startsWith('# Authorization contract test')).toBe(true);
    expect(text).not.toContain('mock-token-');
  });
});
