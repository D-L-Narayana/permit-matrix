// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { generateCases } from '../../engine/cases';
import type { SuiteRun } from '../../engine/types';
import { Findings } from '../Findings';
import { ledgerly, suite, vulnerableFlaws } from './helpers';

afterEach(cleanup);

const contract = ledgerly();
const cases = generateCases(contract);
const caseById = new Map(cases.map((c) => [c.id, c]));

describe('Findings', () => {
  it('shows the pre-run hint, then the "No findings" state after a clean run', () => {
    const { rerender } = render(<Findings run={null} caseById={caseById} onSelectCase={vi.fn()} />);
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent(/^Findings\s*$/);
    expect(screen.getByText(/Findings appear after a run/)).toBeInTheDocument();
    expect(screen.queryAllByRole('article')).toHaveLength(0);
    const { run } = suite(contract, cases);
    rerender(<Findings run={run} caseById={caseById} onSelectCase={vi.fn()} />);
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('Findings · 0');
    expect(screen.getByText(`No findings. Every one of ${run.results.length} cases matched the contract on this build.`)).toHaveClass('good');
  });

  it('renders one article per finding with title, OWASP id, remediation and evidence buttons that select the case', async () => {
    const user = userEvent.setup();
    const { run } = suite(contract, cases, vulnerableFlaws());
    const onSelectCase = vi.fn();
    render(<Findings run={run} caseById={caseById} onSelectCase={onSelectCase} />);
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('Findings · 4');
    const articles = screen.getAllByRole('article');
    expect(articles).toHaveLength(4);
    const first = run.findings[0];
    expect(articles[0]).toHaveClass(`sev-${first.severity}`);
    expect(within(articles[0]).getByText(first.title)).toBeInTheDocument();
    expect(within(articles[0]).getByText(`${first.owaspApi} · ${first.severity} · ${first.endpoint}`)).toBeInTheDocument();
    expect(within(articles[0]).getByText(first.remediation)).toBeInTheDocument();
    const buttons = within(articles[0]).getAllByRole('button');
    expect(buttons).toHaveLength(Math.min(12, first.evidenceCases.length));
    const evidence = caseById.get(first.evidenceCases[0])!;
    expect(buttons[0]).toHaveTextContent(`${evidence.principal} · ${evidence.targetKind}`);
    await user.click(buttons[0]);
    expect(onSelectCase).toHaveBeenCalledWith(first.evidenceCases[0]);
    // The exposure finding names the probed field on its evidence chips.
    const exposure = run.findings.find((f) => f.kind === 'sensitive-exposure')!;
    const article = articles[run.findings.indexOf(exposure)];
    expect(within(article).getAllByRole('button')[0]).toHaveTextContent('· passwordHash');
  });

  it('shows at most 12 evidence buttons and says how many more there are', () => {
    const { run } = suite(contract, cases, vulnerableFlaws());
    const evidenceCases = cases.slice(0, 15).map((c) => c.id);
    const wide: SuiteRun = { ...run, findings: [{ ...run.findings[0], evidenceCases }] };
    render(<Findings run={wide} caseById={caseById} onSelectCase={vi.fn()} />);
    const article = screen.getByRole('article');
    expect(within(article).getAllByRole('button')).toHaveLength(12);
    expect(article).toHaveTextContent('+3 more');
  });
});
