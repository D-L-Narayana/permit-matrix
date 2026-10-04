// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { generateCases } from '../../engine/cases';
import { CaseDetail, CaseLedger } from '../CaseLedger';
import { anonymousCase, anonymousResult, cellCases, ledgerly, suite, vulnerableFlaws } from './helpers';

afterEach(cleanup);

const contract = ledgerly();
const cases = generateCases(contract);
const { results } = suite(contract, cases, vulnerableFlaws());

describe('CaseLedger', () => {
  it('is a complementary landmark labelled "Case ledger" with an empty state until a cell is selected', () => {
    render(<CaseLedger selected={null} cases={cases} results={results} activeCase={undefined} onSelectCase={vi.fn()} />);
    const ledger = screen.getByRole('complementary', { name: 'Case ledger' });
    expect(within(ledger).getByRole('heading', { level: 2 })).toHaveTextContent(/^Case ledger\s*$/);
    expect(within(ledger).getByText('Select a matrix cell to inspect its cases, requests and responses.')).toBeInTheDocument();
    expect(within(ledger).queryAllByRole('button')).toHaveLength(0);
  });

  it('lists the selected cell\'s cases as aria-pressed buttons under a heading naming endpoint and role', async () => {
    const user = userEvent.setup();
    const selected = { endpoint: 'get-invoice', role: 'member' };
    const set = cellCases(cases, selected.endpoint, selected.role);
    const onSelectCase = vi.fn();
    render(<CaseLedger selected={selected} cases={cases} results={results} activeCase={set[0]} onSelectCase={onSelectCase} />);
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('Case ledger · get-invoice as member');
    const buttons = screen.getAllByRole('button');
    expect(buttons).toHaveLength(set.length);
    expect(buttons[0]).toHaveAttribute('aria-pressed', 'true');
    expect(buttons[1]).toHaveAttribute('aria-pressed', 'false');
    expect(buttons[0]).toHaveTextContent(`${set[0].principal} · ${set[0].targetKind}`);
    // The seeded BOLA flaw turns the peer case into a bypass; the verdict chip says so.
    const peer = set.find((c) => c.targetKind === 'peer')!;
    expect(buttons[set.indexOf(peer)]).toHaveTextContent('bypass');
    await user.click(buttons[1]);
    expect(onSelectCase).toHaveBeenCalledWith(set[1].id);
  });

  it('accepts a pre-filtered cell list as well as the full case list', () => {
    const selected = { endpoint: 'delete-user', role: 'admin' };
    const set = cellCases(cases, selected.endpoint, selected.role);
    render(<CaseLedger selected={selected} cases={set} results={results} activeCase={set[0]} onSelectCase={vi.fn()} />);
    expect(screen.getAllByRole('button')).toHaveLength(set.length);
  });

  it('renders the redacted request and the response for an authenticated case', () => {
    const c = cases.find((x) => x.id === 'get-user|p-mem-1|own|read:passwordHash')!;
    const { container } = render(<CaseDetail testCase={c} result={results.get(c.id)} />);
    expect(screen.getByText('Authorization header redacted')).toBeInTheDocument();
    expect(screen.queryByText('No Authorization header (anonymous)')).toBeNull();
    const [request, response] = [...container.querySelectorAll('pre')];
    expect(request.textContent).toContain('GET /users/p-mem-1');
    expect(request.textContent).toContain('Authorization: Bearer [redacted:p-mem-1]');
    expect(request.textContent).not.toContain('mock-token-');
    expect(response.textContent).toContain('passwordHash'); // response bodies are evidence and stay unredacted
    expect(screen.getByText(/^Verdict: exposure\./)).toBeInTheDocument();
    expect(screen.getByText(/^Expectation: allow\./)).toBeInTheDocument();
  });

  it('labels an anonymous request as having no Authorization header', () => {
    const anon = anonymousCase('get-invoice', 'cross-tenant', 'inv-1001');
    const result = anonymousResult(anon, '/invoices/inv-1001');
    const { container } = render(
      <CaseLedger selected={{ endpoint: 'get-invoice', role: 'anonymous' }} cases={[anon]} results={new Map([[anon.id, result]])} activeCase={anon} onSelectCase={vi.fn()} />,
    );
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('Case ledger · get-invoice as anonymous');
    expect(screen.getByText('No Authorization header (anonymous)')).toBeInTheDocument();
    expect(screen.queryByText('Authorization header redacted')).toBeNull();
    const request = container.querySelector('pre')!;
    expect(request.textContent).toContain('GET /invoices/inv-1001');
    expect(request.textContent).toContain('Content-Type: application/json');
    expect(request.textContent).not.toMatch(/authorization/i);
    expect(screen.getByText('401')).toBeInTheDocument();
  });

  it('shows the not-yet-executed message when a case has no result', () => {
    render(<CaseDetail testCase={cases[0]} />);
    expect(screen.getByText('Not yet executed. Run the suite to see the exchange.')).toBeInTheDocument();
    // The rationale is a text node beside the <strong> expectation label, so assert on the enclosing paragraph.
    expect(screen.getByText(/^Expectation: allow\./).closest('p')).toHaveTextContent(cases[0].rationale);
  });
});
