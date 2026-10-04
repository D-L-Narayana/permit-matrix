// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { ContractRail } from '../ContractRail';
import { ledgerly } from './helpers';

afterEach(cleanup);

const contract = ledgerly();

describe('ContractRail', () => {
  it('is a complementary landmark labelled "Contract outline" with the four outline lists', () => {
    render(<ContractRail contract={contract} notice="Demo data loaded." />);
    const rail = screen.getByRole('complementary', { name: 'Contract outline' });
    expect(within(rail).getAllByRole('heading', { level: 2 }).map((h) => h.textContent)).toEqual(['Roles', 'Principals', 'Endpoints', 'Resources']);
    const lists = within(rail).getAllByRole('list');
    expect(lists).toHaveLength(4);
    expect(within(lists[0]).getAllByRole('listitem')).toHaveLength(contract.roles.length);
    expect(within(lists[1]).getAllByRole('listitem')).toHaveLength(contract.principals.length);
    expect(within(lists[2]).getAllByRole('listitem')).toHaveLength(contract.endpoints.length);
    expect(within(lists[3]).getAllByRole('listitem')).toHaveLength(contract.resources.length);
    expect(within(lists[1]).getByText('p-mem-2')).toBeInTheDocument();
    expect(within(lists[1]).getByText('member · globex.example')).toBeInTheDocument();
    expect(within(lists[2]).getAllByText('/invoices/{id}')).toHaveLength(2);
    expect(within(lists[2]).getAllByText('PATCH')).toHaveLength(2);
    // Both Ledgerly resources (invoices, users) hold exactly four records.
    expect(within(lists[3]).getAllByText('4 records')).toHaveLength(2);
    expect(within(lists[3]).getByText('invoices')).toBeInTheDocument();
  });

  it('renders the notice as a status region and the optional health slot between the lists and the notice', () => {
    render(<ContractRail contract={contract} notice="Imported ok." health={<section aria-label="Contract health">0 warnings</section>} />);
    const rail = screen.getByRole('complementary', { name: 'Contract outline' });
    const status = within(rail).getByRole('status');
    expect(status).toHaveTextContent('Imported ok.');
    expect(status).toHaveClass('notice');
    const health = within(rail).getByRole('region', { name: 'Contract health' });
    const lastList = within(rail).getAllByRole('list').at(-1)!;
    expect(lastList.compareDocumentPosition(health) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(health.compareDocumentPosition(status) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('renders nothing extra when no health slot is given', () => {
    render(<ContractRail contract={contract} notice="n" />);
    expect(screen.queryByRole('region')).toBeNull();
  });
});
