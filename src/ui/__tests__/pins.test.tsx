// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { generateCases } from '../../engine/cases';
import type { TestCase } from '../../engine/types';
import { Pins } from '../Pins';
import { anonymousCase, anonymousResult, cellCases, ledgerly, suite } from './helpers';

afterEach(cleanup);

const contract = ledgerly();
const cases = generateCases(contract);
const { results } = suite(contract, cases);
const pinsOf = (container: HTMLElement) => [...container.querySelectorAll<HTMLElement>('.pin')];

describe('Pins', () => {
  it('collection endpoint: a single base pin, no absent placeholders', () => {
    const set = cellCases(cases, 'list-invoices', 'member'); // two member principals, one pin
    expect(set.length).toBeGreaterThan(1);
    const { container } = render(<Pins cases={set} results={results} />);
    const pins = pinsOf(container);
    expect(pins).toHaveLength(1);
    expect(pins[0].className).toContain('v-pass');
    expect(pins[0].className).toContain('exp-allow');
    expect(container.querySelectorAll('.pin.absent')).toHaveLength(0);
    expect(container.querySelectorAll('.sep')).toHaveLength(0);
  });

  it('{id} endpoint: own · peer · cross-tenant slots, with a dotted "absent" placeholder where no record exists', () => {
    // The globex member has no tenant peer, so the middle slot must be a placeholder.
    const set = cases.filter((c) => c.endpoint === 'get-invoice' && c.principal === 'p-mem-2');
    expect(set.map((c) => c.targetKind)).toEqual(['own', 'cross-tenant']);
    const { container } = render(<Pins cases={set} results={results} />);
    const pins = pinsOf(container);
    expect(pins).toHaveLength(3);
    expect(pins[0].className).toContain('v-pass');
    expect(pins[0].className).toContain('exp-allow');
    expect(pins[1].className).toContain('absent');
    expect(pins[1].getAttribute('title')).toBe('no peer record');
    expect(pins[2].className).toContain('v-pass');
    expect(pins[2].className).toContain('exp-deny');
  });

  it('renders one small round pin per property probe after a separator', () => {
    const set = cellCases(cases, 'patch-user', 'member');
    const probes = set.filter((c) => c.probeField);
    expect(probes.length).toBeGreaterThan(0);
    const { container } = render(<Pins cases={set} results={results} />);
    expect(container.querySelectorAll('.pin.prop')).toHaveLength(probes.length);
    expect(container.querySelectorAll('.pin:not(.prop)')).toHaveLength(3);
    expect(container.querySelectorAll('.sep')).toHaveLength(1);
  });

  it('create endpoint: a single base pin plus probe pins, never absent placeholders', () => {
    const base: TestCase = { id: 'create-ticket|p-agent-1|create', endpoint: 'create-ticket', principal: 'p-agent-1', role: 'agent', targetKind: 'create', category: 'object', expected: 'allow', rationale: 'Role is allowed and the endpoint is not object-scoped.' };
    const probe: TestCase = { ...base, id: 'create-ticket|p-agent-1|create|write:status', category: 'property', probeField: 'status', rationale: '"status" is not in writableFields; a create must ignore it.' };
    const { container } = render(<Pins cases={[base, probe]} results={new Map()} />);
    const pins = pinsOf(container);
    expect(pins).toHaveLength(2);
    expect(pins[0].className).toContain('exp-allow');
    expect(pins[0].className).not.toContain('absent');
    expect(pins[0].className).not.toContain('v-'); // pending: expectation only
    expect(pins[1].className).toContain('prop');
    expect(container.querySelectorAll('.pin.absent')).toHaveLength(0);
  });

  it('anonymous cell: a single authentication pin instead of the three target slots', () => {
    const anon = anonymousCase('get-invoice', 'cross-tenant', 'inv-1001');
    const { container } = render(<Pins cases={[anon]} results={new Map([[anon.id, anonymousResult(anon, '/invoices/inv-1001')]])} />);
    const pins = pinsOf(container);
    expect(pins).toHaveLength(1);
    expect(pins[0].className).toContain('auth');
    expect(pins[0].className).toContain('v-pass');
    expect(pins[0].className).toContain('exp-deny');
    expect(container.querySelectorAll('.pin.absent')).toHaveLength(0);
  });

  it('anonymous collection case that bypassed authentication shows the bypass verdict', () => {
    const anon = anonymousCase('list-invoices', 'collection');
    const { container } = render(<Pins cases={[anon]} results={new Map([[anon.id, anonymousResult(anon, '/invoices', 'bypass')]])} />);
    const pins = pinsOf(container);
    expect(pins).toHaveLength(1);
    expect(pins[0].className).toContain('auth');
    expect(pins[0].className).toContain('v-bypass');
  });
});
