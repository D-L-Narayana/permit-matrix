import { ANONYMOUS_PRINCIPAL } from '../engine/types';
import type { CaseResult, TestCase } from '../engine/types';

export interface PinsProps {
  cases: TestCase[];
  results: Map<string, CaseResult>;
}

const SLOTS = ['own', 'peer', 'cross-tenant'] as const;

/** Anonymous-row cases probe authentication, not policy, so they get their own pin style. */
const isAuthentication = (c: TestCase): boolean => c.category === 'authentication' || c.principal === ANONYMOUS_PRINCIPAL;

const classes = (...parts: (string | false | undefined)[]): string => parts.filter(Boolean).join(' ');

/**
 * The signature three-pin cell: own · peer · cross-tenant for `{id}` endpoints (dotted placeholder where the
 * principal has no such record), one pin for collection/create calls and for the no-credentials row, then a
 * separator and a small round pin per property probe. Decorative: the cell button carries the accessible name.
 */
export function Pins({ cases, results }: PinsProps) {
  const objectCases = cases.filter((c) => !c.probeField && !isAuthentication(c));
  const authCases = cases.filter((c) => !c.probeField && isAuthentication(c));
  const propCases = cases.filter((c) => c.probeField);
  const single = objectCases.length > 0 && objectCases.every((c) => c.targetKind === 'collection' || c.targetKind === 'create');
  const verdictClass = (c: TestCase): string | undefined => {
    const r = results.get(c.id);
    return r ? `v-${r.verdict}` : undefined;
  };
  const title = (label: string, c: TestCase): string => `${label}: ${results.get(c.id)?.verdict ?? `expect ${c.expected}`}`;

  return (
    <span className="pins" aria-hidden>
      {single && <i className={classes('pin', verdictClass(objectCases[0]), `exp-${objectCases[0].expected}`)} title={title(objectCases[0].targetKind, objectCases[0])} />}
      {!single && objectCases.length > 0 && SLOTS.map((kind) => {
        const c = objectCases.find((x) => x.targetKind === kind);
        if (!c) return <i key={kind} className="pin absent" title={`no ${kind} record`} />;
        return <i key={kind} className={classes('pin', verdictClass(c), `exp-${c.expected}`)} title={title(kind, c)} />;
      })}
      {authCases.map((c) => <i key={c.id} className={classes('pin', 'auth', verdictClass(c), `exp-${c.expected}`)} title={title('no credentials', c)} />)}
      {propCases.length > 0 && <span className="sep" />}
      {propCases.map((c) => <i key={c.id} className={classes('pin', 'prop', verdictClass(c), 'exp-allow')} title={`${c.probeField}: ${results.get(c.id)?.verdict ?? 'pending'}`} />)}
    </span>
  );
}
