import { describe, expect, it } from 'vitest';
import fixture from '../../fixtures/ledgerly-contract.json';
import { validateContract } from '../contract';
import { generateCases } from '../cases';
import { runSuite } from '../runner';
import { DATA_NOTE, DISCLAIMER, buildReport, redactHeaders, reportToMarkdown } from '../report';
import type { CaseResult, Contract, ContractWarning, Flaw, SuiteRun } from '../types';

const GENERATED_AT = '2026-10-01T00:00:00.000Z';
const EVIDENCE_LIMIT = 8;

const contract = (): Contract => {
  const result = validateContract(fixture);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
};
const vulnerableFlaws = (): Flaw[] => fixture.builds.vulnerable.flaws as Flaw[];

function vulnerableRun(flaws: Flaw[] = vulnerableFlaws()): { c: Contract; run: SuiteRun } {
  const c = contract();
  return { c, run: runSuite(c, generateCases(c), flaws) };
}

const WARNINGS: ContractWarning[] = [
  { code: 'unused-role', severity: 'warn', path: 'roles[1]', message: 'Role "manager" is not allowed on any endpoint.' },
  { code: 'single-tenant', severity: 'info', path: 'principals', message: 'All principals share one tenant; no cross-tenant cases are generated.' },
];

/** Text from `heading` up to the next `## ` heading; empty when the heading is absent (so assertions, not throws, report it). */
function sectionOf(md: string, heading: string): string {
  const start = md.indexOf(`${heading}\n`);
  if (start < 0) return '';
  const next = md.indexOf('\n## ', start + heading.length);
  return md.slice(start, next < 0 ? md.length : next);
}

/** The `### ` blocks inside the Findings section. */
function findingBlocks(md: string): string[] {
  return sectionOf(md, '## Findings').split('\n### ').slice(1);
}

describe('buildReport — build.flaws reflects the active flaws', () => {
  it('lists the active flaws when `flaws` is given, not the build definition', () => {
    const active = vulnerableFlaws().slice(0, 2); // the user switched two of the four seeded flaws off
    const { c, run } = vulnerableRun(active);
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT, flaws: active });
    expect(report.build.id).toBe('vulnerable');
    expect(report.build.label).toBe('release/1.4.0 (vulnerable)');
    expect(report.build.flaws).toEqual(active.map((f) => ({ endpoint: f.endpoint, kind: f.kind })));
    expect(report.summary.findings).toBe(2);
  });

  it('records an empty active list when every switch is off on a vulnerable build', () => {
    const { c, run } = vulnerableRun([]);
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT, flaws: [] });
    expect(report.build.flaws).toEqual([]);
    expect(report.summary.findings).toBe(0);
  });

  it('falls back to the build definition when `flaws` is omitted', () => {
    const { c, run } = vulnerableRun();
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT });
    expect(report.build.flaws).toEqual(vulnerableFlaws());
  });

  it('copies the active flaws so later mutation of the caller’s array does not alter the report', () => {
    const active = vulnerableFlaws().slice(0, 1);
    const { c, run } = vulnerableRun(active);
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT, flaws: active });
    active.push({ endpoint: 'delete-user', kind: 'skip-role-check' });
    expect(report.build.flaws).toHaveLength(1);
  });

  it('keeps the schema id, counts, notes and the bearer-token redaction', () => {
    const { c, run } = vulnerableRun();
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT, flaws: vulnerableFlaws() });
    expect(report.schema).toBe('permitmatrix.report/1');
    expect(report.generatedAt).toBe(GENERATED_AT);
    expect(report.summary.cases).toBe(run.results.length);
    expect(report.summary.findings).toBe(4);
    expect(report.dataNote).toBe(DATA_NOTE);
    expect(report.disclaimer).toBe(DISCLAIMER);
    const text = JSON.stringify(report);
    expect(text).not.toMatch(/mock-token-/);
    expect(text).toMatch(/Bearer \[redacted:p-mem-1\]/);
  });

  it('copes with anonymous cases whose request carries no Authorization header', () => {
    const { c, run } = vulnerableRun();
    const template = run.results[0];
    // Shaped like the runner's anonymous row, with an id that cannot collide with a generated case.
    const anonymous: CaseResult = {
      ...template,
      caseId: 'synthetic-endpoint|anonymous|collection',
      principal: 'anonymous',
      role: 'anonymous',
      request: { ...template.request, principal: 'anonymous', headers: { 'Content-Type': 'application/json' } },
    };
    const report = buildReport(c, { ...run, results: [...run.results, anonymous] }, { build: 'vulnerable', generatedAt: GENERATED_AT });
    const exported = report.cases.find((r) => r.caseId === anonymous.caseId);
    expect(exported?.request.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(report.summary.cases).toBe(run.results.length + 1);
  });
});

describe('buildReport — contract warnings', () => {
  it('omits the warnings key entirely when none are supplied', () => {
    const { c, run } = vulnerableRun();
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT });
    expect('warnings' in report).toBe(false);
    expect(JSON.stringify(report)).not.toContain('"warnings"');
  });

  it('includes the supplied warnings as a copy', () => {
    const { c, run } = vulnerableRun();
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT, warnings: WARNINGS });
    expect(report.warnings).toEqual(WARNINGS);
    expect(report.warnings).not.toBe(WARNINGS);
  });

  it('keeps an explicitly empty warning list (the linter ran and found nothing)', () => {
    const { c, run } = vulnerableRun();
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT, warnings: [] });
    expect(report.warnings).toEqual([]);
  });
});

describe('redactHeaders', () => {
  it('redacts the bearer token but keeps the principal for cross-referencing', () => {
    expect(redactHeaders({ Authorization: 'Bearer mock-token-p-mem-1', 'Content-Type': 'application/json' })).toEqual({
      Authorization: 'Bearer [redacted:p-mem-1]',
      'Content-Type': 'application/json',
    });
  });

  it('matches the header name case-insensitively and redacts unrecognised bearer formats as unknown', () => {
    expect(redactHeaders({ authorization: 'Bearer mock-token-p-admin-1' })).toEqual({ authorization: 'Bearer [redacted:p-admin-1]' });
    expect(redactHeaders({ Authorization: 'Bearer something-else' }).Authorization).toBe('Bearer [redacted:unknown]');
  });

  it('passes anonymous requests (no Authorization header) through as a copy and never invents one', () => {
    const headers = { 'Content-Type': 'application/json' };
    const out = redactHeaders(headers);
    expect(out).toEqual(headers);
    expect(out).not.toBe(headers);
    expect(redactHeaders({})).toEqual({});
  });
});

describe('reportToMarkdown', () => {
  const memo = () => {
    const { c, run } = vulnerableRun();
    const report = buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT, flaws: vulnerableFlaws(), warnings: WARNINGS });
    return { report, md: reportToMarkdown(report) };
  };

  it('opens with the title, the run line and the blockquoted disclaimer and data note', () => {
    const { report, md } = memo();
    expect(md.split('\n')[0]).toBe(`# Authorization contract test — ${report.contract.name} ${report.contract.version}`);
    expect(md).toContain(`Generated ${GENERATED_AT} · build: release/1.4.0 (vulnerable) · ${report.summary.cases} cases · 4 findings`);
    expect(md).toContain(`> ${DISCLAIMER}`);
    expect(md).toContain(`> ${DATA_NOTE}`);
  });

  it('renders every section heading in the documented order', () => {
    const { md } = memo();
    const headings = md.split('\n').filter((l) => l.startsWith('## '));
    expect(headings).toEqual([
      '## Summary',
      '## Active seeded flaws',
      '## Findings',
      '## Contract warnings',
      '## Severity rubric',
      '## Coverage (cases per endpoint × role: passed / total)',
    ]);
  });

  it('summarises verdicts in a table and findings by severity on one line', () => {
    const { report, md } = memo();
    const summary = sectionOf(md, '## Summary');
    expect(summary).toContain('| Verdict | Cases |');
    for (const [verdict, n] of Object.entries(report.summary.byVerdict)) expect(summary).toContain(`| ${verdict} | ${n} |`);
    const { high, medium, low } = report.summary.bySeverity;
    expect(summary).toContain(`Findings by severity: high ${high} · medium ${medium} · low ${low}`);
  });

  it('lists the active seeded flaws as endpoint · kind', () => {
    const { md } = memo();
    const section = sectionOf(md, '## Active seeded flaws');
    for (const f of vulnerableFlaws()) expect(section).toContain(`- ${f.endpoint} · ${f.kind}`);
    expect(section).not.toContain('None');
  });

  it('writes "None" under Active seeded flaws when nothing is toggled on', () => {
    const { c, run } = vulnerableRun([]);
    const md = reportToMarkdown(buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT, flaws: [] }));
    expect(sectionOf(md, '## Active seeded flaws')).toContain('None');
    expect(sectionOf(md, '## Findings')).toContain('No authorization findings.');
  });

  it('lists up to 8 evidence cases per finding as principal · target[ · probe]: explanation', () => {
    const { report, md } = memo();
    const blocks = findingBlocks(md);
    expect(blocks).toHaveLength(report.findings.length);
    // The fixture has a finding with more than 8 evidence cases, so truncation is exercised here.
    expect(report.findings.some((f) => f.evidenceCases.length > EVIDENCE_LIMIT)).toBe(true);
    for (const f of report.findings) {
      const heading = `${f.severity.toUpperCase()} · ${f.title} (${f.owaspApi}) — \`${f.endpoint}\``;
      const block = blocks.find((b) => b.startsWith(heading)) ?? '';
      expect(block, `block for ${f.id}`).not.toBe('');
      expect(block).toContain(`Evidence cases: ${f.evidenceCases.length}. ${f.remediation}`);
      const bullets = block.split('\n').filter((l) => l.startsWith('- '));
      expect(bullets, `bullets for ${f.id}`).toHaveLength(Math.min(EVIDENCE_LIMIT, f.evidenceCases.length));
      if (f.evidenceCases.length > EVIDENCE_LIMIT) expect(block).toMatch(new RegExp(`^\\+${f.evidenceCases.length - EVIDENCE_LIMIT} more`, 'm'));
      else expect(block).not.toMatch(/^\+\d+ more/m);
    }
    // Specific bullets must be composed from the case their id names. The explanation is looked up in the report
    // rather than quoted, so rewording in the runner cannot break this test; the principal/target/probe rendering
    // stays literal because that layout is the behaviour under test.
    const caseOf = (id: string) => report.cases.find((c) => c.caseId === id);
    const explanationOf = (id: string) => caseOf(id)?.explanation ?? `(case ${id} missing from report)`;
    for (const id of ['get-invoice|p-mem-1|peer', 'get-user|p-admin-1|own|read:passwordHash', 'patch-user|p-admin-1|own|write:role']) {
      expect(caseOf(id)?.verdict, `verdict of ${id}`).toBeDefined();
      expect(caseOf(id)?.verdict, `verdict of ${id}`).not.toBe('pass');
    }
    expect(md).toContain(`- p-mem-1 · peer: ${explanationOf('get-invoice|p-mem-1|peer')}`);
    expect(md).toContain(`- p-admin-1 · own · passwordHash: ${explanationOf('get-user|p-admin-1|own|read:passwordHash')}`);
    expect(md).toContain(`- p-admin-1 · own · role: ${explanationOf('patch-user|p-admin-1|own|write:role')}`);
  });

  it('renders contract warnings as severity · code · path · message, and only when warnings exist', () => {
    const { md } = memo();
    const section = sectionOf(md, '## Contract warnings');
    expect(section).toContain('- warn · unused-role · roles[1] · Role "manager" is not allowed on any endpoint.');
    expect(section).toContain('- info · single-tenant · principals · All principals share one tenant; no cross-tenant cases are generated.');
    const { c, run } = vulnerableRun();
    const without = reportToMarkdown(buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT }));
    expect(without).not.toContain('## Contract warnings');
    const empty = reportToMarkdown(buildReport(c, run, { build: 'vulnerable', generatedAt: GENERATED_AT, warnings: [] }));
    expect(empty).not.toContain('## Contract warnings');
  });

  it('explains the severity rubric and says it is not CVSS', () => {
    const { md } = memo();
    const rubric = sectionOf(md, '## Severity rubric');
    expect(rubric).toMatch(/not CVSS/);
    expect(rubric).toMatch(/bypass/i);
    expect(rubric).toMatch(/mass assignment/i);
    expect(rubric).toMatch(/exposure/i);
    expect(rubric).toMatch(/over-deny/i);
    for (const level of ['high', 'medium', 'low']) expect(rubric).toContain(level);
  });

  it('renders the coverage table with one column per coverage key', () => {
    const { report, md } = memo();
    const roles = Object.keys(Object.values(report.coverage)[0]);
    const coverage = sectionOf(md, '## Coverage (cases per endpoint × role: passed / total)');
    expect(coverage).toContain(`| Endpoint | ${roles.join(' | ')} |`);
    for (const [endpoint, cells] of Object.entries(report.coverage)) {
      expect(coverage).toContain(`| ${endpoint} | ${roles.map((r) => `${cells[r].pass}/${cells[r].total}`).join(' | ')} |`);
    }
  });

  it('grows an extra coverage column automatically when the run carries an anonymous column', () => {
    const { c, run } = vulnerableRun();
    const coverage = Object.fromEntries(
      Object.entries(run.coverage).map(([endpoint, cells]) => [endpoint, { ...cells, anonymous: { total: 1, pass: 1, failed: 0 } }]),
    );
    const md = reportToMarkdown(buildReport(c, { ...run, coverage }, { build: 'vulnerable', generatedAt: GENERATED_AT }));
    expect(md).toContain('| Endpoint | admin | manager | member | anonymous |');
    expect(md).toMatch(/\| get-invoice \| \d+\/\d+ \| \d+\/\d+ \| \d+\/\d+ \| 1\/1 \|/);
  });

  it('never contains a raw bearer token', () => {
    expect(memo().md).not.toMatch(/mock-token-/);
  });

  it('is deterministic for a fixed generatedAt', () => {
    expect(memo().md).toBe(memo().md);
  });
});
