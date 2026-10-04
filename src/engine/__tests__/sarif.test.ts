import { describe, expect, it } from 'vitest';
import fixture from '../../fixtures/ledgerly-contract.json';
import { validateContract } from '../contract';
import { generateCases } from '../cases';
import { runSuite } from '../runner';
import { DATA_NOTE, DISCLAIMER, buildReport, type Report } from '../report';
import { reportToSarif } from '../sarif';
import type { Contract, Finding, FindingKind, Flaw } from '../types';

const GENERATED_AT = '2026-10-01T00:00:00.000Z';

const contract = (): Contract => {
  const result = validateContract(fixture);
  if (!result.ok) throw new Error(result.errors.join('\n'));
  return result.contract;
};
const vulnerableFlaws = (): Flaw[] => fixture.builds.vulnerable.flaws as Flaw[];

function vulnerableReport(): Report {
  const c = contract();
  const flaws = vulnerableFlaws();
  return buildReport(c, runSuite(c, generateCases(c), flaws), { build: 'vulnerable', generatedAt: GENERATED_AT, flaws });
}

function finding(overrides: Partial<Finding> & Pick<Finding, 'id' | 'kind' | 'severity'>): Finding {
  return {
    endpoint: 'ep',
    owaspApi: 'API1:2023',
    title: `Title for ${overrides.kind}`,
    evidenceCases: ['ep|p|own'],
    remediation: `Fix ${overrides.kind}.`,
    ...overrides,
  };
}

/** A hand-built report, because the Ledgerly fixture only ever produces high-severity findings. */
function handReport(findings: Finding[]): Report {
  return {
    schema: 'permitmatrix.report/1',
    generatedAt: GENERATED_AT,
    tool: { name: 'permitmatrix', mode: 'browser-local deterministic simulation' },
    contract: { name: 'Hand-built', version: '0.0.1', servers: ['mock://hand.example'] },
    build: { id: 'b', label: 'build b', flaws: [] },
    summary: {
      cases: 0,
      findings: findings.length,
      byVerdict: { pass: 0, bypass: 0, 'over-deny': 0, exposure: 0, 'mass-assignment': 0, error: 0 },
      bySeverity: { high: 0, medium: 0, low: 0 },
    },
    findings,
    coverage: {},
    cases: [],
    dataNote: DATA_NOTE,
    disclaimer: DISCLAIMER,
  };
}

const RULE_NAMES: Record<FindingKind, string> = {
  'object-bypass': 'ObjectBypass',
  'function-bypass': 'FunctionBypass',
  'mass-assignment': 'MassAssignment',
  'sensitive-exposure': 'SensitiveExposure',
  'over-deny': 'OverDeny',
  'auth-bypass': 'AuthBypass',
};

describe('reportToSarif — log shape', () => {
  it('emits a SARIF 2.1.0 log with exactly one run and the permitmatrix driver', () => {
    const sarif = reportToSarif(vulnerableReport());
    expect(sarif.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    const { driver } = sarif.runs[0].tool;
    expect(driver.name).toBe('permitmatrix');
    expect(driver.semanticVersion).toBe('0.1.0');
    expect(driver.informationUri).toBe('https://github.com/D-L-Narayana/permit-matrix');
  });

  it('records the invocation and the run properties (disclaimer, data note, contract, build, generatedAt)', () => {
    const report = vulnerableReport();
    const run = reportToSarif(report).runs[0];
    expect(run.invocations).toEqual([{ executionSuccessful: true, endTimeUtc: GENERATED_AT }]);
    expect(run.properties).toEqual({
      disclaimer: DISCLAIMER,
      dataNote: DATA_NOTE,
      contract: report.contract,
      build: report.build,
      generatedAt: GENERATED_AT,
    });
    expect(run.properties.build.flaws).toEqual(vulnerableFlaws());
  });
});

describe('reportToSarif — rules', () => {
  it('declares one rule per finding kind present, in first-seen order, carrying title, remediation and OWASP tags', () => {
    const report = vulnerableReport();
    const rules = reportToSarif(report).runs[0].tool.driver.rules;
    const kinds = [...new Set(report.findings.map((f) => f.kind))];
    expect(kinds).toHaveLength(4);
    expect(rules.map((r) => r.id)).toEqual(kinds);
    expect(rules.map((r) => r.name)).toEqual(kinds.map((k) => RULE_NAMES[k]));
    for (const rule of rules) {
      const f = report.findings.find((x) => x.kind === rule.id);
      expect(f).toBeDefined();
      if (!f) continue;
      expect(rule.shortDescription.text).toBe(f.title);
      expect(rule.fullDescription.text).toBe(f.remediation);
      expect(rule.help.text).toBe(f.remediation);
      expect(rule.helpUri).toBe('https://owasp.org/API-Security/editions/2023/en/0x11-t10/');
      expect(rule.properties).toEqual({ owaspApi: f.owaspApi, tags: ['security', 'authorization', f.owaspApi] });
    }
  });

  it('collapses several findings of one kind into a single rule and points every result at it', () => {
    const report = handReport([
      finding({ id: 'a:object-bypass', kind: 'object-bypass', severity: 'high', endpoint: 'a' }),
      finding({ id: 'b:object-bypass', kind: 'object-bypass', severity: 'high', endpoint: 'b' }),
      finding({ id: 'b:over-deny', kind: 'over-deny', severity: 'low', endpoint: 'b', owaspApi: 'n/a' }),
    ]);
    const run = reportToSarif(report).runs[0];
    expect(run.tool.driver.rules.map((r) => r.id)).toEqual(['object-bypass', 'over-deny']);
    expect(run.tool.driver.rules[1].name).toBe('OverDeny');
    expect(run.results.map((r) => r.ruleIndex)).toEqual([0, 0, 1]);
  });

  it('names the authentication rule AuthBypass with the API2:2023 tag', () => {
    const report = handReport([finding({ id: 'x:auth-bypass', kind: 'auth-bypass', severity: 'high', owaspApi: 'API2:2023' })]);
    const rule = reportToSarif(report).runs[0].tool.driver.rules[0];
    expect(rule.id).toBe('auth-bypass');
    expect(rule.name).toBe('AuthBypass');
    expect(rule.properties.tags).toEqual(['security', 'authorization', 'API2:2023']);
  });

  it('emits no rules and no results for a clean run but still records a successful invocation', () => {
    const c = contract();
    const report = buildReport(c, runSuite(c, generateCases(c), []), { build: 'fixed', generatedAt: GENERATED_AT, flaws: [] });
    const run = reportToSarif(report).runs[0];
    expect(run.tool.driver.rules).toEqual([]);
    expect(run.results).toEqual([]);
    expect(run.invocations).toEqual([{ executionSuccessful: true, endTimeUtc: GENERATED_AT }]);
  });
});

describe('reportToSarif — results', () => {
  it('emits one result per finding with ruleId/ruleIndex, message, logical location and properties', () => {
    const report = vulnerableReport();
    const run = reportToSarif(report).runs[0];
    expect(run.results).toHaveLength(report.findings.length);
    expect(run.results).toHaveLength(4);
    report.findings.forEach((f, i) => {
      const r = run.results[i];
      expect(r.ruleId).toBe(f.kind);
      expect(run.tool.driver.rules[r.ruleIndex]?.id).toBe(f.kind);
      expect(r.level).toBe('error');
      expect(r.message.text).toBe(`${f.title} on ${f.endpoint} (${f.owaspApi}); ${f.evidenceCases.length} evidence case(s).`);
      expect(r.locations).toEqual([{ logicalLocations: [{ fullyQualifiedName: f.endpoint, kind: 'endpoint' }] }]);
      expect(r.properties).toEqual({ endpoint: f.endpoint, severity: f.severity, evidenceCases: f.evidenceCases });
    });
  });

  it('maps severities to SARIF levels: high → error, medium → warning, low → note', () => {
    const report = handReport([
      finding({ id: 'h', kind: 'object-bypass', severity: 'high' }),
      finding({ id: 'm', kind: 'sensitive-exposure', severity: 'medium', owaspApi: 'API3:2023' }),
      finding({ id: 'l', kind: 'over-deny', severity: 'low', owaspApi: 'n/a' }),
    ]);
    expect(reportToSarif(report).runs[0].results.map((r) => r.level)).toEqual(['error', 'warning', 'note']);
  });

  it('maps a real over-deny finding (deny-everything flaw) to level note with the n/a OWASP id', () => {
    const c = contract();
    const flaws: Flaw[] = [{ endpoint: 'get-invoice', kind: 'deny-everything' }];
    const report = buildReport(c, runSuite(c, generateCases(c), flaws), { build: 'vulnerable', generatedAt: GENERATED_AT, flaws });
    const run = reportToSarif(report).runs[0];
    const overDeny = run.results.find((r) => r.ruleId === 'over-deny');
    expect(overDeny?.level).toBe('note');
    expect(overDeny?.properties.severity).toBe('low');
    expect(run.tool.driver.rules[overDeny?.ruleIndex ?? -1]?.properties.owaspApi).toBe('n/a');
  });
});

describe('reportToSarif — hygiene', () => {
  it('is deterministic for a fixed generatedAt', () => {
    expect(JSON.stringify(reportToSarif(vulnerableReport()))).toBe(JSON.stringify(reportToSarif(vulnerableReport())));
  });

  it('carries findings only: no bearer tokens, headers, request or response bodies', () => {
    const report = vulnerableReport();
    // Every passwordHash value in the fixture's records; the vulnerable build echoes them in response bodies.
    const hashes: string[] = [];
    for (const resource of fixture.resources) {
      for (const record of resource.records) {
        const value = (record.fields as Record<string, unknown>).passwordHash;
        if (typeof value === 'string') hashes.push(value);
      }
    }
    expect(hashes.length).toBeGreaterThan(0);
    // The JSON report deliberately keeps that response evidence (fictional hashes); the SARIF must drop all of it.
    const reportText = JSON.stringify(report);
    for (const hash of hashes) expect(reportText).toContain(hash);
    const text = JSON.stringify(reportToSarif(report));
    for (const hash of hashes) expect(text).not.toContain(hash);
    expect(text).not.toContain('mock-token-');
    expect(text).not.toContain('Bearer');
    expect(text).not.toContain('argon2id');
    expect(text).not.toContain('"request":');
    expect(text).not.toContain('"response":');
    expect(text).not.toContain('"headers":');
    expect(text).not.toContain('"cases":');
  });
});
