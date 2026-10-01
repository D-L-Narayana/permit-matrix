import type { CaseResult, Contract, Coverage, Finding, SuiteRun, Verdict } from './types';

export interface Report {
  schema: 'permitmatrix.report/1';
  generatedAt: string;
  tool: { name: 'permitmatrix'; mode: 'browser-local deterministic simulation' };
  contract: { name: string; version: string; servers: string[] };
  build: { id: string; label: string; flaws: { endpoint: string; kind: string }[] };
  summary: { cases: number; findings: number; byVerdict: Record<Verdict, number>; bySeverity: Record<Finding['severity'], number> };
  findings: Finding[];
  coverage: Coverage;
  cases: CaseResult[];
  dataNote: string;
  disclaimer: string;
}

export const DATA_NOTE =
  'Authorization headers are redacted. Response bodies are not redacted: they are the evidence of what the mock returned, including fields marked sensitive (for example passwordHash). Every value is fictional demo data from the contract; never load a contract containing real records.';

export const DISCLAIMER =
  'Educational prototype. Results describe a deterministic in-browser mock of the supplied contract, not a live system. This is not a penetration test, security certification or compliance opinion.';

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === 'authorization') {
      const subject = v.match(/^Bearer mock-token-([a-z0-9._-]+)$/i)?.[1];
      out[k] = `Bearer [redacted:${subject ?? 'unknown'}]`;
    } else {
      out[k] = v;
    }
  }
  return out;
}

export function buildReport(contract: Contract, run: SuiteRun, options: { build: string; generatedAt?: string }): Report {
  const build = contract.builds[options.build] ?? { label: options.build, flaws: [] };
  const byVerdict: Record<Verdict, number> = { pass: 0, bypass: 0, 'over-deny': 0, exposure: 0, 'mass-assignment': 0, error: 0 };
  for (const r of run.results) byVerdict[r.verdict] += 1;
  const bySeverity: Record<Finding['severity'], number> = { high: 0, medium: 0, low: 0 };
  for (const f of run.findings) bySeverity[f.severity] += 1;
  return {
    schema: 'permitmatrix.report/1',
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    tool: { name: 'permitmatrix', mode: 'browser-local deterministic simulation' },
    contract: { name: contract.name, version: contract.version, servers: [...contract.servers] },
    build: { id: options.build, label: build.label, flaws: build.flaws.map((f) => ({ ...f })) },
    summary: { cases: run.results.length, findings: run.findings.length, byVerdict, bySeverity },
    findings: run.findings.map((f) => ({ ...f, evidenceCases: [...f.evidenceCases] })),
    coverage: run.coverage,
    cases: run.results.map((r) => ({ ...r, request: { ...r.request, headers: redactHeaders(r.request.headers) } })),
    dataNote: DATA_NOTE,
    disclaimer: DISCLAIMER,
  };
}

export function reportToMarkdown(report: Report): string {
  const lines: string[] = [];
  lines.push(`# Authorization contract test — ${report.contract.name} ${report.contract.version}`);
  lines.push('');
  lines.push(`Generated ${report.generatedAt} · build: ${report.build.label} · ${report.summary.cases} cases · ${report.summary.findings} findings`);
  lines.push('');
  lines.push(`> ${report.disclaimer}`);
  lines.push('');
  lines.push(`> ${report.dataNote}`);
  lines.push('');
  lines.push('## Findings');
  if (report.findings.length === 0) lines.push('No authorization findings. Every generated case matched the contract.');
  for (const f of report.findings) {
    lines.push('');
    lines.push(`### ${f.severity.toUpperCase()} · ${f.title} (${f.owaspApi}) — \`${f.endpoint}\``);
    lines.push(`Evidence cases: ${f.evidenceCases.length}. ${f.remediation}`);
  }
  lines.push('');
  lines.push('## Coverage (cases per endpoint × role: passed / total)');
  const roles = Object.keys(Object.values(report.coverage)[0] ?? {});
  lines.push(`| Endpoint | ${roles.join(' | ')} |`);
  lines.push(`|---|${roles.map(() => '---').join('|')}|`);
  for (const [endpoint, cells] of Object.entries(report.coverage)) {
    lines.push(`| ${endpoint} | ${roles.map((r) => `${cells[r].pass}/${cells[r].total}`).join(' | ')} |`);
  }
  return lines.join('\n');
}
