import type { CaseResult, Contract, ContractWarning, Coverage, Finding, Flaw, Severity, SuiteRun, Verdict } from './types';

export interface Report {
  schema: 'permitmatrix.report/1';
  generatedAt: string;
  tool: { name: 'permitmatrix'; mode: 'browser-local deterministic simulation' };
  contract: { name: string; version: string; servers: string[] };
  /** `flaws` are the flaws that were active for the run when the caller supplied them, else the build definition. */
  build: { id: string; label: string; flaws: { endpoint: string; kind: string }[] };
  summary: { cases: number; findings: number; byVerdict: Record<Verdict, number>; bySeverity: Record<Severity, number> };
  findings: Finding[];
  coverage: Coverage;
  cases: CaseResult[];
  /** Contract linter output; present only when the caller supplied it (an empty list means "linted, nothing found"). */
  warnings?: ContractWarning[];
  dataNote: string;
  disclaimer: string;
}

export interface ReportOptions {
  build: string;
  generatedAt?: string;
  /** The flaws actually active for `run` (toggle switches). Without it the report echoes the build definition. */
  flaws?: Flaw[];
  warnings?: ContractWarning[];
}

export const DATA_NOTE =
  'Authorization headers are redacted. Response bodies are not redacted: they are the evidence of what the mock returned, including fields marked sensitive (for example passwordHash). Every value is fictional demo data from the contract; never load a contract containing real records.';

export const DISCLAIMER =
  'Educational prototype. Results describe a deterministic in-browser mock of the supplied contract, not a live system. This is not a penetration test, security certification or compliance opinion.';

/** Triage scale used by the runner; stated in the memo so readers do not mistake it for CVSS. */
const SEVERITY_RUBRIC =
  'Severities are a triage scale, not CVSS. Object, function and authentication bypass are high. Mass assignment is high when the probed field name looks privilege- or money-bearing (role, admin, status, owner, tenant, price, amount), otherwise medium. Sensitive exposure is high when the field name looks credential-like (password, secret, token, hash, ssn, key), otherwise medium. Over-deny is low: a functional regression, never a security pass.';

const VERDICT_ORDER: Verdict[] = ['pass', 'bypass', 'over-deny', 'exposure', 'mass-assignment', 'error'];
const MEMO_EVIDENCE_LIMIT = 8;

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

export function buildReport(contract: Contract, run: SuiteRun, options: ReportOptions): Report {
  const build = contract.builds[options.build] ?? { label: options.build, flaws: [] };
  // The UI lets the user toggle individual flaws, so the build definition may not be what actually ran.
  const flaws = options.flaws ?? build.flaws;
  const byVerdict: Record<Verdict, number> = { pass: 0, bypass: 0, 'over-deny': 0, exposure: 0, 'mass-assignment': 0, error: 0 };
  for (const r of run.results) byVerdict[r.verdict] += 1;
  const bySeverity: Record<Severity, number> = { high: 0, medium: 0, low: 0 };
  for (const f of run.findings) bySeverity[f.severity] += 1;
  return {
    schema: 'permitmatrix.report/1',
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    tool: { name: 'permitmatrix', mode: 'browser-local deterministic simulation' },
    contract: { name: contract.name, version: contract.version, servers: [...contract.servers] },
    build: { id: options.build, label: build.label, flaws: flaws.map((f) => ({ endpoint: f.endpoint, kind: f.kind })) },
    summary: { cases: run.results.length, findings: run.findings.length, byVerdict, bySeverity },
    findings: run.findings.map((f) => ({ ...f, evidenceCases: [...f.evidenceCases] })),
    coverage: run.coverage,
    cases: run.results.map((r) => ({ ...r, request: { ...r.request, headers: redactHeaders(r.request.headers) } })),
    ...(options.warnings ? { warnings: options.warnings.map((w) => ({ ...w })) } : {}),
    dataNote: DATA_NOTE,
    disclaimer: DISCLAIMER,
  };
}

/** Property probes end their id in `read:<field>` / `write:<field>`; the field is not stored on the result itself. */
function probeFieldOf(caseId: string): string | undefined {
  const last = caseId.slice(caseId.lastIndexOf('|') + 1);
  return /^(?:read|write):(.+)$/.exec(last)?.[1];
}

function evidenceLine(caseId: string, result: CaseResult | undefined): string {
  if (!result) return `${caseId}: not present in this report.`;
  const probe = probeFieldOf(caseId);
  return `${result.principal} · ${result.targetKind}${probe ? ` · ${probe}` : ''}: ${result.explanation}`;
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

  lines.push('## Summary');
  lines.push('');
  lines.push('| Verdict | Cases |');
  lines.push('|---|---|');
  for (const verdict of VERDICT_ORDER) lines.push(`| ${verdict} | ${report.summary.byVerdict[verdict]} |`);
  lines.push('');
  const { high, medium, low } = report.summary.bySeverity;
  lines.push(`Findings by severity: high ${high} · medium ${medium} · low ${low}`);
  lines.push('');

  lines.push('## Active seeded flaws');
  lines.push('');
  if (report.build.flaws.length === 0) lines.push('None');
  for (const f of report.build.flaws) lines.push(`- ${f.endpoint} · ${f.kind}`);
  lines.push('');

  lines.push('## Findings');
  if (report.findings.length === 0) lines.push('No authorization findings. Every generated case matched the contract.');
  const caseById = new Map(report.cases.map((c) => [c.caseId, c]));
  for (const f of report.findings) {
    lines.push('');
    lines.push(`### ${f.severity.toUpperCase()} · ${f.title} (${f.owaspApi}) — \`${f.endpoint}\``);
    lines.push(`Evidence cases: ${f.evidenceCases.length}. ${f.remediation}`);
    for (const id of f.evidenceCases.slice(0, MEMO_EVIDENCE_LIMIT)) lines.push(`- ${evidenceLine(id, caseById.get(id))}`);
    if (f.evidenceCases.length > MEMO_EVIDENCE_LIMIT) {
      lines.push('');
      lines.push(`+${f.evidenceCases.length - MEMO_EVIDENCE_LIMIT} more evidence case(s) are listed in the JSON report.`);
    }
  }
  lines.push('');

  if (report.warnings && report.warnings.length > 0) {
    lines.push('## Contract warnings');
    lines.push('');
    for (const w of report.warnings) lines.push(`- ${w.severity} · ${w.code} · ${w.path} · ${w.message}`);
    lines.push('');
  }

  lines.push('## Severity rubric');
  lines.push('');
  lines.push(SEVERITY_RUBRIC);
  lines.push('');

  lines.push('## Coverage (cases per endpoint × role: passed / total)');
  lines.push('');
  // Column set is the union of coverage keys, so an anonymous column appears as soon as the runner emits one.
  const columns: string[] = [];
  for (const cells of Object.values(report.coverage)) for (const key of Object.keys(cells)) if (!columns.includes(key)) columns.push(key);
  lines.push(`| Endpoint | ${columns.join(' | ')} |`);
  lines.push(`|---|${columns.map(() => '---').join('|')}|`);
  for (const [endpoint, cells] of Object.entries(report.coverage)) {
    lines.push(`| ${endpoint} | ${columns.map((c) => (cells[c] ? `${cells[c].pass}/${cells[c].total}` : '–')).join(' | ')} |`);
  }
  return lines.join('\n');
}
