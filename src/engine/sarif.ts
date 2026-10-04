import type { Report } from './report';
import type { FindingKind, OwaspApi, Severity } from './types';

/**
 * The subset of SARIF 2.1.0 that permitmatrix emits. Findings only: the log never carries cases,
 * request headers or response bodies, so it can be attached to a ticket or a code-scanning upload
 * without re-checking the redaction rules that apply to the JSON report.
 */
export type SarifLevel = 'error' | 'warning' | 'note';
export interface SarifMessage { text: string }
export interface SarifRule {
  id: FindingKind;
  name: string;
  shortDescription: SarifMessage;
  fullDescription: SarifMessage;
  help: SarifMessage;
  helpUri: string;
  properties: { owaspApi: OwaspApi; tags: string[] };
}
export interface SarifLogicalLocation { fullyQualifiedName: string; kind: 'endpoint' }
export interface SarifResult {
  ruleId: FindingKind;
  ruleIndex: number;
  level: SarifLevel;
  message: SarifMessage;
  locations: { logicalLocations: SarifLogicalLocation[] }[];
  properties: { endpoint: string; severity: Severity; evidenceCases: string[] };
}
export interface SarifInvocation { executionSuccessful: true; endTimeUtc: string }
export interface SarifRunProperties {
  disclaimer: string;
  dataNote: string;
  contract: Report['contract'];
  build: Report['build'];
  generatedAt: string;
}
export interface SarifDriver { name: 'permitmatrix'; semanticVersion: string; informationUri: string; rules: SarifRule[] }
export interface SarifRun {
  tool: { driver: SarifDriver };
  invocations: SarifInvocation[];
  results: SarifResult[];
  properties: SarifRunProperties;
}
export interface SarifLog {
  $schema: 'https://json.schemastore.org/sarif-2.1.0.json';
  version: '2.1.0';
  runs: SarifRun[];
}

// These URLs are identifiers written into the exported file; nothing in the app ever requests them.
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const INFORMATION_URI = 'https://github.com/D-L-Narayana/permit-matrix';
const OWASP_API_TOP10_2023 = 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/';
/** Mirrors package.json `version`; kept literal so the engine bundle does not embed the manifest. */
const SEMANTIC_VERSION = '0.1.0';

const LEVEL_FOR: Record<Severity, SarifLevel> = { high: 'error', medium: 'warning', low: 'note' };

/** `object-bypass` → `ObjectBypass`: SARIF rule names are conventionally UpperCamelCase. */
function ruleName(kind: FindingKind): string {
  return kind.split('-').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('');
}

export function reportToSarif(report: Report): SarifLog {
  // One rule per finding kind present, in first-seen order; the title/remediation come from the finding
  // itself so this module never duplicates the runner's catalogue.
  const rules: SarifRule[] = [];
  for (const f of report.findings) {
    if (rules.some((r) => r.id === f.kind)) continue;
    rules.push({
      id: f.kind,
      name: ruleName(f.kind),
      shortDescription: { text: f.title },
      fullDescription: { text: f.remediation },
      help: { text: f.remediation },
      helpUri: OWASP_API_TOP10_2023,
      properties: { owaspApi: f.owaspApi, tags: ['security', 'authorization', f.owaspApi] },
    });
  }

  const results: SarifResult[] = report.findings.map((f) => ({
    ruleId: f.kind,
    ruleIndex: rules.findIndex((r) => r.id === f.kind),
    level: LEVEL_FOR[f.severity],
    message: { text: `${f.title} on ${f.endpoint} (${f.owaspApi}); ${f.evidenceCases.length} evidence case(s).` },
    // Endpoints are logical locations: there is no source file in a contract-driven simulation.
    locations: [{ logicalLocations: [{ fullyQualifiedName: f.endpoint, kind: 'endpoint' }] }],
    properties: { endpoint: f.endpoint, severity: f.severity, evidenceCases: [...f.evidenceCases] },
  }));

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'permitmatrix', semanticVersion: SEMANTIC_VERSION, informationUri: INFORMATION_URI, rules } },
      invocations: [{ executionSuccessful: true, endTimeUtc: report.generatedAt }],
      results,
      properties: {
        disclaimer: report.disclaimer,
        dataNote: report.dataNote,
        contract: { ...report.contract, servers: [...report.contract.servers] },
        build: { ...report.build, flaws: report.build.flaws.map((x) => ({ ...x })) },
        generatedAt: report.generatedAt,
      },
    }],
  };
}
