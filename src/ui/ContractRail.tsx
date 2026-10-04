import type { ReactNode } from 'react';
import type { Contract } from '../engine/types';

export interface ContractRailProps {
  contract: Contract;
  notice: string;
  /** Optional slot rendered after the outline lists (the lead places the contract-health lint panel here). */
  health?: ReactNode;
}

export function ContractRail({ contract, notice, health }: ContractRailProps) {
  return (
    <aside className="rail" aria-label="Contract outline">
      <h2 className="section">Roles</h2>
      <ul>{contract.roles.map((r) => <li key={r.id}><code>{r.id}</code><span className="muted">{r.label}</span></li>)}</ul>
      <h2 className="section">Principals</h2>
      <ul>{contract.principals.map((p) => <li key={p.id}><code>{p.id}</code><span className="muted">{p.role} · {p.tenant}</span></li>)}</ul>
      <h2 className="section">Endpoints</h2>
      <ul>{contract.endpoints.map((e) => (
        <li key={e.id}><span className={`pill method-${e.method}`}>{e.method}</span><code>{e.path}</code></li>
      ))}</ul>
      <h2 className="section">Resources</h2>
      <ul>{contract.resources.map((r) => <li key={r.id}><code>{r.id}</code><span className="muted">{r.records.length} records</span></li>)}</ul>
      {health}
      <p className="notice" role="status">{notice}</p>
    </aside>
  );
}
