import { intelligenceRepository } from '@/data/repositories/intelligence-repository';

function risk(score: number | null, kev: boolean) {
  if (kev) return 'Critical';
  if (score === null) return 'Unknown';
  return score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Low';
}

export default function OverviewPage() {
  const vulnerabilities = intelligenceRepository.listVulnerabilities();
  const research = intelligenceRepository.listResearchReferences();
  return <main className="cti-shell">
    <header className="topbar"><div><strong>OpenIntellegence</strong><span className="tenant">Bundled sample-data mode</span></div><span className="scope">Tenant telemetry unavailable</span></header>
    <aside className="sidebar"><strong>CTI Console</strong><nav><a href="/overview">Overview</a><a href="/vulnerabilities">Vulnerabilities</a><a href="/research">Research references</a><span>Assets — unavailable</span><span>Alerts — unavailable</span><span>Endpoint intents — awaiting API</span></nav></aside>
    <section className="content"><p className="banner">Historical bundled source snapshot. This is not live tenant telemetry.</p><h1>Threat intelligence overview</h1><div className="metrics"><article><b>{vulnerabilities.length}</b><span>Source-backed vulnerabilities</span></article><article><b>{vulnerabilities.filter(v => v.knownExploited).length}</b><span>Known exploited</span></article><article><b>{research.length}</b><span>Unverified research references</span></article></div><h2>Vulnerability triage</h2><table><thead><tr><th>Record</th><th>Risk</th><th>CVSS</th><th>Source / freshness</th></tr></thead><tbody>{vulnerabilities.map(v => <tr key={v.id}><td><strong>{v.id}</strong><br/><small>{v.title}</small></td><td><span className={`risk ${risk(v.cvssScore,v.knownExploited).toLowerCase()}`}>{risk(v.cvssScore,v.knownExploited)}</span></td><td>{v.cvssScore ?? 'Unknown'}</td><td>{v.provenance.sourceFile}<br/><small>{v.provenance.snapshotLabel}</small></td></tr>)}</tbody></table><h2>Research references</h2><p className="muted">These records are unverified research references and provide no payload, execution, or delivery control.</p>{research.map(r => <article className="reference" key={r.id}><strong>{r.repository}</strong><span>Unverified research reference</span><p>{r.description}</p><small>{r.provenance.snapshotLabel}</small></article>)}</section>
  </main>;
}
