import { intelligenceRepository } from '@/data/repositories/intelligence-repository';

export default function VulnerabilitiesPage() {
  const records = intelligenceRepository.listVulnerabilities();
  return <main className="content"><p className="banner">Bundled historical source snapshot — not live tenant exposure data.</p><h1>Vulnerabilities & exposures</h1><table><thead><tr><th>CVE</th><th>Known exploited</th><th>CVSS</th><th>Provenance</th></tr></thead><tbody>{records.map(record => <tr key={record.id}><td><strong>{record.id}</strong><br/><small>{record.title}</small></td><td>{record.knownExploited ? 'Known exploited' : 'Not present in KEV snapshot'}</td><td>{record.cvssScore ?? 'Unknown'}</td><td>{record.provenance.sourceFile}<br/><small>{record.provenance.snapshotLabel}</small></td></tr>)}</tbody></table></main>;
}
