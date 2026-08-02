import { DataTable, type Column } from '@/components/DataTable';
import { RiskBadge } from '@/components/RiskBadge';
import { DemoDataBanner } from '@/components/States';
import { intelligenceRepository } from '@/data/repositories/intelligence-repository';

type VulnerabilityRow = ReturnType<typeof intelligenceRepository.listVulnerabilities>[number];

export default function OverviewPage() {
  const vulnerabilities = intelligenceRepository.listVulnerabilities();
  const research = intelligenceRepository.listResearchReferences();

  const columns: Column<VulnerabilityRow>[] = [
    {
      key: 'record',
      header: 'Record',
      render: (row) => (
        <>
          <strong>{row.id}</strong>
          <br />
          <small>{row.title}</small>
        </>
      ),
    },
    {
      key: 'risk',
      header: 'Risk',
      render: (row) => <RiskBadge score={row.cvssScore} knownExploited={row.knownExploited} />,
    },
    {
      key: 'cvss',
      header: 'CVSS',
      render: (row) => <>{row.cvssScore ?? 'Unknown'}</>,
    },
    {
      key: 'provenance',
      header: 'Source / freshness',
      render: (row) => (
        <>
          {row.provenance.sourceFile}
          <br />
          <small>{row.provenance.snapshotLabel}</small>
        </>
      ),
    },
  ];

  return (
    <section className="content">
      <DemoDataBanner label="Bundled source snapshot." />
      <h1>Threat intelligence overview</h1>
      <div className="metrics">
        <article>
          <b>{vulnerabilities.length}</b>
          <span>Source-backed vulnerabilities</span>
        </article>
        <article>
          <b>{vulnerabilities.filter((item) => item.knownExploited).length}</b>
          <span>Known exploited</span>
        </article>
        <article>
          <b>{research.length}</b>
          <span>Unverified research references</span>
        </article>
      </div>

      <h2>Vulnerability triage</h2>
      <DataTable
        columns={columns}
        rows={vulnerabilities}
        rowKey={(row) => row.id}
        caption="Unknown CVSS is displayed as Unknown and is never treated as clean."
      />

      <h2>Research references</h2>
      <p className="muted">
        These records are unverified research references and provide no payload, execution, or delivery control.
      </p>
      {research.map((item) => (
        <article className="reference" key={item.id}>
          <strong>{item.repository}</strong>
          <span>Unverified research reference</span>
          <p>{item.description}</p>
          <small>{item.provenance.snapshotLabel}</small>
        </article>
      ))}
    </section>
  );
}
