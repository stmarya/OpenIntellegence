import { DataTable, type Column } from '@/components/DataTable';
import { RiskBadge } from '@/components/RiskBadge';
import { StatusChip } from '@/components/StatusChip';
import { DemoDataBanner } from '@/components/States';
import { intelligenceRepository } from '@/data/repositories/intelligence-repository';

type VulnerabilityRow = ReturnType<typeof intelligenceRepository.listVulnerabilities>[number];

const columns: Column<VulnerabilityRow>[] = [
  {
    key: 'cve',
    header: 'CVE',
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
    key: 'kev',
    header: 'Exploitation',
    render: (row) =>
      row.knownExploited ? (
        <StatusChip label="Known exploited" tone="blocked" />
      ) : (
        <StatusChip label="Not present in KEV snapshot" tone="unknown" />
      ),
  },
  {
    key: 'cvss',
    header: 'CVSS',
    render: (row) => <>{row.cvssScore ?? 'Unknown'}</>,
  },
  {
    key: 'provenance',
    header: 'Provenance',
    render: (row) => (
      <>
        {row.provenance.sourceFile}
        <br />
        <small>{row.provenance.snapshotLabel}</small>
      </>
    ),
  },
];

export default function VulnerabilitiesPage() {
  const records = intelligenceRepository.listVulnerabilities();
  return (
    <section className="content">
      <DemoDataBanner label="Bundled historical source snapshot." />
      <h1>Vulnerabilities and exposures</h1>
      <DataTable
        columns={columns}
        rows={records}
        rowKey={(row) => row.id}
        caption="Absence from the KEV snapshot is reported as unknown exploitation, never as safe."
      />
    </section>
  );
}
