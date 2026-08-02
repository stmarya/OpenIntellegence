import type { Metadata } from 'next';
import { TenantScopeIndicator } from '@/components/States';
import './globals.css';

export const metadata: Metadata = {
  title: { default: 'OpenIntellegence', template: '%s | OpenIntellegence' },
  description: 'Threat intelligence and security operations platform',
  robots: { index: false, follow: false },
};

const NAVIGATION_SECTIONS = [
  {
    label: 'Overview',
    items: [
      ['Command center', '/overview'],
      ['Executive intelligence', '/executive'],
    ],
  },
  {
    label: 'Threat intelligence',
    items: [
      ['Intelligence explorer', '/research'],
      ['Vulnerabilities', '/vulnerabilities'],
      ['Indicators', '/indicators'],
      ['Threat actors', '/threat-actors'],
      ['Campaigns', '/campaigns'],
      ['Malware and tools', '/malware'],
      ['Ransomware', '/ransomware'],
      ['ATT&CK coverage', '/attack'],
    ],
  },
  {
    label: 'Investigations',
    items: [
      ['Alerts', '/alerts'],
      ['Correlations', '/correlations'],
      ['Cases', '/cases'],
      ['Investigations', '/investigations'],
      ['Intelligence requirements', '/intelligence-requirements'],
    ],
  },
  {
    label: 'Exposure',
    items: [
      ['Assets', '/assets'],
      ['Software inventory', '/software-inventory'],
      ['Endpoint agents', '/agents'],
      ['Endpoint intents', '/endpoint-intents'],
    ],
  },
  {
    label: 'Intelligence production',
    items: [
      ['Reports', '/reports'],
      ['Advisories', '/advisories'],
      ['Detection content', '/detection-content'],
      ['Collections', '/collections'],
      ['AI analyst', '/ai-analyst'],
    ],
  },
  {
    label: 'Data and integrations',
    items: [
      ['Data sources', '/data-sources'],
      ['Data quality', '/data-quality'],
      ['Connectors', '/connectors'],
      ['Automation', '/automation'],
      ['Developer portal', '/developer'],
    ],
  },
  {
    label: 'Administration',
    items: [
      ['Audit log', '/audit-log'],
      ['System health', '/system-health'],
      ['Settings', '/settings'],
    ],
  },
] as const;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <div className="cti-shell">
          <header className="topbar">
            <div>
              <strong>OpenIntellegence</strong>
              <span className="tenant">Bundled sample-data mode</span>
            </div>
            <TenantScopeIndicator scope="Tenant telemetry unavailable" />
          </header>
          <aside className="sidebar">
            <strong>CTI Console</strong>
            <nav aria-label="Primary navigation">
              {NAVIGATION_SECTIONS.map((section) => (
                <section aria-label={section.label} key={section.label}>
                  <small className="nav-group">{section.label}</small>
                  {section.items.map(([label, href]) => (
                    <a href={href} key={href}>
                      {label}
                    </a>
                  ))}
                </section>
              ))}
            </nav>
          </aside>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}
