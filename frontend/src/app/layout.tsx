import type { Metadata } from 'next';
import { TenantScopeIndicator } from '@/components/States';
import './globals.css';

export const metadata: Metadata = {
  title: { default: 'OpenIntellegence', template: '%s | OpenIntellegence' },
  description: 'Threat intelligence and security operations platform',
  robots: { index: false, follow: false },
};

const PRIMARY_NAVIGATION = [
  ['Overview', '/overview'],
  ['Vulnerabilities', '/vulnerabilities'],
  ['Intelligence', '/research'],
  ['Indicators', '/indicators'],
  ['Assets', '/assets'],
  ['Alerts', '/alerts'],
  ['Correlations', '/correlations'],
  ['Cases', '/cases'],
  ['Investigations', '/investigations'],
  ['Automation', '/automation'],
  ['Endpoint intents', '/endpoint-intents'],
  ['Reports', '/reports'],
  ['Connectors', '/connectors'],
  ['AI analyst', '/ai-analyst'],
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
              {PRIMARY_NAVIGATION.map(([label, href]) => (
                <a href={href} key={href}>
                  {label}
                </a>
              ))}
            </nav>
          </aside>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}
