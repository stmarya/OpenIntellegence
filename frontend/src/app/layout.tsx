import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: { default: 'OpenIntellegence', template: '%s | OpenIntellegence' },
  description: 'Threat intelligence and security operations platform',
  robots: { index: false, follow: false },
};

const primary = [
  ['Overview', '/overview'], ['Vulnerabilities', '/vulnerabilities'], ['Intelligence', '/research'],
  ['Indicators', '/indicators'], ['Assets', '/assets'], ['Alerts', '/alerts'], ['Correlations', '/correlations'],
  ['Investigations', '/investigations'], ['Automation', '/automation'], ['Endpoint intents', '/endpoint-intents'],
  ['Reports', '/reports'], ['Connectors', '/connectors'], ['AI analyst', '/ai-analyst'],
] as const;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en" className="dark"><body className="bg-surface text-text-primary antialiased">
    <header className="topbar"><div><strong>OpenIntellegence</strong><span className="tenant">Bundled sample-data mode</span></div><span className="scope">Tenant telemetry unavailable</span></header>
    <div className="cti-shell"><aside className="sidebar"><strong>CTI Console</strong><nav aria-label="Primary navigation">{primary.map(([label, href]) => <a href={href} key={href}>{label}</a>)}</nav></aside><section>{children}</section></div>
  </body></html>;
}
