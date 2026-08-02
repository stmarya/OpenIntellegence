import type { Metadata } from 'next';
import { SideNav } from '@/components/SideNav';
import './globals.css';

export const metadata: Metadata = {
  title: { default: 'OpenIntellegence', template: '%s | OpenIntellegence' },
  description: 'Threat intelligence and security operations platform',
  robots: { index: false, follow: false },
};

/**
 * Application shell.
 *
 * The topbar deliberately makes no claim about data provenance. It previously
 * announced bundled sample-data mode and a global tenant-unavailable state,
 * neither of which survived the move to live endpoints. Provenance is a
 * property of each surface, and each surface states its own; a stale global
 * banner would only teach analysts to ignore the accurate labels.
 */
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <div className="cti-shell">
          <header className="topbar">
            <div>
              <strong>OpenIntellegence</strong>
              <span className="tenant">Every surface states its own data source</span>
            </div>
          </header>
          <aside className="sidebar">
            <strong>CTI Console</strong>
            <SideNav />
          </aside>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}
