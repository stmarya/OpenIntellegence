'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const NAVIGATION_SECTIONS = [
  {
    label: 'Overview',
    items: [
      ['Command center', '/overview'],
      ['Executive intelligence', '/executive'],
      ['My workspace', '/workspace'],
    ],
  },
  {
    label: 'Threat intelligence',
    items: [
      ['Intelligence explorer', '/research'],
      ['Investigation graph', '/graph'],
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
      ['Action workbench', '/actions'],
      ['Alerts', '/alerts'],
      ['Alert rules', '/alert-rules'],
      ['Sightings', '/sightings'],
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
      ['Import workbench', '/import'],
      ['Integrations', '/integrations'],
      ['Automation', '/automation'],
      ['Developer portal', '/developer'],
    ],
  },
  {
    label: 'Administration',
    items: [
      ['Access and roles', '/access'],
      ['Tenants and sharing', '/tenants'],
      ['Audit log', '/audit-log'],
      ['System health', '/system-health'],
      ['Settings', '/settings'],
    ],
  },
] as const;

export function SideNav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Primary navigation">
      {NAVIGATION_SECTIONS.map((section) => (
        <section aria-label={section.label} key={section.label}>
          <small className="nav-group">{section.label}</small>
          {section.items.map(([label, href]) => {
            const active = pathname === href || pathname.startsWith(`${href}/`);
            return (
              <Link
                href={href}
                key={href}
                aria-current={active ? 'page' : undefined}
                style={active ? { color: 'var(--accent)', fontWeight: 600 } : undefined}
              >
                {label}
              </Link>
            );
          })}
        </section>
      ))}
    </nav>
  );
}
