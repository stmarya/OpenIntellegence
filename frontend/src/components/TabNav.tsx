import Link from 'next/link';

/**
 * Section navigation for entity detail surfaces.
 *
 * Tabs are rendered from what a surface can actually populate. A tab that
 * exists only to be empty teaches analysts that empty means "nothing found",
 * when it really means "never implemented", so unavailable sections are
 * declared in prose instead of being shown as hollow tabs.
 */

export interface TabDefinition {
  key: string;
  label: string;
}

export function TabNav({
  basePath,
  tabs,
  active,
}: {
  basePath: string;
  tabs: TabDefinition[];
  active: string;
}) {
  return (
    <nav aria-label="Detail sections" className="muted">
      {tabs.map((tab, index) => (
        <span key={tab.key}>
          {index > 0 ? ' \u00b7 ' : null}
          {tab.key === active ? (
            <strong aria-current="page">{tab.label}</strong>
          ) : (
            <Link href={`${basePath}?tab=${encodeURIComponent(tab.key)}`}>{tab.label}</Link>
          )}
        </span>
      ))}
    </nav>
  );
}

/** Resolve the requested tab, falling back to the first defined tab. */
export function resolveTab(
  tabs: TabDefinition[],
  requested: string | string[] | undefined
): string {
  const raw = Array.isArray(requested) ? requested[0] : requested;
  return tabs.some((tab) => tab.key === raw) && raw ? raw : tabs[0].key;
}
