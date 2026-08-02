export function UnavailableState({ title, detail }: { title: string; detail: string }) {
  return <main className="content"><p className="banner">Tenant-scoped live data is unavailable in bundled sample-data mode.</p><h1>{title}</h1><section className="reference"><strong>Awaiting API integration</strong><p>{detail}</p><small>No synthetic tenant telemetry, completion result, or delivery state is shown.</small></section></main>;
}
