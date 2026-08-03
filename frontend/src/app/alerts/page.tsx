import type { Metadata } from 'next';
import Link from 'next/link';
import type { Column } from '@/components/DataTable';
import { ResourceTable } from '@/components/ResourceTable';
import { StatusChip } from '@/components/StatusChip';
import { pageMetaOf, readPageState, withPageQuery, type SearchParams } from '@/lib/pagination';
import { fetchList, rowsOf, unknown } from '@/lib/server-fetch';
export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Alerts' };
type AlertRow = { id:string; title?:string|null; summary?:string|null; severity?:string|null; status?:string|null; entity_type?:string|null; entity_id?:string|null; risk_score?:number|null; occurrences?:number|null; last_triggered_at?:string|null };
const columns: Column<AlertRow>[] = [
  { key:'alert', header:'Alert', render:(row)=><><Link href={`/alerts/${encodeURIComponent(row.id)}`}><strong>{unknown(row.title)}</strong></Link><br/><small>{row.summary ?? 'No summary recorded.'}</small></> },
  { key:'severity', header:'Severity', render:(row)=>row.severity ? <StatusChip label={row.severity} tone={row.severity === 'critical' || row.severity === 'high' ? 'blocked' : 'neutral'} /> : <StatusChip label="Unknown" tone="unknown"/> },
  { key:'status', header:'Triage state', render:(row)=>row.status === 'acknowledged' ? <StatusChip label="Acknowledged" tone="approved"/> : <StatusChip label={row.status ?? 'open'} tone="pending"/> },
  { key:'entity', header:'Entity', render:(row)=><small>{unknown(row.entity_type)} · {unknown(row.entity_id)}</small> },
  { key:'activity', header:'Occurrences / last seen', render:(row)=><>{row.occurrences ?? 'Unknown'}<br/><small>{unknown(row.last_triggered_at)}</small></> },
];
export default async function AlertsPage({searchParams}:{searchParams?:SearchParams}) {
  const state=readPageState(searchParams); const envelope=await fetchList<AlertRow>(withPageQuery('/alerts',state));
  return <section className="content"><h1>Alerts</h1><p className="muted">Repeat triggers increment an occurrence counter instead of burying the queue in duplicates.</p><ResourceTable outcome={rowsOf(envelope)} columns={columns} rowKey={(row)=>row.id} page={pageMetaOf(envelope)} basePath="/alerts" emptyTitle="No alerts raised" emptyDetail="The API responded successfully and no alert has fired for this tenant." caption="Ordering follows risk score, then most recent trigger."/></section>;
}
