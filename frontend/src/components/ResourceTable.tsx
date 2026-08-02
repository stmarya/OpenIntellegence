import { DataTable, type Column } from '@/components/DataTable';
import { Pagination } from '@/components/Pagination';
import { EmptyState, FeatureGate } from '@/components/States';
import type { PageMeta } from '@/lib/pagination';
import type { FetchOutcome } from '@/lib/server-fetch';

/**
 * Renders a live collection, or explains precisely why it is absent. It never
 * falls back to sample rows, cached values, or zeroes.
 *
 * When `basePath` is supplied the table also reports how much of the
 * collection is on screen. Surfaces that genuinely return a bounded set, such
 * as a fixed capability list, may omit it.
 */
export function ResourceTable<T>({
  outcome,
  columns,
  rowKey,
  caption,
  emptyTitle,
  emptyDetail,
  note,
  page,
  basePath,
}: {
  outcome: FetchOutcome<T[]>;
  columns: Column<T>[];
  rowKey: (row: T) => string;
  caption?: string;
  emptyTitle: string;
  emptyDetail: string;
  note?: string | null;
  page?: PageMeta | null;
  basePath?: string;
}) {
  if (outcome.status === 'unavailable') {
    return (
      <FeatureGate title="Live tenant data unavailable" detail={outcome.reason}>
        <small>No sample rows are substituted, so an outage is never mistaken for an empty environment.</small>
      </FeatureGate>
    );
  }
  if (outcome.data.length === 0) {
    return <EmptyState title={emptyTitle} detail={emptyDetail} />;
  }
  return (
    <>
      <DataTable columns={columns} rows={outcome.data} rowKey={rowKey} caption={caption} />
      {note ? <p className="muted">{note}</p> : null}
      {basePath ? <Pagination basePath={basePath} meta={page ?? null} rowCount={outcome.data.length} /> : null}
    </>
  );
}
