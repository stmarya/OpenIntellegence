import { DataTable, type Column } from '@/components/DataTable';
import { EmptyState, FeatureGate } from '@/components/States';
import type { FetchOutcome } from '@/lib/server-fetch';

/**
 * Renders a live collection, or explains precisely why it is absent. It never
 * falls back to sample rows, cached values, or zeroes.
 */
export function ResourceTable<T>({
  outcome,
  columns,
  rowKey,
  caption,
  emptyTitle,
  emptyDetail,
  note,
}: {
  outcome: FetchOutcome<T[]>;
  columns: Column<T>[];
  rowKey: (row: T) => string;
  caption?: string;
  emptyTitle: string;
  emptyDetail: string;
  note?: string | null;
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
    </>
  );
}
