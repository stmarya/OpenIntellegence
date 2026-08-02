import Link from 'next/link';
import { describeRange, pageHref, type PageMeta } from '@/lib/pagination';

/**
 * Page controls that state the size of what is being withheld.
 *
 * When the API returns no page metadata, this renders a caveat instead of
 * silently implying the visible rows are everything. An unknown total is
 * reported as unknown, in keeping with the rest of the console.
 */
export function Pagination({
  basePath,
  meta,
  rowCount,
}: {
  basePath: string;
  meta: PageMeta | null;
  rowCount: number;
}) {
  if (!meta) {
    return (
      <p className="muted">
        The API did not report a total for this collection, so the console cannot say whether these {rowCount} rows are
        the complete set. Treat this view as a sample rather than an inventory.
      </p>
    );
  }

  const previousOffset = meta.offset - meta.limit;
  const nextOffset = meta.offset + meta.limit;
  const hasPrevious = meta.offset > 0;
  const hasNext = meta.has_more || nextOffset < meta.total;

  return (
    <nav className="pagination" aria-label="Pagination">
      <p className="muted">{describeRange(meta, rowCount)}</p>
      <span>
        {hasPrevious ? (
          <Link href={pageHref(basePath, meta.limit, previousOffset)} rel="prev">
            Previous page
          </Link>
        ) : (
          <span className="muted">Previous page</span>
        )}
        {' \u00b7 '}
        {hasNext ? (
          <Link href={pageHref(basePath, meta.limit, nextOffset)} rel="next">
            Next page
          </Link>
        ) : (
          <span className="muted">Next page</span>
        )}
      </span>
    </nav>
  );
}
