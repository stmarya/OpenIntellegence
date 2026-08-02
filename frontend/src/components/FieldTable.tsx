import type { ReactNode } from 'react';
import { DataTable, type Column } from '@/components/DataTable';

export type Field = { key: string; label: string; value: ReactNode };

const columns: Column<Field>[] = [
  { key: 'label', header: 'Field', render: (row) => <strong>{row.label}</strong> },
  { key: 'value', header: 'Value', render: (row) => <>{row.value}</> },
];

/**
 * Renders a record's attributes with the same table styling as collections, so
 * a detail view never looks like a different product.
 */
export function FieldTable({ fields, caption }: { fields: Field[]; caption?: string }) {
  return <DataTable columns={columns} rows={fields} rowKey={(row) => row.key} caption={caption} />;
}
