export type StatusTone = 'neutral' | 'pending' | 'approved' | 'blocked' | 'unknown';

export function StatusChip({ label, tone = 'neutral' }: { label: string; tone?: StatusTone }) {
  return <span className={`chip chip-${tone}`}>{label}</span>;
}
