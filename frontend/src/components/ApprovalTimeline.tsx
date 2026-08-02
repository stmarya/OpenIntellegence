export type ApprovalEvent = {
  id: string;
  label: string;
  actor: string | null;
  occurredAt: string | null;
};

/**
 * Renders an approval history for control-plane requests. This component never
 * renders dispatch, execution, or delivery affordances.
 */
export function ApprovalTimeline({ events }: { events: ApprovalEvent[] }) {
  if (events.length === 0) {
    return <p className="muted">No approval history is available for this request.</p>;
  }
  return (
    <ol className="timeline">
      {events.map((event) => (
        <li key={event.id}>
          <strong>{event.label}</strong>
          <span>{event.actor ?? 'Actor unknown'}</span>
          <small>{event.occurredAt ?? 'Timestamp unknown'}</small>
        </li>
      ))}
    </ol>
  );
}
