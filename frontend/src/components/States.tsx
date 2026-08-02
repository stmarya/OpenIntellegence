import type { ReactNode } from 'react';

export function DemoDataBanner({ label }: { label: string }) {
  return (
    <p className="banner" role="note">
      {label} This is a bundled historical snapshot, not live tenant telemetry.
    </p>
  );
}

export function TenantScopeIndicator({ scope }: { scope: string }) {
  return <span className="scope">{scope}</span>;
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <section className="state state-empty">
      <h2>{title}</h2>
      <p className="muted">{detail}</p>
    </section>
  );
}

export function LoadingState({ label = 'Loading records' }: { label?: string }) {
  return (
    <p className="state state-loading" role="status" aria-live="polite">
      {label}…
    </p>
  );
}

export function ErrorState({ title, detail }: { title: string; detail: string }) {
  return (
    <section className="state state-error" role="alert">
      <h2>{title}</h2>
      <p className="muted">{detail}</p>
    </section>
  );
}

export function FeatureGate({ title, detail, children }: { title: string; detail: string; children?: ReactNode }) {
  return (
    <section className="state state-gated">
      <h2>{title}</h2>
      <p className="muted">{detail}</p>
      {children}
    </section>
  );
}
