/**
 * Reusable UI primitives in GravityZone style:
 * Dense dark, teal #16A9A0, 4px radius, 120ms motion, no decorative shadows.
 */
import type { Provenance, RemoteState } from "@/lib/api/types";
import React from "react";

// ---------------------------------------------------------------------------
// StatusBadge
// ---------------------------------------------------------------------------

type SeverityLevel = "critical" | "high" | "medium" | "low";

const SEVERITY_STYLES: Record<SeverityLevel, string> = {
  critical: "bg-red-900/50 text-red-300 border border-red-700/40",
  high:     "bg-orange-900/50 text-orange-300 border border-orange-700/40",
  medium:   "bg-amber-900/50 text-amber-300 border border-amber-700/40",
  low:      "bg-blue-900/50 text-blue-300 border border-blue-700/40",
};

export function SeverityBadge({ level }: { level: SeverityLevel | null | undefined }) {
  if (!level) return <span className="text-[--text-muted] text-xs">—</span>;
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-medium uppercase tracking-wide ${SEVERITY_STYLES[level]}`}>
      {level}
    </span>
  );
}

// ---------------------------------------------------------------------------
// CvssScore
// ---------------------------------------------------------------------------

export function CvssScore({ score }: { score: number | null | undefined }) {
  if (score == null) {
    return <span className="text-[--text-muted] text-xs">not yet scored</span>;
  }
  const colour =
    score >= 9 ? "text-red-400"
    : score >= 7 ? "text-orange-400"
    : score >= 4 ? "text-amber-400"
    : "text-green-400";
  return <span className={`font-mono text-sm font-semibold ${colour}`}>{score.toFixed(1)}</span>;
}

// ---------------------------------------------------------------------------
// ProvenanceBanner
// ---------------------------------------------------------------------------

export function ProvenanceBanner({ prov }: { prov: Provenance }) {
  if (!prov.is_partial) return null;
  return (
    <div className="flex items-start gap-2 rounded px-3 py-2 bg-amber-950/40 border border-amber-700/30 text-amber-300 text-xs mb-4">
      <span className="mt-0.5 shrink-0">⚠</span>
      <span>{prov.note ?? "Some data feeds are degraded; figures may be incomplete."}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skeleton loader
// ---------------------------------------------------------------------------

export function SkeletonRow({ cols = 4 }: { cols?: number }) {
  return (
    <tr>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-3 py-2">
          <div className="h-3 rounded bg-[--bg-overlay] animate-pulse w-full" />
        </td>
      ))}
    </tr>
  );
}

// ---------------------------------------------------------------------------
// EmptyState
// ---------------------------------------------------------------------------

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-[--text-muted]">
      <span className="text-3xl mb-3">◯</span>
      <p className="text-sm">{message}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ErrorState
// ---------------------------------------------------------------------------

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-red-400">
      <span className="text-3xl mb-3">✕</span>
      <p className="text-sm">{message}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// RemoteView — generic component for RemoteState rendering
// ---------------------------------------------------------------------------

interface RemoteViewProps<T> {
  state: RemoteState<T>;
  renderData: (data: T, prov?: Provenance) => React.ReactNode;
  skeletonRows?: number;
  skeletonCols?: number;
  emptyMessage?: string;
}

export function RemoteView<T>({
  state,
  renderData,
  skeletonRows = 5,
  skeletonCols = 4,
  emptyMessage = "No records found.",
}: RemoteViewProps<T>) {
  if (state.status === "idle" || state.status === "loading") {
    return (
      <table className="w-full text-sm">
        <tbody>
          {Array.from({ length: skeletonRows }).map((_, i) => (
            <SkeletonRow key={i} cols={skeletonCols} />
          ))}
        </tbody>
      </table>
    );
  }
  if (state.status === "error") {
    return <ErrorState message={state.message} />;
  }
  if (state.status === "empty") {
    return (
      <>
        {state.provenance && <ProvenanceBanner prov={state.provenance} />}
        <EmptyState message={emptyMessage} />
      </>
    );
  }
  const prov = "provenance" in state ? state.provenance : undefined;
  const data = state.data;
  return (
    <>
      {prov && <ProvenanceBanner prov={prov} />}
      {renderData(data, prov)}
    </>
  );
}

// ---------------------------------------------------------------------------
// MockBadge — visual indicator that mock data is active
// ---------------------------------------------------------------------------

export function MockBadge() {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-widest bg-teal-950/60 text-teal-400 border border-teal-700/30">
      <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse" />
      Mock Data
    </span>
  );
}

// ---------------------------------------------------------------------------
// PageHeader
// ---------------------------------------------------------------------------

export function PageHeader({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <h1 className="text-base font-semibold text-[--text-primary]">{title}</h1>
        {subtitle && <p className="text-xs text-[--text-secondary] mt-0.5">{subtitle}</p>}
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  );
}
