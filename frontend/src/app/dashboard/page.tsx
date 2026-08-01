"use client";

import { api, fromListResponse, idle, loading, USE_MOCK } from "@/lib/api";
import type { RemoteState } from "@/lib/api/types";
import type { Alert, Asset, Correlation, Vulnerability } from "@/lib/api/types";
import {
  CvssScore,
  EmptyState,
  ErrorState,
  MockBadge,
  PageHeader,
  ProvenanceBanner,
  SeverityBadge,
} from "@/components/ui";
import { useEffect, useState } from "react";

interface DashboardState {
  vulns: RemoteState<Vulnerability[]>;
  assets: RemoteState<Asset[]>;
  alerts: RemoteState<Alert[]>;
  correlations: RemoteState<Correlation[]>;
}

export default function DashboardPage() {
  const [state, setState] = useState<DashboardState>({
    vulns: idle(),
    assets: idle(),
    alerts: idle(),
    correlations: idle(),
  });

  useEffect(() => {
    setState({
      vulns: loading(),
      assets: loading(),
      alerts: loading(),
      correlations: loading(),
    });

    Promise.allSettled([
      api.vulnerabilities(),
      api.assets(),
      api.alerts(),
      api.correlations(),
    ]).then(([vr, ar, alr, cr]) => {
      setState({
        vulns:
          vr.status === "fulfilled"
            ? fromListResponse(vr.value)
            : { status: "error", message: String((vr as PromiseRejectedResult).reason) },
        assets:
          ar.status === "fulfilled"
            ? fromListResponse(ar.value)
            : { status: "error", message: String((ar as PromiseRejectedResult).reason) },
        alerts:
          alr.status === "fulfilled"
            ? fromListResponse(alr.value)
            : { status: "error", message: String((alr as PromiseRejectedResult).reason) },
        correlations:
          cr.status === "fulfilled"
            ? fromListResponse(cr.value)
            : { status: "error", message: String((cr as PromiseRejectedResult).reason) },
      });
    });
  }, []);

  const criticalVulns =
    state.vulns.status === "ok" || state.vulns.status === "partial"
      ? state.vulns.data.filter((v) => v.severity === "critical").length
      : null;

  const openAlerts =
    state.alerts.status === "ok" || state.alerts.status === "partial"
      ? state.alerts.data.filter((a) => a.status === "open").length
      : null;

  const exposedAssets =
    state.assets.status === "ok" || state.assets.status === "partial"
      ? state.assets.data.filter((a) => a.internet_exposed).length
      : null;

  const criticalCorr =
    state.correlations.status === "ok" || state.correlations.status === "partial"
      ? state.correlations.data.filter((c) => c.risk_tier === "critical").length
      : null;

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle="Real-time risk posture summary"
      >
        {USE_MOCK && <MockBadge />}
      </PageHeader>

      {/* KPI row */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        <KpiCard
          label="Critical CVEs"
          value={criticalVulns}
          loading={state.vulns.status === "loading" || state.vulns.status === "idle"}
          danger
        />
        <KpiCard
          label="Open Alerts"
          value={openAlerts}
          loading={state.alerts.status === "loading" || state.alerts.status === "idle"}
          danger
        />
        <KpiCard
          label="Exposed Assets"
          value={exposedAssets}
          loading={state.assets.status === "loading" || state.assets.status === "idle"}
        />
        <KpiCard
          label="Critical Correlations"
          value={criticalCorr}
          loading={state.correlations.status === "loading" || state.correlations.status === "idle"}
          danger
        />
      </div>

      {/* Provenance banners */}
      {(state.alerts.status === "partial") && (
        <ProvenanceBanner prov={state.alerts.provenance} />
      )}

      {/* Top vulnerabilities */}
      <Section title="Top Vulnerabilities">
        {state.vulns.status === "loading" || state.vulns.status === "idle" ? (
          <SkeletonTable cols={4} rows={3} />
        ) : state.vulns.status === "error" ? (
          <ErrorState message={state.vulns.message} />
        ) : state.vulns.status === "empty" ? (
          <EmptyState message="No vulnerabilities found." />
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr style={{ color: "var(--text-muted)", borderBottom: "1px solid var(--border)" }}>
                <Th>CVE</Th>
                <Th>CVSS</Th>
                <Th>Severity</Th>
                <Th>KEV</Th>
                <Th>Assets</Th>
              </tr>
            </thead>
            <tbody>
              {state.vulns.data.slice(0, 5).map((v) => (
                <tr key={v.id} style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                  <Td><span className="font-mono">{v.cve_id}</span></Td>
                  <Td><CvssScore score={v.cvss_score} /></Td>
                  <Td><SeverityBadge level={v.severity} /></Td>
                  <Td>{v.is_kev ? <span className="text-red-400">Yes</span> : "—"}</Td>
                  <Td>{v.affected_asset_count ?? 0}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      {/* Recent Alerts */}
      <Section title="Recent Alerts">
        {state.alerts.status === "loading" || state.alerts.status === "idle" ? (
          <SkeletonTable cols={3} rows={3} />
        ) : state.alerts.status === "error" ? (
          <ErrorState message={state.alerts.message} />
        ) : state.alerts.status === "empty" ? (
          <EmptyState message="No alerts." />
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr style={{ color: "var(--text-muted)", borderBottom: "1px solid var(--border)" }}>
                <Th>Title</Th>
                <Th>Severity</Th>
                <Th>Status</Th>
              </tr>
            </thead>
            <tbody>
              {state.alerts.data.slice(0, 5).map((a) => (
                <tr key={a.id} style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                  <Td>{a.title}</Td>
                  <Td><SeverityBadge level={a.severity} /></Td>
                  <Td><span style={{ color: "var(--text-secondary)" }}>{a.status}</span></Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  );
}

function KpiCard({
  label,
  value,
  loading,
  danger = false,
}: {
  label: string;
  value: number | null;
  loading: boolean;
  danger?: boolean;
}) {
  return (
    <div
      style={{
        background: "var(--bg-surface)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        padding: "12px 16px",
      }}
    >
      <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "6px" }}>
        {label}
      </div>
      {loading ? (
        <div className="h-6 w-16 rounded animate-pulse" style={{ background: "var(--bg-overlay)" }} />
      ) : (
        <div
          style={{
            fontSize: "24px",
            fontWeight: 700,
            color: danger && value ? "var(--red)" : "var(--text-primary)",
          }}
        >
          {value ?? "—"}
        </div>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div
      style={{
        background: "var(--bg-surface)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        marginBottom: "16px",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          padding: "8px 12px",
          fontSize: "11px",
          fontWeight: 600,
          color: "var(--text-secondary)",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          borderBottom: "1px solid var(--border)",
        }}
      >
        {title}
      </div>
      <div style={{ padding: "0 0 4px" }}>{children}</div>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-3 py-2 text-left font-medium">{children}</th>;
}

function Td({ children }: { children: React.ReactNode }) {
  return <td className="px-3 py-2" style={{ color: "var(--text-primary)" }}>{children}</td>;
}

function SkeletonTable({ cols, rows }: { cols: number; rows: number }) {
  return (
    <table className="w-full">
      <tbody>
        {Array.from({ length: rows }).map((_, i) => (
          <tr key={i}>
            {Array.from({ length: cols }).map((_, j) => (
              <td key={j} className="px-3 py-2">
                <div
                  className="h-3 rounded animate-pulse"
                  style={{ background: "var(--bg-overlay)", width: `${60 + j * 15}%` }}
                />
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
