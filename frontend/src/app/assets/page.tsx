"use client";

import { api, fromListResponse, USE_MOCK } from "@/lib/api";
import type { Asset, RemoteState } from "@/lib/api/types";
import { MockBadge, PageHeader, RemoteView, SeverityBadge } from "@/components/ui";
import { useEffect, useState } from "react";

function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const secs = (Date.now() - new Date(iso).getTime()) / 1000;
  if (secs < 60) return `${Math.round(secs)}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

export default function AssetsPage() {
  const [state, setState] = useState<RemoteState<Asset[]>>({ status: "idle" });

  useEffect(() => {
    setState({ status: "loading" });
    api
      .assets()
      .then((r) => setState(fromListResponse(r)))
      .catch((e) => setState({ status: "error", message: String(e) }));
  }, []);

  return (
    <div>
      <PageHeader title="Assets" subtitle="Endpoint inventory with exposure data">
        {USE_MOCK && <MockBadge />}
      </PageHeader>

      <RemoteView
        state={state}
        skeletonCols={6}
        emptyMessage="No assets enrolled."
        renderData={(data) => (
          <table
            style={{
              width: "100%",
              fontSize: "12px",
              background: "var(--bg-surface)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              borderCollapse: "collapse",
            }}
          >
            <thead>
              <tr style={{ color: "var(--text-muted)", borderBottom: "1px solid var(--border)" }}>
                {["Hostname", "IP", "OS", "Criticality", "Exposed", "CVEs", "Last Seen"].map((h) => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-[11px] uppercase tracking-wide">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.map((a) => (
                <tr
                  key={a.id}
                  style={{ borderBottom: "1px solid var(--border-subtle)" }}
                >
                  <td className="px-3 py-2 font-mono text-xs">{a.hostname ?? "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs" style={{ color: "var(--text-secondary)" }}>
                    {a.ip_address ?? "—"}
                  </td>
                  <td className="px-3 py-2" style={{ color: "var(--text-secondary)" }}>
                    {a.os ? `${a.os} ${a.os_version ?? ""}`.trim() : "—"}
                  </td>
                  <td className="px-3 py-2"><SeverityBadge level={a.criticality} /></td>
                  <td className="px-3 py-2">
                    {a.internet_exposed ? (
                      <span style={{ color: "var(--red)", fontSize: "11px" }}>Yes</span>
                    ) : (
                      <span style={{ color: "var(--text-muted)" }}>No</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <span
                      style={{
                        color: a.exposed_cve_count > 0 ? "var(--red)" : "var(--text-muted)",
                        fontWeight: a.exposed_cve_count > 0 ? 600 : undefined,
                      }}
                    >
                      {a.exposed_cve_count}
                    </span>
                  </td>
                  <td className="px-3 py-2" style={{ color: "var(--text-muted)", fontSize: "11px" }}>
                    {timeAgo(a.last_seen_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      />
    </div>
  );
}
