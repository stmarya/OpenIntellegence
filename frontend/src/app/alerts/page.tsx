"use client";

import { api, fromListResponse, USE_MOCK } from "@/lib/api";
import type { Alert, RemoteState } from "@/lib/api/types";
import { MockBadge, PageHeader, RemoteView, SeverityBadge } from "@/components/ui";
import { useEffect, useState } from "react";

const STATUS_COLOUR: Record<string, string> = {
  open: "var(--red)",
  acknowledged: "var(--amber)",
  resolved: "var(--green)",
  suppressed: "var(--text-muted)",
};

export default function AlertsPage() {
  const [state, setState] = useState<RemoteState<Alert[]>>({ status: "idle" });

  useEffect(() => {
    setState({ status: "loading" });
    api
      .alerts()
      .then((r) => setState(fromListResponse(r)))
      .catch((e) => setState({ status: "error", message: String(e) }));
  }, []);

  return (
    <div>
      <PageHeader title="Alerts" subtitle="Triggered alert rules and triage queue">
        {USE_MOCK && <MockBadge />}
      </PageHeader>

      <RemoteView
        state={state}
        skeletonCols={5}
        emptyMessage="No alerts triggered."
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
                {["Title", "Severity", "Status", "Entity", "Triggered"].map((h) => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-[11px] uppercase tracking-wide">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.map((a) => (
                <tr key={a.id} style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                  <td className="px-3 py-2">{a.title}</td>
                  <td className="px-3 py-2"><SeverityBadge level={a.severity} /></td>
                  <td className="px-3 py-2">
                    <span
                      style={{
                        fontSize: "11px",
                        color: STATUS_COLOUR[a.status] ?? "var(--text-secondary)",
                      }}
                    >
                      {a.status}
                    </span>
                  </td>
                  <td className="px-3 py-2" style={{ color: "var(--text-muted)", fontFamily: "monospace", fontSize: "11px" }}>
                    {a.entity_type ? `${a.entity_type}/${a.entity_id}` : "—"}
                  </td>
                  <td className="px-3 py-2" style={{ color: "var(--text-muted)", fontSize: "11px" }}>
                    {new Date(a.triggered_at).toLocaleString()}
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
