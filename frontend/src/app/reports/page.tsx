"use client";

import { api, fromListResponse, USE_MOCK } from "@/lib/api";
import type { RemoteState, Report } from "@/lib/api/types";
import { MockBadge, PageHeader, RemoteView } from "@/components/ui";
import { useEffect, useState } from "react";

const STATUS_COLOUR: Record<string, string> = {
  ready: "var(--green)",
  generating: "var(--teal)",
  pending: "var(--amber)",
  failed: "var(--red)",
};

export default function ReportsPage() {
  const [state, setState] = useState<RemoteState<Report[]>>({ status: "idle" });

  useEffect(() => {
    setState({ status: "loading" });
    api
      .reports()
      .then((r) => setState(fromListResponse(r)))
      .catch((e) => setState({ status: "error", message: String(e) }));
  }, []);

  return (
    <div>
      <PageHeader title="Reports" subtitle="Generated intelligence reports">
        {USE_MOCK && <MockBadge />}
      </PageHeader>

      <RemoteView
        state={state}
        skeletonCols={5}
        emptyMessage="No reports generated yet."
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
                {["Title", "Type", "Status", "Requested By", "Created"].map((h) => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-[11px] uppercase tracking-wide">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.map((r) => (
                <tr key={r.id} style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                  <td className="px-3 py-2 font-semibold">{r.title}</td>
                  <td className="px-3 py-2 font-mono text-[11px]" style={{ color: "var(--text-secondary)" }}>
                    {r.report_type}
                  </td>
                  <td className="px-3 py-2">
                    <span style={{ fontSize: "11px", color: STATUS_COLOUR[r.status] ?? "var(--text-secondary)" }}>
                      {r.status}
                    </span>
                  </td>
                  <td className="px-3 py-2" style={{ color: "var(--text-secondary)" }}>
                    {r.requested_by}
                  </td>
                  <td className="px-3 py-2" style={{ color: "var(--text-muted)", fontSize: "11px" }}>
                    {new Date(r.created_at).toLocaleDateString()}
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
