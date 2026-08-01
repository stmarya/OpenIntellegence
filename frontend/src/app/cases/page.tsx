"use client";

import { api, fromListResponse, USE_MOCK } from "@/lib/api";
import type { Investigation, RemoteState } from "@/lib/api/types";
import { MockBadge, PageHeader, RemoteView, SeverityBadge } from "@/components/ui";
import { useEffect, useState } from "react";

const STATUS_LABEL: Record<string, string> = {
  open: "Open",
  in_progress: "In Progress",
  closed: "Closed",
};

const STATUS_COLOUR: Record<string, string> = {
  open: "var(--red)",
  in_progress: "var(--teal)",
  closed: "var(--text-muted)",
};

export default function CasesPage() {
  const [state, setState] = useState<RemoteState<Investigation[]>>({ status: "idle" });

  useEffect(() => {
    setState({ status: "loading" });
    api
      .investigations()
      .then((r) => setState(fromListResponse(r)))
      .catch((e) => setState({ status: "error", message: String(e) }));
  }, []);

  return (
    <div>
      <PageHeader title="Cases" subtitle="Active investigations and their current status">
        {USE_MOCK && <MockBadge />}
      </PageHeader>

      <RemoteView
        state={state}
        skeletonCols={4}
        emptyMessage="No active investigations."
        renderData={(data) => (
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {data.map((inv) => (
              <div
                key={inv.id}
                style={{
                  background: "var(--bg-surface)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius)",
                  padding: "10px 14px",
                  display: "flex",
                  alignItems: "center",
                  gap: "12px",
                }}
              >
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-primary)" }}>
                    {inv.title}
                  </div>
                  {inv.summary && (
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                      {inv.summary}
                    </div>
                  )}
                </div>
                <SeverityBadge level={inv.severity} />
                <span
                  style={{
                    fontSize: "11px",
                    color: STATUS_COLOUR[inv.status] ?? "var(--text-secondary)",
                    minWidth: "72px",
                    textAlign: "right",
                  }}
                >
                  {STATUS_LABEL[inv.status] ?? inv.status}
                </span>
              </div>
            ))}
          </div>
        )}
      />
    </div>
  );
}
