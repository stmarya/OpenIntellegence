"use client";

import { api, fromListResponse, USE_MOCK } from "@/lib/api";
import type { Playbook, RemoteState } from "@/lib/api/types";
import { MockBadge, PageHeader, RemoteView } from "@/components/ui";
import { useEffect, useState } from "react";

export default function AutomationPage() {
  const [state, setState] = useState<RemoteState<Playbook[]>>({ status: "idle" });

  useEffect(() => {
    setState({ status: "loading" });
    api
      .playbooks()
      .then((r) => setState(fromListResponse(r)))
      .catch((e) => setState({ status: "error", message: String(e) }));
  }, []);

  return (
    <div>
      <PageHeader
        title="Automation"
        subtitle="Playbooks and automation-run history"
      >
        {USE_MOCK && <MockBadge />}
      </PageHeader>

      <RemoteView
        state={state}
        skeletonCols={4}
        emptyMessage="No playbooks configured."
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
                {["Name", "Trigger", "Enabled", "Description"].map((h) => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-[11px] uppercase tracking-wide">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.map((p) => (
                <tr key={p.id} style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                  <td className="px-3 py-2 font-semibold">{p.name}</td>
                  <td className="px-3 py-2 font-mono text-[11px]" style={{ color: "var(--text-secondary)" }}>
                    {p.trigger_type}
                  </td>
                  <td className="px-3 py-2">
                    <span
                      style={{
                        fontSize: "11px",
                        color: p.enabled ? "var(--green)" : "var(--text-muted)",
                      }}
                    >
                      {p.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </td>
                  <td className="px-3 py-2" style={{ color: "var(--text-secondary)" }}>
                    {p.description ?? "—"}
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
