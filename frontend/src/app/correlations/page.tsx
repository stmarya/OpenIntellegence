"use client";

import { api, fromListResponse, USE_MOCK } from "@/lib/api";
import type { Correlation, RemoteState } from "@/lib/api/types";
import { MockBadge, PageHeader, RemoteView, SeverityBadge } from "@/components/ui";
import { useEffect, useState } from "react";

const TIER_COLOURS: Record<string, string> = {
  critical: "var(--red)",
  high: "var(--amber)",
  medium: "var(--teal)",
  low: "var(--text-muted)",
};

export default function CorrelationsPage() {
  const [state, setState] = useState<RemoteState<Correlation[]>>({ status: "idle" });

  useEffect(() => {
    setState({ status: "loading" });
    api
      .correlations()
      .then((r) => setState(fromListResponse(r)))
      .catch((e) => setState({ status: "error", message: String(e) }));
  }, []);

  return (
    <div>
      <PageHeader title="Correlations" subtitle="Risk-scored evidence correlations with automation candidates">
        {USE_MOCK && <MockBadge />}
      </PageHeader>

      <RemoteView
        state={state}
        skeletonCols={5}
        emptyMessage="No correlations evaluated."
        renderData={(data) => (
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {data.map((c) => (
              <div
                key={c.id}
                style={{
                  background: "var(--bg-surface)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius)",
                  padding: "12px 16px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
                  <span
                    style={{
                      fontSize: "20px",
                      fontWeight: 700,
                      color: TIER_COLOURS[c.risk_tier] ?? "var(--text-primary)",
                      fontFamily: "monospace",
                      minWidth: "42px",
                    }}
                  >
                    {c.risk_score}
                  </span>
                  <div>
                    <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-primary)" }}>
                      {c.title}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                      {c.primary_entity_type} / {c.primary_entity_id}
                    </div>
                  </div>
                  <div style={{ marginLeft: "auto" }}>
                    <SeverityBadge level={c.risk_tier as "critical" | "high" | "medium" | "low"} />
                  </div>
                </div>

                {/* Factors */}
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "8px" }}>
                  {c.factors.map((f) => (
                    <span
                      key={f.key}
                      style={{
                        fontSize: "10px",
                        padding: "2px 6px",
                        borderRadius: "2px",
                        background: f.state === "present" ? "var(--teal-glow)" : "var(--bg-overlay)",
                        border: `1px solid ${f.state === "present" ? "var(--teal-dim)" : "var(--border)"}`,
                        color: f.state === "present" ? "var(--teal)" : "var(--text-muted)",
                      }}
                    >
                      {f.label} (+{f.points})
                    </span>
                  ))}
                </div>

                {/* Automation candidates */}
                {c.automation_candidates.length > 0 && (
                  <div style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                    <span style={{ color: "var(--text-muted)" }}>Actions: </span>
                    {c.automation_candidates.map((ac) => ac.label).join(" · ")}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      />
    </div>
  );
}
