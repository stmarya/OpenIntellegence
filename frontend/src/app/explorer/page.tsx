"use client";

import { api, fromListResponse, USE_MOCK } from "@/lib/api";
import type { RemoteState, Vulnerability } from "@/lib/api/types";
import {
  CvssScore,
  MockBadge,
  PageHeader,
  ProvenanceBanner,
  RemoteView,
  SeverityBadge,
} from "@/components/ui";
import { useEffect, useState } from "react";

export default function ExplorerPage() {
  const [state, setState] = useState<RemoteState<Vulnerability[]>>({ status: "idle" });
  const [kevOnly, setKevOnly] = useState(false);
  const [minCvss, setMinCvss] = useState<string>("");

  const load = () => {
    setState({ status: "loading" });
    api
      .vulnerabilities()
      .then((r) => setState(fromListResponse(r)))
      .catch((e) => setState({ status: "error", message: String(e) }));
  };

  useEffect(load, []);

  const filtered =
    (state.status === "ok" || state.status === "partial") && state.data
      ? state.data.filter((v) => {
          if (kevOnly && !v.is_kev) return false;
          if (minCvss !== "" && (v.cvss_score ?? 0) < parseFloat(minCvss)) return false;
          return true;
        })
      : [];

  return (
    <div>
      <PageHeader
        title="Threat Explorer"
        subtitle="Browse and filter the full vulnerability catalogue"
      >
        {USE_MOCK && <MockBadge />}
      </PageHeader>

      {/* Filters */}
      <div
        style={{
          display: "flex",
          gap: "12px",
          marginBottom: "16px",
          alignItems: "center",
          padding: "8px 12px",
          background: "var(--bg-surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
        }}
      >
        <label style={{ fontSize: "12px", color: "var(--text-secondary)", display: "flex", alignItems: "center", gap: "6px" }}>
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={(e) => setKevOnly(e.target.checked)}
            style={{ accentColor: "var(--teal)" }}
          />
          KEV only
        </label>
        <label style={{ fontSize: "12px", color: "var(--text-secondary)", display: "flex", alignItems: "center", gap: "6px" }}>
          Min CVSS
          <input
            type="number"
            min={0}
            max={10}
            step={0.1}
            value={minCvss}
            onChange={(e) => setMinCvss(e.target.value)}
            placeholder="0–10"
            style={{
              width: "64px",
              background: "var(--bg-raised)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              color: "var(--text-primary)",
              padding: "2px 6px",
              fontSize: "12px",
            }}
          />
        </label>
      </div>

      <RemoteView
        state={
          state.status === "ok" || state.status === "partial"
            ? { ...state, data: filtered }
            : state
        }
        skeletonCols={6}
        emptyMessage="No vulnerabilities match the current filters."
        renderData={(data, prov) => (
          <>
            {prov && <ProvenanceBanner prov={prov} />}
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
                  {["CVE ID", "CVSS", "Severity", "KEV", "Exploit", "Summary"].map((h) => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-[11px] uppercase tracking-wide">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.map((v) => (
                  <tr
                    key={v.id}
                    style={{
                      borderBottom: "1px solid var(--border-subtle)",
                      transition: "background var(--transition)",
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-raised)")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "")}
                  >
                    <td className="px-3 py-2 font-mono text-xs">{v.cve_id}</td>
                    <td className="px-3 py-2"><CvssScore score={v.cvss_score} /></td>
                    <td className="px-3 py-2"><SeverityBadge level={v.severity} /></td>
                    <td className="px-3 py-2">{v.is_kev ? <span style={{ color: "var(--red)" }}>Yes</span> : "—"}</td>
                    <td className="px-3 py-2" style={{ color: "var(--text-secondary)" }}>
                      {v.exploit_maturity ?? "—"}
                    </td>
                    <td className="px-3 py-2" style={{ color: "var(--text-secondary)", maxWidth: "300px" }}>
                      <span style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>
                        {v.summary ?? "—"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      />
    </div>
  );
}
