"use client";

import { api, USE_MOCK } from "@/lib/api";
import type { AiChatResponse } from "@/lib/api/types";
import { MockBadge, PageHeader } from "@/components/ui";
import { FormEvent, useState } from "react";

interface Message {
  role: "user" | "assistant";
  content: string;
  citations?: AiChatResponse["citations"];
  isPartial?: boolean;
}

export default function AnalystPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const q = input.trim();
    if (!q || loading) return;

    setInput("");
    setMessages((prev) => [...prev, { role: "user", content: q }]);
    setLoading(true);

    try {
      const resp = await api.aiQuery(q);
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: resp.answer,
          citations: resp.citations,
          isPartial: resp.is_partial,
        },
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `Error: ${String(err)}. The assistant is unavailable.`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 40px)" }}>
      <PageHeader
        title="AI Analyst"
        subtitle="Retrieval-augmented intelligence assistant — answers only from ingested data"
      >
        {USE_MOCK && <MockBadge />}
      </PageHeader>

      {/* Dev boundary notice */}
      <div
        style={{
          padding: "8px 12px",
          marginBottom: "12px",
          fontSize: "11px",
          color: "var(--text-muted)",
          background: "var(--bg-surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
        }}
      >
        <strong style={{ color: "var(--text-secondary)" }}>Dev boundary: </strong>
        The language model endpoint is not connected in this environment. The assistant
        returns the evidence it would cite, not an LLM-composed answer. Never marks
        unknown values as safe.
      </div>

      {/* Chat history */}
      <div
        style={{
          flex: 1,
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          gap: "8px",
          marginBottom: "12px",
        }}
      >
        {messages.length === 0 && (
          <div
            style={{
              display: "flex",
              flex: 1,
              alignItems: "center",
              justifyContent: "center",
              color: "var(--text-muted)",
              fontSize: "13px",
            }}
          >
            Ask a question about your threat intelligence. Answers cite sources.
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} style={{ display: "flex", justifyContent: msg.role === "user" ? "flex-end" : "flex-start" }}>
            <div
              style={{
                maxWidth: "80%",
                padding: "8px 12px",
                borderRadius: "var(--radius)",
                fontSize: "13px",
                lineHeight: 1.6,
                background:
                  msg.role === "user" ? "var(--teal-glow)" : "var(--bg-surface)",
                border: `1px solid ${msg.role === "user" ? "var(--teal-dim)" : "var(--border)"}`,
                color: "var(--text-primary)",
              }}
            >
              <p style={{ whiteSpace: "pre-wrap" }}>{msg.content}</p>

              {/* Citations */}
              {msg.citations && msg.citations.length > 0 && (
                <div style={{ marginTop: "8px", borderTop: "1px solid var(--border)", paddingTop: "6px" }}>
                  <p style={{ fontSize: "10px", color: "var(--text-muted)", marginBottom: "4px", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                    Citations
                  </p>
                  {msg.citations.map((c, j) => (
                    <div key={j} style={{ fontSize: "11px", color: "var(--text-secondary)", marginBottom: "2px" }}>
                      [{j + 1}] {c.title} — <span style={{ color: "var(--text-muted)" }}>{c.source ?? c.entity_type}</span>
                    </div>
                  ))}
                </div>
              )}

              {msg.isPartial && (
                <p style={{ fontSize: "10px", color: "var(--amber)", marginTop: "6px" }}>
                  ⚠ Partial: not all intelligence sources contributed to this answer.
                </p>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div style={{ display: "flex", justifyContent: "flex-start" }}>
            <div
              style={{
                padding: "8px 14px",
                borderRadius: "var(--radius)",
                background: "var(--bg-surface)",
                border: "1px solid var(--border)",
                fontSize: "13px",
                color: "var(--text-muted)",
              }}
            >
              <span className="animate-pulse">Retrieving context…</span>
            </div>
          </div>
        )}
      </div>

      {/* Input */}
      <form onSubmit={submit} style={{ display: "flex", gap: "8px" }}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about a CVE, threat actor, or campaign…"
          disabled={loading}
          style={{
            flex: 1,
            padding: "8px 12px",
            fontSize: "13px",
            background: "var(--bg-surface)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius)",
            color: "var(--text-primary)",
            outline: "none",
            transition: "border-color var(--transition)",
          }}
          onFocus={(e) => (e.target.style.borderColor = "var(--teal)")}
          onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          style={{
            padding: "8px 16px",
            fontSize: "12px",
            fontWeight: 600,
            background: loading || !input.trim() ? "var(--bg-overlay)" : "var(--teal)",
            color: loading || !input.trim() ? "var(--text-muted)" : "#0a1a19",
            border: "none",
            borderRadius: "var(--radius)",
            cursor: loading || !input.trim() ? "default" : "pointer",
            transition: "background var(--transition)",
          }}
        >
          Ask
        </button>
      </form>
    </div>
  );
}
