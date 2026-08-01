"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React from "react";

interface NavItem {
  href: string;
  label: string;
  icon: string;
}

const NAV: NavItem[] = [
  { href: "/dashboard",    label: "Dashboard",     icon: "▪" },
  { href: "/explorer",     label: "Explorer",      icon: "⬡" },
  { href: "/assets",       label: "Assets",        icon: "◈" },
  { href: "/alerts",       label: "Alerts",        icon: "◉" },
  { href: "/correlations", label: "Correlations",  icon: "⬢" },
  { href: "/cases",        label: "Cases",         icon: "◫" },
  { href: "/automation",   label: "Automation",    icon: "▷" },
  { href: "/reports",      label: "Reports",       icon: "☰" },
  { href: "/analyst",      label: "AI Analyst",    icon: "✦" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside
      style={{ background: "var(--bg-surface)", borderRight: "1px solid var(--border)" }}
      className="w-44 flex flex-col shrink-0"
    >
      {/* Logo */}
      <div className="px-4 py-3 border-b" style={{ borderColor: "var(--border)" }}>
        <span className="text-sm font-semibold tracking-tight" style={{ color: "var(--teal)" }}>
          OpenIntel
        </span>
        <span className="text-[10px] ml-1.5 font-mono opacity-50">dev</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-2 overflow-y-auto">
        {NAV.map(({ href, label, icon }) => {
          const active = pathname === href || pathname.startsWith(href + "/");
          return (
            <Link
              key={href}
              href={href}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "6px 12px",
                fontSize: "12px",
                color: active ? "var(--teal)" : "var(--text-secondary)",
                background: active ? "var(--teal-glow)" : "transparent",
                borderLeft: `2px solid ${active ? "var(--teal)" : "transparent"}`,
                transition: "color var(--transition), background var(--transition)",
                textDecoration: "none",
              }}
            >
              <span style={{ fontSize: "10px", opacity: 0.7 }}>{icon}</span>
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div
        className="px-4 py-2 text-[10px] border-t"
        style={{ color: "var(--text-muted)", borderColor: "var(--border)" }}
      >
        Not production ready
      </div>
    </aside>
  );
}
