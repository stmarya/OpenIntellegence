import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/layout/Sidebar";

export const metadata: Metadata = {
  title: "OpenIntelligence",
  description: "Cyber threat intelligence platform — development preview",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
          <Sidebar />
          <main
            style={{
              flex: 1,
              overflowY: "auto",
              padding: "20px 24px",
              background: "var(--bg-base)",
            }}
          >
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
