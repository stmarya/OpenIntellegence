import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'OpenIntellegence',
    template: '%s | OpenIntellegence',
  },
  description: 'Threat intelligence and security operations platform',
  robots: { index: false, follow: false },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-surface text-text-primary antialiased">
        {children}
      </body>
    </html>
  );
}
