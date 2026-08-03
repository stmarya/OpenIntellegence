import type { Metadata } from 'next';
import { ActionWorkbench } from '@/components/ActionWorkbench';

export const metadata: Metadata = { title: 'Action workbench' };

export default function ActionsPage() {
  return <section className="content">
    <h1>Action workbench</h1>
    <p className="muted">Eight explicit write operations are mediated by a server-only credential. The browser never receives API key material, and paths outside the allowlist cannot be called through this gateway.</p>
    <ActionWorkbench />
    <p className="muted">Endpoint actions remain approval-first. A request records intent; it does not prove delivery to a device.</p>
  </section>;
}
