import { LoadingState } from '@/components/States';

export default function Loading() {
  return (
    <section className="content">
      <LoadingState label="Reading live tenant data" />
    </section>
  );
}
