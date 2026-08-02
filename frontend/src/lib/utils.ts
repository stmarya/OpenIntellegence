import type { RiskLevel, StatusType } from '@/types';

// Format a date string to a relative or absolute display
export function formatDate(iso: string, style: 'relative' | 'absolute' | 'short' = 'relative'): string {
  const date = new Date(iso);
  if (isNaN(date.getTime())) return '—';

  if (style === 'absolute') {
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
  }

  if (style === 'short') {
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
    });
  }

  // Relative
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSecs < 60) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  if (diffDays < 30) return `${Math.floor(diffDays / 7)}w ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

// Truncate a hash or long string
export function truncateHash(hash: string, chars = 8): string {
  if (!hash) return '—';
  if (hash.length <= chars * 2 + 3) return hash;
  return `${hash.slice(0, chars)}…${hash.slice(-chars)}`;
}

// Format a number with K/M suffix
export function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

// Return CSS class segment for risk level
export function riskColorClass(risk: RiskLevel): string {
  const map: Record<RiskLevel, string> = {
    critical: 'text-risk-critical',
    high: 'text-risk-high',
    medium: 'text-risk-medium',
    low: 'text-risk-low',
    info: 'text-risk-info',
    unknown: 'text-text-muted',
  };
  return map[risk] ?? 'text-text-muted';
}

// Return CSS class for risk badge background
export function riskBgClass(risk: RiskLevel): string {
  const map: Record<RiskLevel, string> = {
    critical: 'bg-risk-critical/10 text-risk-critical border-risk-critical/30',
    high: 'bg-risk-high/10 text-risk-high border-risk-high/30',
    medium: 'bg-risk-medium/10 text-risk-medium border-risk-medium/30',
    low: 'bg-risk-low/10 text-risk-low border-risk-low/30',
    info: 'bg-risk-info/10 text-risk-info border-risk-info/30',
    unknown: 'bg-surface-elevated text-text-muted border-border',
  };
  return map[risk] ?? 'bg-surface-elevated text-text-muted border-border';
}

// Return CSS classes for status chips
export function statusColorClass(status: StatusType): string {
  const map: Record<string, string> = {
    active: 'bg-accent/10 text-accent border-accent/30',
    healthy: 'bg-accent/10 text-accent border-accent/30',
    approved: 'bg-accent/10 text-accent border-accent/30',
    published: 'bg-accent/10 text-accent border-accent/30',
    open: 'bg-risk-medium/10 text-risk-medium border-risk-medium/30',
    in_progress: 'bg-risk-medium/10 text-risk-medium border-risk-medium/30',
    pending: 'bg-risk-info/10 text-risk-info border-risk-info/30',
    draft: 'bg-risk-info/10 text-risk-info border-risk-info/30',
    resolved: 'bg-surface-elevated text-text-secondary border-border',
    closed: 'bg-surface-elevated text-text-secondary border-border',
    stale: 'bg-surface-elevated text-text-muted border-border',
    expired: 'bg-surface-elevated text-text-muted border-border',
    rejected: 'bg-risk-critical/10 text-risk-critical border-risk-critical/30',
    degraded: 'bg-risk-high/10 text-risk-high border-risk-high/30',
    offline: 'bg-risk-critical/10 text-risk-critical border-risk-critical/30',
    unknown: 'bg-surface-elevated text-text-muted border-border',
  };
  return map[status] ?? 'bg-surface-elevated text-text-muted border-border';
}

// Clamp a number between min and max
export function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

// Format a confidence value (0-100) to a display string
export function formatConfidence(confidence: number): string {
  return `${Math.round(clamp(confidence, 0, 100))}%`;
}

// Merge class names (simple utility without clsx dependency)
export function cn(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(' ');
}

// Format file size
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// Sanitize display value - return dash for empty
export function displayValue(value: string | number | undefined | null): string {
  if (value === null || value === undefined || value === '') return '—';
  return String(value);
}
