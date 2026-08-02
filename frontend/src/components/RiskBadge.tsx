export type RiskTier = 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown';

/**
 * Derives a risk tier without ever treating an unknown score as clean.
 */
export function riskTier(score: number | null, knownExploited: boolean): RiskTier {
  if (knownExploited) return 'Critical';
  if (score === null || Number.isNaN(score)) return 'Unknown';
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

export function RiskBadge({ score, knownExploited }: { score: number | null; knownExploited: boolean }) {
  const tier = riskTier(score, knownExploited);
  return (
    <span className={`risk ${tier.toLowerCase()}`} title={tier === 'Unknown' ? 'Unknown risk is not the same as no risk' : undefined}>
      {tier}
    </span>
  );
}
