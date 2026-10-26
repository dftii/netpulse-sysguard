import { RISK_STYLES } from "../../lib/thresholds";
import type { RiskLevel } from "../../types/api";

interface RiskBadgeProps {
  level: RiskLevel;
  className?: string;
}

/** Uppercase pill coloured by risk level. */
export function RiskBadge({ level, className = "" }: RiskBadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wider uppercase ring-1 ring-inset ${RISK_STYLES[level].badge} ${className}`}
    >
      {level}
    </span>
  );
}
