/** Horizontal gauge with an animated fill and optional threshold tick marks. */

import { memo } from "react";
import { LEVEL_STYLES, type LoadLevel } from "../../lib/thresholds";

export interface ProgressBarProps {
  /** Fill ratio between 0 and 1 (values outside the range are clamped). */
  fraction: number;
  /** Colour level, usually the result of loadLevel(). */
  level: LoadLevel;
  /** Accessible name of the gauge, e.g. "CPU load of db-primary". */
  ariaLabel: string;
  /** Human readable value announced by assistive technology, e.g. "42.1%". */
  valueText: string;
  /** Tick positions as ratios between 0 and 1 (typically the warn and crit thresholds). */
  markers?: readonly number[];
  className?: string;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

function ProgressBarImpl({ fraction, level, ariaLabel, valueText, markers, className = "" }: ProgressBarProps) {
  const ratio = clamp01(fraction);
  return (
    <div
      role="progressbar"
      aria-label={ariaLabel}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(ratio * 100)}
      aria-valuetext={valueText}
      className={`relative h-1.5 w-full overflow-hidden rounded-full bg-slate-800/80 ${className}`}
    >
      <div
        className={`h-full rounded-full transition-[width,background-color] duration-700 ease-out ${LEVEL_STYLES[level].bar}`}
        style={{ width: `${(ratio * 100).toFixed(2)}%` }}
      />
      {markers?.map((marker) => (
        <span
          key={marker}
          aria-hidden="true"
          className="absolute inset-y-0 w-px bg-slate-950/80"
          style={{ left: `${(clamp01(marker) * 100).toFixed(2)}%` }}
        />
      ))}
    </div>
  );
}

export const ProgressBar = memo(ProgressBarImpl);
