/** Tiny axis-less trend line that stretches to fill its container. */

import { memo, useId, useMemo } from "react";
import { monotoneAreaPath, monotonePath, splitRuns, type Point } from "./geometry";

export interface SparklineProps {
  values: readonly (number | null)[];
  /** Any CSS colour accepted by SVG stroke. */
  color: string;
  /** Fixed lower bound; defaults to the smallest value. */
  min?: number;
  /** Fixed upper bound; defaults to the largest value. */
  max?: number;
  /** Draw a gradient area under the line. */
  fill?: boolean;
  /** Sizing classes for the container, e.g. "h-7 w-full". */
  className?: string;
  ariaLabel?: string;
}

const VIEW_SIZE = 100;
const PAD_Y = 8;

function SparklineImpl({ values, color, min, max, fill = true, className = "h-7 w-full", ariaLabel }: SparklineProps) {
  const gradientId = useId();

  const geometry = useMemo(() => {
    const finite = values.filter((v): v is number => v !== null && Number.isFinite(v));
    if (finite.length < 2) return null;
    let lo = min ?? Math.min(...finite);
    let hi = max ?? Math.max(...finite);
    if (hi - lo < 1e-9) {
      lo -= 1;
      hi += 1;
    }
    const lastIndex = values.length - 1;
    const toY = (v: number): number => {
      const ratio = Math.min(1, Math.max(0, (v - lo) / (hi - lo)));
      return VIEW_SIZE - PAD_Y - ratio * (VIEW_SIZE - 2 * PAD_Y);
    };
    const points: (Point | null)[] = values.map((v, i) =>
      v === null || !Number.isFinite(v) ? null : { x: (i / lastIndex) * VIEW_SIZE, y: toY(v) },
    );
    const runs = splitRuns(points);
    const lastValue = values[lastIndex];
    const endY = lastValue !== null && lastValue !== undefined && Number.isFinite(lastValue) ? toY(lastValue) : null;
    return {
      lines: runs.map((run) => monotonePath(run)),
      areas: runs.map((run) => monotoneAreaPath(run, VIEW_SIZE)),
      endY,
    };
  }, [values, min, max]);

  return (
    <div
      className={`relative ${className}`}
      role={ariaLabel ? "img" : undefined}
      aria-label={ariaLabel}
      aria-hidden={ariaLabel ? undefined : true}
    >
      <svg
        viewBox={`0 0 ${VIEW_SIZE} ${VIEW_SIZE}`}
        preserveAspectRatio="none"
        className="absolute inset-0 h-full w-full overflow-visible"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.3} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        {geometry === null ? (
          <line
            x1={0}
            y1={VIEW_SIZE - PAD_Y}
            x2={VIEW_SIZE}
            y2={VIEW_SIZE - PAD_Y}
            stroke="#334155"
            strokeWidth={1}
            strokeDasharray="3 3"
            vectorEffect="non-scaling-stroke"
          />
        ) : (
          <>
            {fill
              ? geometry.areas.map((d, i) =>
                  d ? <path key={`a${i}`} d={d} fill={`url(#${gradientId})`} stroke="none" /> : null,
                )
              : null}
            {geometry.lines.map((d, i) => (
              <path
                key={`l${i}`}
                d={d}
                fill="none"
                stroke={color}
                strokeWidth={1.5}
                strokeLinejoin="round"
                strokeLinecap="round"
                vectorEffect="non-scaling-stroke"
              />
            ))}
          </>
        )}
      </svg>
      {geometry !== null && geometry.endY !== null ? (
        <span
          aria-hidden="true"
          className="absolute right-0 size-1.5 -translate-y-1/2 rounded-full"
          style={{ top: `${geometry.endY}%`, backgroundColor: color, boxShadow: `0 0 6px ${color}` }}
        />
      ) : null}
    </div>
  );
}

export const Sparkline = memo(SparklineImpl);
