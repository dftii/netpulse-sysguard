/**
 * Dependency-free SVG time series chart: monotone cubic lines, gradient areas, grid, nice y ticks,
 * "seconds ago" x labels, last-value markers and a hover crosshair with tooltip.
 * The viewBox always matches the measured pixel width, so text and strokes are never distorted.
 */

import { useId, useMemo, useState, type PointerEvent as ReactPointerEvent } from "react";
import { formatClock } from "../../lib/format";
import { fixedScale, formatTick, monotoneAreaPath, monotonePath, niceScale, splitRuns, type Point } from "./geometry";
import { useElementWidth } from "./useElementWidth";

export interface ChartSeries {
  /** Stable identifier (React key). */
  key: string;
  label: string;
  /** Any CSS colour accepted by SVG stroke and fill. */
  color: string;
  /** One entry per timestamp; null leaves a gap in the line. */
  values: readonly (number | null)[];
}

export interface TimeSeriesChartProps {
  series: readonly ChartSeries[];
  /** Epoch milliseconds, ascending, one per sample. */
  timestamps: readonly number[];
  /** Fixed upper bound of the y axis. When omitted the axis auto-scales to "nice" ticks. */
  yMax?: number;
  /** Unit shown above the axis and in the tooltip, e.g. "%" or "Mbps". */
  unit?: string;
  /** Chart height in pixels. */
  height?: number;
  /** Visible time window in seconds, ending at the latest timestamp. */
  windowSeconds?: number;
  /** Short description used for the accessible name of the chart. */
  title?: string;
  /** Custom value formatter for the tooltip and the accessible summary. */
  formatValue?: (value: number) => string;
}

const MARGIN = { top: 20, right: 14, bottom: 22, left: 42 } as const;
const X_INTERVALS = 4;

function defaultFormat(value: number): string {
  if (Math.abs(value) >= 100) return value.toFixed(0);
  if (Math.abs(value) >= 10) return value.toFixed(1);
  return value.toFixed(2);
}

function isFiniteNumber(value: number | null | undefined): value is number {
  return value !== null && value !== undefined && Number.isFinite(value);
}

export function TimeSeriesChart({
  series,
  timestamps,
  yMax,
  unit = "",
  height = 200,
  windowSeconds = 120,
  title = "Time series chart",
  formatValue = defaultFormat,
}: TimeSeriesChartProps) {
  const uid = useId();
  const { ref, width } = useElementWidth<HTMLDivElement>();
  const [hoverX, setHoverX] = useState<number | null>(null);

  const plotWidth = Math.max(0, width - MARGIN.left - MARGIN.right);
  const plotHeight = Math.max(0, height - MARGIN.top - MARGIN.bottom);
  const endTime = timestamps.length > 0 ? timestamps[timestamps.length - 1]! : 0;
  const startTime = endTime - windowSeconds * 1000;

  const scale = useMemo(() => {
    if (yMax !== undefined) return fixedScale(yMax);
    let peak = 0;
    for (const s of series) {
      for (let i = 0; i < s.values.length; i += 1) {
        const v = s.values[i];
        const t = timestamps[i];
        if (isFiniteNumber(v) && t !== undefined && t >= startTime && v > peak) peak = v;
      }
    }
    return niceScale(peak * 1.08);
  }, [series, timestamps, yMax, startTime]);

  const toX = (t: number): number => MARGIN.left + ((t - startTime) / (endTime - startTime)) * plotWidth;
  const toY = (v: number): number =>
    MARGIN.top + plotHeight - Math.min(1, Math.max(0, v / scale.max)) * plotHeight;
  const baselineY = MARGIN.top + plotHeight;

  const rendered = useMemo(() => {
    if (plotWidth <= 0 || timestamps.length === 0) return [];
    const xOf = (t: number): number => MARGIN.left + ((t - startTime) / (endTime - startTime)) * plotWidth;
    const yOf = (v: number): number =>
      MARGIN.top + plotHeight - Math.min(1, Math.max(0, v / scale.max)) * plotHeight;
    const base = MARGIN.top + plotHeight;
    return series.map((s) => {
      const points: (Point | null)[] = timestamps.map((t, i) => {
        const v = s.values[i];
        return isFiniteNumber(v) && t >= startTime - 1000 ? { x: xOf(t), y: yOf(v) } : null;
      });
      const runs = splitRuns(points);
      const lastValue = s.values[timestamps.length - 1];
      return {
        series: s,
        lines: runs.map((run) => monotonePath(run)),
        areas: runs.map((run) => monotoneAreaPath(run, base)),
        lonePoints: runs.filter((run) => run.length === 1).map((run) => run[0]!),
        lastPoint: isFiniteNumber(lastValue) ? { x: xOf(endTime), y: yOf(lastValue), value: lastValue } : null,
      };
    });
  }, [series, timestamps, plotWidth, plotHeight, scale.max, startTime, endTime]);

  // Hover: snap the pointer to the nearest sample inside the visible window.
  let hoverIndex: number | null = null;
  if (hoverX !== null && plotWidth > 0 && timestamps.length > 0) {
    const pointerTime = startTime + ((hoverX - MARGIN.left) / plotWidth) * (endTime - startTime);
    let best = Number.POSITIVE_INFINITY;
    for (let i = 0; i < timestamps.length; i += 1) {
      const t = timestamps[i]!;
      if (t < startTime) continue;
      const distance = Math.abs(t - pointerTime);
      if (distance < best) {
        best = distance;
        hoverIndex = i;
      }
    }
  }
  const hoverTime = hoverIndex !== null ? timestamps[hoverIndex]! : null;
  const hoverPx = hoverTime !== null ? toX(hoverTime) : null;

  const handlePointer = (event: ReactPointerEvent<SVGSVGElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    const x = event.clientX - rect.left;
    setHoverX(x >= MARGIN.left && x <= MARGIN.left + plotWidth ? x : null);
  };

  const summary = series
    .map((s) => {
      const last = s.values[timestamps.length - 1];
      return `${s.label} ${isFiniteNumber(last) ? `${formatValue(last)} ${unit}`.trim() : "no data"}`;
    })
    .join(", ");
  const ariaLabel = `${title}, last ${windowSeconds} seconds. Latest: ${summary}.`;
  const hasData = timestamps.length >= 2;

  const xTicks = Array.from({ length: X_INTERVALS + 1 }, (_, i) => {
    const secondsAgo = windowSeconds - (i * windowSeconds) / X_INTERVALS;
    return { secondsAgo, x: toX(endTime - secondsAgo * 1000) };
  });

  const flipTooltip = hoverPx !== null && hoverPx > width * 0.55;

  return (
    <div ref={ref} className="relative w-full select-none" style={{ height }}>
      {width > 0 ? (
        <svg
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label={ariaLabel}
          className="block touch-pan-y overflow-visible"
          onPointerMove={handlePointer}
          onPointerDown={handlePointer}
          onPointerLeave={() => setHoverX(null)}
          onPointerCancel={() => setHoverX(null)}
        >
          <defs>
            <clipPath id={`${uid}-clip`}>
              <rect x={MARGIN.left} y={MARGIN.top - 4} width={plotWidth} height={plotHeight + 8} />
            </clipPath>
            {series.map((s, i) => (
              <linearGradient key={s.key} id={`${uid}-g${i}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={s.color} stopOpacity={series.length > 1 ? 0.2 : 0.3} />
                <stop offset="100%" stopColor={s.color} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>

          {unit ? (
            <text x={MARGIN.left - 8} y={9} textAnchor="end" className="fill-slate-600 font-mono text-[9px] tracking-wider uppercase">
              {unit}
            </text>
          ) : null}

          {/* Horizontal grid and y labels */}
          {scale.ticks.map((tick) => {
            const y = toY(tick);
            return (
              <g key={`y${tick}`}>
                <line
                  x1={MARGIN.left}
                  x2={MARGIN.left + plotWidth}
                  y1={y}
                  y2={y}
                  className={tick === 0 ? "stroke-slate-700" : "stroke-noc-grid"}
                  strokeWidth={1}
                  strokeDasharray={tick === 0 ? undefined : "2 4"}
                />
                <text x={MARGIN.left - 8} y={y} dy="0.32em" textAnchor="end" className="fill-slate-500 font-mono text-[10px]">
                  {formatTick(tick, scale.step)}
                </text>
              </g>
            );
          })}

          {/* Vertical grid and x labels */}
          {xTicks.map((tick, i) => (
            <g key={`x${tick.secondsAgo}`}>
              {i > 0 && i < X_INTERVALS ? (
                <line
                  x1={tick.x}
                  x2={tick.x}
                  y1={MARGIN.top}
                  y2={baselineY}
                  className="stroke-noc-grid"
                  strokeWidth={1}
                  strokeDasharray="2 4"
                />
              ) : null}
              <text
                x={tick.x}
                y={baselineY + 15}
                textAnchor={i === 0 ? "start" : i === X_INTERVALS ? "end" : "middle"}
                className="fill-slate-500 font-mono text-[10px]"
              >
                {tick.secondsAgo === 0 ? "now" : `-${Math.round(tick.secondsAgo)}s`}
              </text>
            </g>
          ))}

          {/* Data */}
          <g clipPath={`url(#${uid}-clip)`}>
            {rendered.map((r, seriesIndex) => (
              <g key={r.series.key}>
                {r.areas.map((d, i) =>
                  d ? <path key={`a${i}`} d={d} fill={`url(#${uid}-g${seriesIndex})`} stroke="none" /> : null,
                )}
                {r.lines.map((d, i) => (
                  <path
                    key={`l${i}`}
                    d={d}
                    fill="none"
                    stroke={r.series.color}
                    strokeWidth={1.75}
                    strokeLinejoin="round"
                    strokeLinecap="round"
                  />
                ))}
                {r.lonePoints.map((p, i) => (
                  <circle key={`p${i}`} cx={p.x} cy={p.y} r={2} fill={r.series.color} />
                ))}
              </g>
            ))}
          </g>

          {/* Last-value markers */}
          {rendered.map((r) =>
            r.lastPoint ? (
              <g key={`m-${r.series.key}`}>
                <circle cx={r.lastPoint.x} cy={r.lastPoint.y} r={7} fill={r.series.color} opacity={0.18} />
                <circle cx={r.lastPoint.x} cy={r.lastPoint.y} r={3} fill={r.series.color} className="stroke-noc-panel" strokeWidth={1.5} />
              </g>
            ) : null,
          )}

          {!hasData ? (
            <text
              x={MARGIN.left + plotWidth / 2}
              y={MARGIN.top + plotHeight / 2}
              textAnchor="middle"
              dy="0.32em"
              className="fill-slate-600 font-mono text-[11px]"
            >
              Collecting samples…
            </text>
          ) : null}

          {/* Hover crosshair */}
          {hoverPx !== null && hoverIndex !== null ? (
            <g pointerEvents="none">
              <line x1={hoverPx} x2={hoverPx} y1={MARGIN.top} y2={baselineY} className="stroke-slate-400/60" strokeWidth={1} />
              {series.map((s) => {
                const v = s.values[hoverIndex!];
                return isFiniteNumber(v) ? (
                  <circle key={s.key} cx={hoverPx} cy={toY(v)} r={3.5} fill={s.color} className="stroke-noc-bg" strokeWidth={1.5} />
                ) : null;
              })}
            </g>
          ) : null}

          {/* Transparent hit area keeps pointer events stable across gaps between elements. */}
          <rect x={MARGIN.left} y={MARGIN.top} width={plotWidth} height={plotHeight} fill="transparent" />
        </svg>
      ) : null}

      {hoverPx !== null && hoverIndex !== null && hoverTime !== null ? (
        <div
          role="presentation"
          className="pointer-events-none absolute z-10 min-w-32 rounded-md border border-noc-border bg-noc-bg/95 px-2.5 py-1.5 font-mono text-[11px] shadow-lg backdrop-blur"
          style={{
            top: MARGIN.top,
            left: hoverPx,
            transform: flipTooltip ? "translateX(calc(-100% - 12px))" : "translateX(12px)",
          }}
        >
          <div className="mb-1 text-slate-500">{formatClock(hoverTime)}</div>
          {series.map((s) => {
            const v = s.values[hoverIndex!];
            return (
              <div key={s.key} className="flex items-center justify-between gap-3">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span className="size-2 rounded-full" style={{ backgroundColor: s.color }} />
                  {s.label}
                </span>
                <span className="text-slate-100 tabular-nums">
                  {isFiniteNumber(v) ? `${formatValue(v)}${unit ? ` ${unit}` : ""}` : "—"}
                </span>
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
