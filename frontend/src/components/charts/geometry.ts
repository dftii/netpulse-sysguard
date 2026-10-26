/** Pure geometry helpers for the SVG charts: monotone cubic paths, run splitting and nice axis ticks. */

export interface Point {
  readonly x: number;
  readonly y: number;
}

function fmt(value: number): string {
  return (Math.round(value * 100) / 100).toString();
}

/**
 * Tangents for monotone cubic interpolation (Fritsch-Carlson, same scheme as d3's curveMonotoneX).
 * x must be strictly increasing. The curve never overshoots the data between two samples.
 */
function monotoneTangents(points: readonly Point[]): number[] {
  const n = points.length;
  const dx: number[] = [];
  const slope: number[] = [];
  for (let i = 0; i < n - 1; i += 1) {
    const a = points[i]!;
    const b = points[i + 1]!;
    const h = b.x - a.x;
    dx.push(h);
    slope.push(h === 0 ? 0 : (b.y - a.y) / h);
  }

  const tangents = new Array<number>(n).fill(0);
  for (let i = 1; i < n - 1; i += 1) {
    const s0 = slope[i - 1]!;
    const s1 = slope[i]!;
    const h0 = dx[i - 1]!;
    const h1 = dx[i]!;
    if (s0 * s1 <= 0 || h0 + h1 === 0) continue;
    const p = (s0 * h1 + s1 * h0) / (h0 + h1);
    tangents[i] = (Math.sign(s0) + Math.sign(s1)) * Math.min(Math.abs(s0), Math.abs(s1), 0.5 * Math.abs(p));
  }

  const endTangent = (s: number, inner: number): number => {
    const t = (3 * s - inner) / 2;
    if (t * s <= 0) return 0;
    return Math.abs(t) > 3 * Math.abs(s) ? 3 * s : t;
  };
  tangents[0] = endTangent(slope[0]!, tangents[1]!);
  tangents[n - 1] = endTangent(slope[n - 2]!, tangents[n - 2]!);
  return tangents;
}

/** SVG path data ("M..C..") for a smooth monotone curve through the points. */
export function monotonePath(points: readonly Point[]): string {
  const n = points.length;
  if (n === 0) return "";
  const first = points[0]!;
  if (n === 1) return `M${fmt(first.x)},${fmt(first.y)}`;
  if (n === 2) {
    const second = points[1]!;
    return `M${fmt(first.x)},${fmt(first.y)}L${fmt(second.x)},${fmt(second.y)}`;
  }

  const tangents = monotoneTangents(points);
  let d = `M${fmt(first.x)},${fmt(first.y)}`;
  for (let i = 0; i < n - 1; i += 1) {
    const p0 = points[i]!;
    const p1 = points[i + 1]!;
    const third = (p1.x - p0.x) / 3;
    const c1x = p0.x + third;
    const c1y = p0.y + tangents[i]! * third;
    const c2x = p1.x - third;
    const c2y = p1.y - tangents[i + 1]! * third;
    d += `C${fmt(c1x)},${fmt(c1y)},${fmt(c2x)},${fmt(c2y)},${fmt(p1.x)},${fmt(p1.y)}`;
  }
  return d;
}

/** Closed path filling the area between a monotone curve and a horizontal baseline. */
export function monotoneAreaPath(points: readonly Point[], baselineY: number): string {
  if (points.length < 2) return "";
  const first = points[0]!;
  const last = points[points.length - 1]!;
  return `${monotonePath(points)}L${fmt(last.x)},${fmt(baselineY)}L${fmt(first.x)},${fmt(baselineY)}Z`;
}

/** Splits a sequence at null entries so gaps in the data produce gaps in the line. */
export function splitRuns<T>(items: readonly (T | null)[]): T[][] {
  const runs: T[][] = [];
  let current: T[] = [];
  for (const item of items) {
    if (item === null) {
      if (current.length > 0) runs.push(current);
      current = [];
    } else {
      current.push(item);
    }
  }
  if (current.length > 0) runs.push(current);
  return runs;
}

export interface NiceScale {
  /** Upper bound of the axis (always the last tick). */
  max: number;
  step: number;
  ticks: number[];
}

/** Axis from 0 to a "round" maximum at or above `maxValue`, with about `targetTicks` intervals. */
export function niceScale(maxValue: number, targetTicks = 4): NiceScale {
  const safe = Number.isFinite(maxValue) && maxValue > 0 ? maxValue : 1;
  const rough = safe / targetTicks;
  const magnitude = 10 ** Math.floor(Math.log10(rough));
  const normalised = rough / magnitude;
  const factor = normalised <= 1 ? 1 : normalised <= 2 ? 2 : normalised <= 2.5 ? 2.5 : normalised <= 5 ? 5 : 10;
  const step = factor * magnitude;
  const count = Math.max(1, Math.ceil(safe / step - 1e-9));
  const ticks: number[] = [];
  for (let i = 0; i <= count; i += 1) ticks.push(Number((i * step).toFixed(10)));
  return { max: ticks[ticks.length - 1]!, step, ticks };
}

/** Axis from 0 to a fixed maximum, split into evenly spaced ticks. */
export function fixedScale(max: number, intervals = 4): NiceScale {
  const safe = Number.isFinite(max) && max > 0 ? max : 1;
  const step = safe / intervals;
  const ticks: number[] = [];
  for (let i = 0; i <= intervals; i += 1) ticks.push(Number((i * step).toFixed(10)));
  return { max: safe, step, ticks };
}

/** Formats a tick label with just enough decimals to show every multiple of the axis step exactly. */
export function formatTick(value: number, step: number): string {
  let decimals = 0;
  while (decimals < 3 && Math.abs(step * 10 ** decimals - Math.round(step * 10 ** decimals)) > 1e-9) decimals += 1;
  return value.toLocaleString("en-US", { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
}
