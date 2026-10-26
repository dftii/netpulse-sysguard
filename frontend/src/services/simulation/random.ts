/**
 * Seedable pseudo-random number generation for the in-browser simulation.
 * mulberry32 is tiny, fast and statistically good enough for noise processes; a fixed seed makes
 * every run reproducible (used by the headless verification and by deterministic scan profiles).
 */

/** Hash a string to an unsigned 32-bit integer (FNV-1a). Used to derive per-target seeds. */
export function hashString(value: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

export class Random {
  private state: number;
  private spareGaussian: number | null = null;

  constructor(seed: number) {
    this.state = seed >>> 0;
  }

  /** Uniform float in [0, 1). */
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /** Uniform float in [low, high). */
  uniform(low: number, high: number): number {
    return low + (high - low) * this.next();
  }

  /** Uniform integer in [low, high], both inclusive. */
  int(low: number, high: number): number {
    return low + Math.floor(this.next() * (high - low + 1));
  }

  /** Normally distributed value (Box-Muller, polar form), mean `mean` and deviation `sigma`. */
  gauss(mean = 0, sigma = 1): number {
    if (this.spareGaussian !== null) {
      const spare = this.spareGaussian;
      this.spareGaussian = null;
      return mean + sigma * spare;
    }
    let u = 0;
    let v = 0;
    let s = 0;
    do {
      u = 2 * this.next() - 1;
      v = 2 * this.next() - 1;
      s = u * u + v * v;
    } while (s >= 1 || s === 0);
    const factor = Math.sqrt((-2 * Math.log(s)) / s);
    this.spareGaussian = v * factor;
    return mean + sigma * (u * factor);
  }

  /** True with probability `probability`. */
  chance(probability: number): boolean {
    return this.next() < probability;
  }

  /** Uniformly chosen element of a non-empty array. */
  pick<T>(items: readonly T[]): T {
    const item = items[Math.floor(this.next() * items.length)];
    if (item === undefined) {
      throw new RangeError("Cannot pick from an empty array");
    }
    return item;
  }
}

/** Seed used when the caller does not provide one: different on every page load. */
export function randomSeed(): number {
  return (Math.floor(Math.random() * 0xffffffff) ^ Date.now()) >>> 0;
}
