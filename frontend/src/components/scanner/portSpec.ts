/** Port profiles and the parser for the "custom ports" input of the scan console. */

export type PortProfileId = "common" | "quick" | "custom";

export const MAX_CUSTOM_PORTS = 1024;

/** The twenty ports most often exposed by mistake. */
export const QUICK_PORTS: readonly number[] = [
  21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
];

/**
 * Ports of the backend's built-in catalogue (backend/app/services/network_scanner.py COMMON_PORTS).
 * Only used to animate the probe stream: the backend decides what is really scanned when ports are omitted.
 */
export const COMMON_CATALOGUE_PORTS: readonly number[] = [
  20, 21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 1883,
  2049, 2375, 2376, 3000, 3306, 3389, 5000, 5432, 5672, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 9090, 9200, 11211,
  27017,
];

export interface ProfileDescriptor {
  id: PortProfileId;
  label: string;
  hint: string;
}

export const PORT_PROFILES: readonly ProfileDescriptor[] = [
  { id: "common", label: "Common services", hint: `${COMMON_CATALOGUE_PORTS.length} catalogued ports` },
  { id: "quick", label: "Quick top ports", hint: `${QUICK_PORTS.length} most exposed ports` },
  { id: "custom", label: "Custom", hint: 'List or range: "22,80,443" or "1-1024"' },
];

export type PortSpecResult = { ok: true; ports: number[] } | { ok: false; error: string };

const PORT_TOKEN = /^\d{1,5}$/;
const RANGE_TOKEN = /^(\d{1,5})\s*-\s*(\d{1,5})$/;

function inPortRange(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

/**
 * Parses "22,80,443", "1-1024" or a mix such as "22, 80, 8000-8100" into a sorted list of unique ports.
 * Separators may be commas, semicolons or whitespace.
 */
export function parsePortSpec(raw: string): PortSpecResult {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return { ok: false, error: 'Enter at least one port, e.g. "22,80,443" or "1-1024".' };
  }

  const tokens = trimmed
    .replace(/\s*-\s*/g, "-")
    .split(/[\s,;]+/)
    .filter((token) => token !== "");
  const unique = new Set<number>();

  for (const token of tokens) {
    if (PORT_TOKEN.test(token)) {
      const port = Number(token);
      if (!inPortRange(port)) return { ok: false, error: `Port ${token} is outside the valid range 1-65535.` };
      unique.add(port);
      continue;
    }

    const range = RANGE_TOKEN.exec(token);
    if (range === null) {
      return { ok: false, error: `"${token}" is not a valid port or range.` };
    }
    const start = Number(range[1]);
    const end = Number(range[2]);
    if (!inPortRange(start) || !inPortRange(end)) {
      return { ok: false, error: `Range ${token} is outside the valid range 1-65535.` };
    }
    if (start > end) return { ok: false, error: `Range ${token} is reversed: the start must not exceed the end.` };
    if (end - start + 1 > MAX_CUSTOM_PORTS) {
      return { ok: false, error: `Range ${token} covers more than ${MAX_CUSTOM_PORTS} ports.` };
    }
    for (let port = start; port <= end; port += 1) unique.add(port);

    if (unique.size > MAX_CUSTOM_PORTS) {
      return { ok: false, error: `Too many ports: the maximum per scan is ${MAX_CUSTOM_PORTS}.` };
    }
  }

  if (unique.size > MAX_CUSTOM_PORTS) {
    return { ok: false, error: `Too many ports (${unique.size}): the maximum per scan is ${MAX_CUSTOM_PORTS}.` };
  }
  return { ok: true, ports: [...unique].sort((a, b) => a - b) };
}

const TARGET_PATTERN = /^[A-Za-z0-9._:\-[\]%]+$/;

/** Light client-side sanity check; the backend remains the authority (private-range policy, DNS). */
export function validateTarget(raw: string): string | null {
  const target = raw.trim();
  if (target === "") return "Enter an IP address or hostname to audit.";
  if (target.length > 253) return "The target is too long (253 characters maximum).";
  if (!TARGET_PATTERN.test(target)) return "The target contains characters that are not valid in an IP address or hostname.";
  return null;
}
