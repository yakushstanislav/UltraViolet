import { isIPv4, isIPv6 } from './inetAddr';

export function hostPathForIPLiteral(addr: string): string | null {
  if (addr === '') {
    return null;
  }

  if (isIPv4(addr) || isIPv6(addr)) {
    return `/hosts/${encodeURIComponent(addr)}`;
  }

  return null;
}

/**
 * When a scan target denotes a single host IP, returns the bare IP literal:
 * plain IPv4/IPv6, or host-only CIDR (/32, /128). Other prefixes and
 * hostnames are ignored — the host API accepts only IP literals.
 */
export function hostIPFromScanTarget(target: string): string | null {
  const trimmed = target.trim();
  if (trimmed === '') {
    return null;
  }

  const slash = trimmed.indexOf('/');
  if (slash !== -1) {
    const addr = trimmed.slice(0, slash).trim();
    const suffix = trimmed.slice(slash + 1).trim();
    if (!/^\d+$/.test(suffix)) {
      return null;
    }

    const bits = Number(suffix);
    if (bits === 32 && isIPv4(addr)) {
      return addr;
    }

    if (bits === 128 && isIPv6(addr)) {
      return addr;
    }

    return null;
  }

  if (isIPv4(trimmed) || isIPv6(trimmed)) {
    return trimmed;
  }

  return null;
}

/**
 * Strips a CIDR suffix from an inet string (e.g. 203.0.113.5/32 → 203.0.113.5).
 */
export function hostIPLiteral(value: string | undefined): string | undefined {
  if (value === undefined || value.trim() === '') {
    return undefined;
  }

  const fromTarget = hostIPFromScanTarget(value);
  if (fromTarget !== null) {
    return fromTarget;
  }

  const trimmed = value.trim();
  const slash = trimmed.indexOf('/');
  if (slash === -1) {
    return trimmed;
  }

  const addr = trimmed.slice(0, slash).trim();
  if (isIPv4(addr) || isIPv6(addr)) {
    return addr;
  }

  return trimmed;
}

/**
 * When a scan target denotes a single host IP, returns the in-app path to the
 * host detail page: bare IP, IPv6 literal, or host-only CIDR (/32, /128).
 * Other prefixes and hostnames are ignored — the host API accepts only IP
 * literals.
 */
export function hostPathFromScanTarget(target: string): string | null {
  const ip = hostIPFromScanTarget(target);
  if (ip === null) {
    return null;
  }

  return hostPathForIPLiteral(ip);
}
