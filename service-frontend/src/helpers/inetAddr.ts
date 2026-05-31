const IPV4_RE =
  /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isIPv4(value: string): boolean {
  return IPV4_RE.test(value);
}

export function isIPv6(value: string): boolean {
  if (value === '' || !value.includes(':')) {
    return false;
  }

  try {
    new URL(`http://[${value}]/`);
  } catch {
    return false;
  }

  return true;
}

export type IPFamily = 'v4' | 'v6';

export type ParsedCIDR = {
  addr: string;
  prefix: number;
  family: IPFamily;
};

export function parseCIDR(value: string): ParsedCIDR | null {
  const slash = value.indexOf('/');
  if (slash <= 0) {
    return null;
  }

  const addr = value.slice(0, slash);
  const maskRaw = value.slice(slash + 1);
  if (!/^\d+$/.test(maskRaw)) {
    return null;
  }

  const prefix = Number(maskRaw);
  if (!Number.isInteger(prefix) || prefix < 0) {
    return null;
  }

  if (isIPv4(addr) && prefix <= 32) {
    return { addr, prefix, family: 'v4' };
  }

  if (isIPv6(addr) && prefix <= 128) {
    return { addr, prefix, family: 'v6' };
  }

  return null;
}

export function isCIDR(value: string): boolean {
  return parseCIDR(value) !== null;
}
