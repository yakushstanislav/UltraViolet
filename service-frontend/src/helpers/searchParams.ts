export function parsePositiveInt(
  value: string | null,
  fallback: number
): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return fallback;
  }

  return Math.floor(parsed);
}

export function parseEnum<T extends string>(
  value: string | null,
  allowed: readonly T[],
  fallback: T
): T {
  if (value !== null && (allowed as readonly string[]).includes(value)) {
    return value as T;
  }

  return fallback;
}

export function parseOptionalEnum<T extends string>(
  value: string | null,
  allowed: readonly T[]
): T | undefined {
  if (value !== null && (allowed as readonly string[]).includes(value)) {
    return value as T;
  }

  return undefined;
}
