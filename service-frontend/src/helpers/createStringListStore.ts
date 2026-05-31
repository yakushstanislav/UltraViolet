export type StringListStore = {
  read(): string[];
  remember(value: string): void;
  clear(): void;
};

export function createStringListStore(
  storageKey: string,
  maxItems: number
): StringListStore {
  function read(): string[] {
    if (typeof window === 'undefined') {
      return [];
    }

    try {
      const raw = window.localStorage.getItem(storageKey);
      if (!raw) {
        return [];
      }

      const parsed = JSON.parse(raw) as unknown;
      if (!Array.isArray(parsed)) {
        return [];
      }

      return parsed.filter((v): v is string => typeof v === 'string');
    } catch {
      return [];
    }
  }

  function write(list: string[]): void {
    if (typeof window === 'undefined') {
      return;
    }

    try {
      window.localStorage.setItem(storageKey, JSON.stringify(list));
    } catch {
      // quota exceeded or storage unavailable; this store is best-effort
    }
  }

  function remember(value: string): void {
    const trimmed = value.trim();
    if (trimmed === '') {
      return;
    }

    const prev = read().filter((x) => x !== trimmed);
    const next = [trimmed, ...prev].slice(0, maxItems);
    write(next);
  }

  function clear(): void {
    write([]);
  }

  return { read, remember, clear };
}
