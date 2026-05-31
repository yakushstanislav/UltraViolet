type ResourceChipProps = {
  value: string;
};

const KNOWN_PREFIXES = new Set([
  'onvif',
  'rtsp',
  'scan',
  'host',
  'alert',
  'user',
  'saved_search',
  'credential',
  'auth',
]);

export function ResourceChip({ value }: ResourceChipProps) {
  const colonIndex = value.indexOf(':');

  if (colonIndex <= 0) {
    return (
      <span className="resource-chip resource-chip-plain" title={value}>
        <span className="resource-chip-value cell-mono">{value}</span>
      </span>
    );
  }

  const prefix = value.slice(0, colonIndex);
  const rest = value.slice(colonIndex + 1);
  const variant = KNOWN_PREFIXES.has(prefix.toLowerCase())
    ? prefix.toLowerCase()
    : 'other';

  return (
    <span
      className={`resource-chip resource-chip-${variant}`}
      title={value}
    >
      <span className="resource-chip-prefix">{prefix}</span>
      <span className="resource-chip-value cell-mono">{rest}</span>
    </span>
  );
}
