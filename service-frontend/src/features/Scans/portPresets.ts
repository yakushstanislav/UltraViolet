// Port lists mirror TCP handlers registered via probe.Register in
// service-api/internal/pkg/probe — extend presets when new Register() ports
// appear.

import type { PortExprItem } from '@/types/api';

export type PortPreset = {
  id: string;
  portsExpr: PortExprItem[];
};

export type PortPresetGroup = {
  id: string;
  presets: PortPreset[];
};

/** probeHTTP — http.go */
const HTTP_PROBE_TCP: number[] = [
  80, 81, 3000, 5000, 5800, 5984, 7070, 8000, 8080, 8086, 8123, 8200, 8500,
  8888, 9000, 9090, 9091, 9999, 15672, 16080,
];

/** probeHTTPS — tls.go */
const HTTPS_PROBE_TCP: number[] = [
  443, 992, 4443, 8443, 8444, 9443, 10000, 10443, 55443,
];

/** Union of HTTP + HTTPS probe ports (Web preset). */
const WEB_TCP: number[] = [...HTTP_PROBE_TCP, ...HTTPS_PROBE_TCP];

/** Common TCP services (unique ports, merged to ranges when applied). */
const POPULAR_TCP: number[] = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
  3306, 3389, 5432, 5900, 8080, 8443, 8888, 9200,
];

/** Frequent TCP ports (merged ranges after dedup). */
const TOP100_TCP: number[] = [
  80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 53, 135, 143, 3306, 8080, 1723,
  111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 113, 81, 2000, 514,
  8443, 8000, 554, 10000, 49152, 1026, 2001, 515, 8008, 49154, 1027, 5666, 646,
  8444, 49153, 5800, 7070, 9999, 6646, 49155, 256, 406, 631, 144, 32768, 55443,
  873, 1755, 992, 10626, 2222, 32769, 6000, 5631, 1110, 6001, 2049, 4045, 497,
  6567, 3000, 42510, 27352, 6647, 20005, 280, 5093, 898, 5405, 1900, 3986, 5051,
  6648, 49156, 7741, 5190, 6789, 9100, 49157, 5357, 9929, 17185, 20031, 20828,
  5544, 10243, 6502, 1666, 19842, 2048, 6667, 6503, 6504, 17988, 41511, 41523,
  9000, 6699, 10443, 25565, 19671, 5678, 16080, 12401, 7937, 3988, 10778, 5901,
  9998, 32770, 32771, 5009, 6649, 49158,
];

/** probeRTSP — rtsp.go */
const RTSP_TCP: number[] = [554, 8554];

/** Cameras / NVR: RTSP + full HTTP/HTTPS probe set (ONVIF via HTTP). */
const CAMERAS_NVR_TCP: number[] = [...RTSP_TCP, ...WEB_TCP];

/** TV & media dongles — chromecast, airplay, sonos, roku, webos, samsung */
const TV_MEDIA_TCP: number[] = [8008, 8009, 7000, 1400, 8060, 3001, 8001, 8002];

/** Tuya, WeMo, EdgeX */
const SMART_HOME_TCP: number[] = [6668, 49152, 49153, 49154, 48080, 59880];

/** Modbus, S7, OPC-UA, ENIP, DNP3, IEC-104, Niagara, MELSEC, CODESYS, DLMS, C37.118, OCPP */
const INDUSTRIAL_OT_TCP: number[] = [
  502, 102, 4840, 44818, 20000, 2404, 1911, 4911, 5006, 5007, 1217, 11740, 4059,
  4060, 4712, 8887, 8889,
];

/** ROS, Universal Robots, VxWorks WDB */
const ROBOTICS_TCP: number[] = [11311, 30001, 17185];

/** Kafka, NATS, MQTT, AMQP, Redis, Memcached, Elasticsearch */
const MESSAGING_TCP: number[] = [9092, 4222, 1883, 5672, 6379, 11211, 9200];

/** Postgres, MySQL, MongoDB, MSSQL, Oracle TNS */
const DATABASES_TCP: number[] = [
  5432, 3306, 27017, 1433, 1521, 1522, 1525, 2483,
];

/** Docker API, etcd, ZooKeeper, Proxmox, Linkerd, Istio, Envoy, Cilium */
const INFRA_MESH_TCP: number[] = [
  2375, 2379, 2181, 8006, 4191, 15014, 9901, 9963,
];

/** Loki, Tempo, VictoriaMetrics, Alertmanager, Splunk, Datadog APM, TeamCity, GoCD, NRPE */
const OBSERVABILITY_TCP: number[] = [
  3100, 3200, 8428, 9093, 8089, 8126, 8111, 8153, 8154, 5666,
];

/** NFS, iSCSI, SMB, Bareos, Veeam, Commvault */
const STORAGE_BACKUP_TCP: number[] = [
  2049, 3260, 445, 9101, 9102, 9103, 9392, 9419, 8400,
];

/** DICOM, HL7 MLLP */
const MEDICAL_TCP: number[] = [104, 11112, 2575];

/** SSH, Telnet, FTP, RDP, VNC, PPTP, X11 */
const REMOTE_ACCESS_TCP: number[] = [
  22, 2222, 23, 21, 3389, 5900, 5901, 5902, 5903, 1723, 6000, 6001, 6002, 6003,
  6004, 6005,
];

/** SMTP/SMTPS, POP3, IMAP */
const MAIL_TCP: number[] = [25, 465, 587, 2525, 110, 995, 143, 993];

/** IPP, Jetdirect, LPD */
const PRINTERS_TCP: number[] = [631, 9100, 515];

/** SunRPC, MSRPC */
const RPC_TCP: number[] = [
  111, 135, 1025, 1026, 1027, 32768, 32769, 32770, 32771, 49155, 49156, 49157,
  49158,
];

/** DNS over TCP, LDAP, DNS-over-TLS control */
const DIRECTORY_DNS_TCP: number[] = [53, 389, 853];

/** IRC, Bitcoin, Ethereum JSON-RPC, Minecraft, Perforce, Rsync, AFP, ADS-B, AIS, NMEA */
const MISC_FINGERPRINT_TCP: number[] = [
  6667, 6669, 6697, 8333, 8545, 25565, 1666, 873, 548, 30003, 5631, 10110,
];

/** Full TCP range as explicit port_expr rows. */
const FULL_PORTS_EXPR: PortExprItem[] = [{ from: 1, to: 65535 }];

function mergePortIntsToRanges(ports: number[]): PortExprItem[] {
  const sorted = [...new Set(ports)].sort((a, b) => a - b);
  const first = sorted[0];
  if (first === undefined) {
    return [];
  }

  const out: PortExprItem[] = [];
  let start = first;
  let prev = first;

  for (let i = 1; i < sorted.length; i++) {
    const p = sorted[i];
    if (p === undefined) {
      continue;
    }
    if (p === prev + 1) {
      prev = p;
      continue;
    }

    out.push({ from: start, to: prev });
    start = p;
    prev = p;
  }

  out.push({ from: start, to: prev });

  return out;
}

export function countPorts(portsExpr: PortExprItem[]): number {
  let total = 0;

  for (const range of portsExpr) {
    const from = Number(range.from);
    const to = Number(range.to);

    if (!Number.isFinite(from) || !Number.isFinite(to) || to < from) {
      continue;
    }

    total += to - from + 1;
  }

  return total;
}

export const SCAN_PORT_PRESET_GROUPS: PortPresetGroup[] = [
  {
    id: 'general',
    presets: [
      {
        id: 'web',
        portsExpr: mergePortIntsToRanges(WEB_TCP),
      },
      {
        id: 'popular',
        portsExpr: mergePortIntsToRanges(POPULAR_TCP),
      },
      {
        id: 'top100',
        portsExpr: mergePortIntsToRanges(TOP100_TCP),
      },
      {
        id: 'full',
        portsExpr: FULL_PORTS_EXPR,
      },
    ],
  },
  {
    id: 'cameras',
    presets: [
      {
        id: 'cameras_rtsp_http',
        portsExpr: mergePortIntsToRanges(CAMERAS_NVR_TCP),
      },
    ],
  },
  {
    id: 'tv_media',
    presets: [
      {
        id: 'tv_streaming_devices',
        portsExpr: mergePortIntsToRanges(TV_MEDIA_TCP),
      },
    ],
  },
  {
    id: 'smart_home',
    presets: [
      {
        id: 'smart_home_edge_iot',
        portsExpr: mergePortIntsToRanges(SMART_HOME_TCP),
      },
    ],
  },
  {
    id: 'industrial',
    presets: [
      {
        id: 'industrial_ot_tcp',
        portsExpr: mergePortIntsToRanges(INDUSTRIAL_OT_TCP),
      },
    ],
  },
  {
    id: 'robotics',
    presets: [
      {
        id: 'robotics_embedded_tcp',
        portsExpr: mergePortIntsToRanges(ROBOTICS_TCP),
      },
    ],
  },
  {
    id: 'messaging',
    presets: [
      {
        id: 'messaging_caches_tcp',
        portsExpr: mergePortIntsToRanges(MESSAGING_TCP),
      },
    ],
  },
  {
    id: 'databases',
    presets: [
      {
        id: 'databases_tcp',
        portsExpr: mergePortIntsToRanges(DATABASES_TCP),
      },
    ],
  },
  {
    id: 'infra',
    presets: [
      {
        id: 'infra_orchestration_mesh_tcp',
        portsExpr: mergePortIntsToRanges(INFRA_MESH_TCP),
      },
    ],
  },
  {
    id: 'observability',
    presets: [
      {
        id: 'observability_ci_tcp',
        portsExpr: mergePortIntsToRanges(OBSERVABILITY_TCP),
      },
    ],
  },
  {
    id: 'storage',
    presets: [
      {
        id: 'storage_backup_tcp',
        portsExpr: mergePortIntsToRanges(STORAGE_BACKUP_TCP),
      },
    ],
  },
  {
    id: 'medical',
    presets: [
      {
        id: 'medical_tcp',
        portsExpr: mergePortIntsToRanges(MEDICAL_TCP),
      },
    ],
  },
  {
    id: 'remote',
    presets: [
      {
        id: 'remote_access_tcp',
        portsExpr: mergePortIntsToRanges(REMOTE_ACCESS_TCP),
      },
    ],
  },
  {
    id: 'mail',
    presets: [
      {
        id: 'mail_tcp',
        portsExpr: mergePortIntsToRanges(MAIL_TCP),
      },
    ],
  },
  {
    id: 'printers',
    presets: [
      {
        id: 'printers_tcp',
        portsExpr: mergePortIntsToRanges(PRINTERS_TCP),
      },
    ],
  },
  {
    id: 'rpc',
    presets: [
      {
        id: 'rpc_services_tcp',
        portsExpr: mergePortIntsToRanges(RPC_TCP),
      },
    ],
  },
  {
    id: 'directory_dns',
    presets: [
      {
        id: 'directory_dns_tcp',
        portsExpr: mergePortIntsToRanges(DIRECTORY_DNS_TCP),
      },
    ],
  },
  {
    id: 'misc',
    presets: [
      {
        id: 'misc_fingerprinted_tcp',
        portsExpr: mergePortIntsToRanges(MISC_FINGERPRINT_TCP),
      },
    ],
  },
];

export const SCAN_PORT_PRESETS: PortPreset[] = SCAN_PORT_PRESET_GROUPS.flatMap(
  (g) => g.presets
);

/** True when port_expr lists match (numeric from/to, same length and order). */
export function portExprListsEqual(
  a: PortExprItem[] | undefined,
  b: PortExprItem[] | undefined
): boolean {
  if (!Array.isArray(a) || !Array.isArray(b)) {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  for (let i = 0; i < a.length; i++) {
    const ai = a[i];
    const bi = b[i];
    if (ai === undefined || bi === undefined) {
      return false;
    }
    if (Number(ai.from) !== Number(bi.from) || Number(ai.to) !== Number(bi.to)) {
      return false;
    }
  }

  return true;
}

/**
 * Union of TCP ports from the given presets (by id), merged into ranges.
 * Empty ids or ids containing `full` yield the full 1–65535 range.
 */
export function mergePresetsByIds(ids: string[]): PortExprItem[] {
  const uniqueIds = [...new Set(ids)];

  if (uniqueIds.length === 0 || uniqueIds.includes('full')) {
    return [{ from: 1, to: 65535 }];
  }

  const ports = new Set<number>();

  for (const id of uniqueIds) {
    const preset = SCAN_PORT_PRESETS.find((p) => p.id === id);
    if (!preset) {
      continue;
    }

    for (const r of preset.portsExpr) {
      const from = Number(r.from);
      const to = Number(r.to);

      if (!Number.isFinite(from) || !Number.isFinite(to) || to < from) {
        continue;
      }

      for (let p = from; p <= to; p++) {
        ports.add(p);
      }
    }
  }

  if (ports.size === 0) {
    return [{ from: 1, to: 65535 }];
  }

  return mergePortIntsToRanges([...ports]);
}

export function findMatchingPreset(
  portsExpr: PortExprItem[]
): PortPreset | undefined {
  if (!Array.isArray(portsExpr) || portsExpr.length === 0) {
    return undefined;
  }

  return SCAN_PORT_PRESETS.find((preset) => {
    if (preset.portsExpr.length !== portsExpr.length) {
      return false;
    }

    for (let i = 0; i < preset.portsExpr.length; i++) {
      const a = preset.portsExpr[i];
      const b = portsExpr[i];

      if (a === undefined || b === undefined) {
        return false;
      }

      if (Number(a.from) !== Number(b.from) || Number(a.to) !== Number(b.to)) {
        return false;
      }
    }

    return true;
  });
}

function rangesOverlap(a: PortExprItem, b: PortExprItem): boolean {
  return Number(a.from) <= Number(b.to) && Number(b.from) <= Number(a.to);
}

function presetOverlapsExpr(preset: PortPreset, expr: PortExprItem[]): boolean {
  return preset.portsExpr.some((pr) =>
    expr.some((er) => rangesOverlap(pr, er))
  );
}

/** k-combinations of `elements` (order within each combo follows `elements`). */
function combinations<T>(elements: readonly T[], k: number): T[][] {
  if (k === 0) {
    return [[]];
  }

  if (k > elements.length) {
    return [];
  }

  const first = elements[0];
  if (first === undefined) {
    return [];
  }

  const rest = elements.slice(1);
  const withFirst = combinations(rest, k - 1).map((c) => [first, ...c]);
  const withoutFirst = combinations(rest, k);

  return [...withFirst, ...withoutFirst];
}

const MAX_PRESET_COMBO_SIZE = 8;

/**
 * Resolves `portsExpr` to a preset id list for UI checkboxes: single preset,
 * or a small multi-select whose merge equals `portsExpr`. Returns [] when no
 * known preset combination matches (custom port list).
 */
export function findMatchingPresetSelection(
  portsExpr: PortExprItem[]
): string[] {
  if (!Array.isArray(portsExpr) || portsExpr.length === 0) {
    return [];
  }

  const single = findMatchingPreset(portsExpr);

  if (single) {
    return [single.id];
  }

  const candidates = SCAN_PORT_PRESETS.filter(
    (p) => p.id !== 'full' && presetOverlapsExpr(p, portsExpr)
  ).map((p) => p.id);
  const maxK = Math.min(MAX_PRESET_COMBO_SIZE, candidates.length);

  for (let k = 2; k <= maxK; k++) {
    for (const combo of combinations(candidates, k)) {
      if (portExprListsEqual(mergePresetsByIds(combo), portsExpr)) {
        return combo;
      }
    }
  }

  return [];
}
