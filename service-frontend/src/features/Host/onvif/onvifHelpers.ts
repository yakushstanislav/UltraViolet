import type { TFunction } from 'i18next';

import i18n from '@i18n/i18n';
import type { ONVIFCommandRequest } from '@/types/hosts';

export const COMMAND_ORDER = [
  'get_system_date_and_time',
  'get_capabilities',
  'get_device_information',
  'get_hostname',
  'get_media_profiles',
  'get_video_sources',
  'get_snapshot_uri',
  'get_stream_uri',
  'get_media_service_capabilities',
  'get_imaging_settings',
  'get_imaging_options',
  'get_ptz_configurations',
  'get_ptz_nodes',
  'get_ptz_status',
] as const satisfies readonly ONVIFCommandRequest['command'][];

/** Matches API `onvifProfileTokenRE` — tokens outside this set are not offered as chips. */
const MEDIA_COMMANDS = new Set<ONVIFCommandRequest['command']>([
  'get_media_profiles',
  'get_stream_uri',
  'get_video_sources',
  'get_snapshot_uri',
  'get_media_service_capabilities',
]);

const IMAGING_COMMANDS = new Set<ONVIFCommandRequest['command']>([
  'get_imaging_settings',
  'get_imaging_options',
]);

const PTZ_COMMANDS = new Set<ONVIFCommandRequest['command']>([
  'get_ptz_configurations',
  'get_ptz_nodes',
  'get_ptz_status',
]);

const ONVIF_TOKEN_CHIP_RE = /^[A-Za-z0-9_.-]{1,128}$/;

export function onvifCommandLabel(
  value: ONVIFCommandRequest['command'],
  translate: TFunction
): string {
  return translate(`onvif.commands.${value}`);
}

export function formatOnvifUserMessage(
  translate: TFunction,
  code: string | undefined
): string {
  const key =
    code !== undefined && code !== ''
      ? (`onvif.errors.${code}` as const)
      : null;

  if (key !== null && i18n.exists(key)) {
    return translate(key);
  }

  return code !== undefined && code !== ''
    ? code
    : translate('onvif.errors.requestFailed');
}

export function isOnvifMediaCommand(
  cmd: ONVIFCommandRequest['command']
): boolean {
  return MEDIA_COMMANDS.has(cmd);
}

export function isOnvifImagingCommand(
  cmd: ONVIFCommandRequest['command']
): boolean {
  return IMAGING_COMMANDS.has(cmd);
}

export function isOnvifPTZCommand(
  cmd: ONVIFCommandRequest['command']
): boolean {
  return PTZ_COMMANDS.has(cmd);
}

export function needsProfileToken(
  cmd: ONVIFCommandRequest['command']
): boolean {
  return (
    cmd === 'get_stream_uri' ||
    cmd === 'get_snapshot_uri' ||
    cmd === 'get_ptz_status'
  );
}

export function needsVideoSourceToken(
  cmd: ONVIFCommandRequest['command']
): boolean {
  return cmd === 'get_imaging_settings' || cmd === 'get_imaging_options';
}

export type HttpStatusTone =
  | 'success'
  | 'redirect'
  | 'client'
  | 'server'
  | 'unknown';

export function httpStatusTone(code: number): HttpStatusTone {
  if (code >= 200 && code < 300) {
    return 'success';
  }

  if (code >= 300 && code < 400) {
    return 'redirect';
  }

  if (code >= 400 && code < 500) {
    return 'client';
  }

  if (code >= 500 && code < 600) {
    return 'server';
  }

  return 'unknown';
}

export function videoSourceTokensFromXml(body: string): string[] {
  const re = /<(?:[\w.]+:)?VideoSource[^>]*token="([^"]+)"/gi;
  const seen = new Set<string>();
  const out: string[] = [];

  let m = re.exec(body);
  while (m !== null) {
    const t = m[1]?.trim() ?? '';
    if (t !== '' && ONVIF_TOKEN_CHIP_RE.test(t) && !seen.has(t)) {
      seen.add(t);
      out.push(t);
    }

    m = re.exec(body);
  }

  return out;
}

export function profileTokensFromParsed(
  parsed: Record<string, unknown> | undefined
): string[] {
  if (parsed === undefined) {
    return [];
  }

  const profiles = parsed.profiles;
  if (Array.isArray(profiles)) {
    const out: string[] = [];

    for (const p of profiles) {
      if (
        typeof p === 'object' &&
        p !== null &&
        'token' in p &&
        typeof (p as { token: unknown }).token === 'string'
      ) {
        const t = (p as { token: string }).token.trim();
        if (t !== '' && ONVIF_TOKEN_CHIP_RE.test(t)) {
          out.push(t);
        }
      }
    }

    if (out.length > 0) {
      return out;
    }
  }

  const v = parsed.profile_tokens;
  if (!Array.isArray(v)) {
    return [];
  }

  return v.filter(
    (x): x is string =>
      typeof x === 'string' && x !== '' && ONVIF_TOKEN_CHIP_RE.test(x.trim())
  );
}

export function videoSourceTokensFromParsed(
  parsed: Record<string, unknown> | undefined
): string[] {
  if (parsed === undefined) {
    return [];
  }

  const vs = parsed.video_sources;
  if (!Array.isArray(vs)) {
    return [];
  }

  const out: string[] = [];

  for (const item of vs) {
    if (
      typeof item === 'object' &&
      item !== null &&
      'token' in item &&
      typeof (item as { token: unknown }).token === 'string'
    ) {
      const t = (item as { token: string }).token.trim();
      if (t !== '' && ONVIF_TOKEN_CHIP_RE.test(t)) {
        out.push(t);
      }
    }
  }

  return out;
}
