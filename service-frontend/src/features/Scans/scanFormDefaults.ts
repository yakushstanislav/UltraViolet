import type { ScanFormValues } from '@schemas/scan';

export const SCAN_CREATE_FORM_DEFAULTS: ScanFormValues = {
  target: '127.0.0.1',
  scanSubnet: false,
  mode: 'slow',
  slowProfile: 'stealth',
  targetStrategy: 'sequential',
  portsExpr: [{ from: 1, to: 65535 }],
};
