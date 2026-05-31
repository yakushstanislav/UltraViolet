/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
  readonly VITE_REALTIME_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

declare const __BUILD_SHA__: string;
declare const __APP_VERSION__: string;
