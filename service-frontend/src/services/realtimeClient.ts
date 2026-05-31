import {
  clearAuthTokens,
  getAccessToken,
  getRealtimeURL,
} from '@storage/accessToken';

import { emitUnauthorized } from './authEvents';
import type { RealtimeEvent } from '@/types/realtime';

export type RealtimeConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting';

type Handler = (event: RealtimeEvent) => void;
type ConnectionListener = (state: RealtimeConnectionState) => void;

type GlobalSubscription = {
  types: Set<string>;
  handler: Handler;
};

type ScanSubscription = {
  handler: Handler;
};

const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;
const PING_INTERVAL_MS = 25000;
const PONG_TIMEOUT_MS = PING_INTERVAL_MS * 2;
const CONNECT_TIMEOUT_MS = 15000;
const TOKEN_SUBPROTOCOL = 'uv-token.v1';

let socket: WebSocket | null = null;
let connectGeneration = 0;
let backoffMs = INITIAL_BACKOFF_MS;
let reconnectTimer: number | null = null;
let pingTimer: number | null = null;
let missedPongs = 0;
let lastPongAt = Date.now();
let connectionState: RealtimeConnectionState = 'disconnected';
let hadConnectedOnce = false;
let activeConnectURL = '';
let connectTimeoutTimer: number | null = null;

const globalSubs = new Set<GlobalSubscription>();
const scanSubs = new Map<number, ScanSubscription>();
const activeScanIds = new Set<number>();
const connectionListeners = new Set<ConnectionListener>();
const pendingOutbound: unknown[] = [];

function setConnectionState(next: RealtimeConnectionState): void {
  if (connectionState === next) {
    return;
  }

  connectionState = next;

  for (const listener of connectionListeners) {
    listener(next);
  }
}

function wsURL(): string {
  const realtimeBase = getRealtimeURL().replace(/\/$/, '');

  if (realtimeBase.startsWith('/')) {
    return `${realtimeBase}/v1/ws`;
  }

  const wsBase = realtimeBase
    .replace(/^http:\/\//i, 'ws://')
    .replace(/^https:\/\//i, 'wss://');

  return `${wsBase}/v1/ws`;
}

function clientSubprotocols(): string[] {
  const sha = __BUILD_SHA__ !== '' ? __BUILD_SHA__ : 'dev';
  const token = getAccessToken();

  return [TOKEN_SUBPROTOCOL, token, `uv-frontend.v1.${sha}`];
}

function clearTimers(): void {
  if (reconnectTimer !== null) {
    window.clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }

  if (pingTimer !== null) {
    window.clearInterval(pingTimer);
    pingTimer = null;
  }

  if (connectTimeoutTimer !== null) {
    window.clearTimeout(connectTimeoutTimer);
    connectTimeoutTimer = null;
  }
}

function scheduleReconnect(): void {
  if (reconnectTimer !== null) {
    return;
  }

  if (getAccessToken() === '') {
    setConnectionState('disconnected');

    return;
  }

  setConnectionState(hadConnectedOnce ? 'reconnecting' : 'connecting');

  reconnectTimer = window.setTimeout(() => {
    reconnectTimer = null;
    connectInternal();
  }, backoffMs);

  backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
}

function sendJSON(payload: unknown): void {
  if (socket?.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(payload));

    return;
  }

  if (socket?.readyState === WebSocket.CONNECTING) {
    pendingOutbound.push(payload);

    return;
  }
}

function resubscribeScans(): void {
  pendingOutbound.length = 0;

  for (const scanId of activeScanIds) {
    sendJSON({ op: 'subscribe', scan_id: scanId });
  }
}

function dispatchEvent(event: RealtimeEvent): void {
  for (const sub of globalSubs) {
    if (sub.types.size === 0 || sub.types.has(event.type)) {
      sub.handler(event);
    }
  }

  if (event.scan_id !== undefined) {
    const scanSub = scanSubs.get(event.scan_id);
    if (scanSub) {
      scanSub.handler(event);
    }
  }
}

function handleMessage(raw: string): void {
  try {
    const event = JSON.parse(raw) as RealtimeEvent;

    if ((event as { op?: string }).op === 'pong') {
      missedPongs = 0;
      lastPongAt = Date.now();

      return;
    }

    dispatchEvent(event);
  } catch {
    // ignore malformed frames
  }
}

function startPingLoop(): void {
  if (pingTimer !== null) {
    window.clearInterval(pingTimer);
  }

  missedPongs = 0;
  lastPongAt = Date.now();

  pingTimer = window.setInterval(() => {
    if (socket?.readyState !== WebSocket.OPEN) {
      return;
    }

    if (Date.now() - lastPongAt > PONG_TIMEOUT_MS) {
      missedPongs += 1;
    } else {
      missedPongs = 0;
    }

    if (missedPongs >= 2) {
      socket.close();

      return;
    }

    sendJSON({ op: 'ping' });
  }, PING_INTERVAL_MS);
}

function connectInternal(): void {
  const token = getAccessToken();
  if (token === '') {
    setConnectionState('disconnected');

    return;
  }

  const url = wsURL();

  if (
    socket?.readyState === WebSocket.CONNECTING &&
    activeConnectURL === url
  ) {
    setConnectionState(hadConnectedOnce ? 'reconnecting' : 'connecting');

    return;
  }

  const generation = ++connectGeneration;

  setConnectionState(hadConnectedOnce ? 'reconnecting' : 'connecting');
  activeConnectURL = url;

  if (socket) {
    socket.onopen = null;
    socket.onmessage = null;
    socket.onclose = null;
    socket.onerror = null;

    if (
      socket.readyState === WebSocket.OPEN ||
      socket.readyState === WebSocket.CONNECTING
    ) {
      socket.close();
    }

    socket = null;
  }

  const ws = new WebSocket(url, clientSubprotocols());
  socket = ws;

  connectTimeoutTimer = window.setTimeout(() => {
    if (generation !== connectGeneration) {
      return;
    }

    if (ws.readyState === WebSocket.CONNECTING) {
      ws.close();
    }
  }, CONNECT_TIMEOUT_MS);

  ws.onopen = () => {
    if (generation !== connectGeneration) {
      return;
    }

    if (connectTimeoutTimer !== null) {
      window.clearTimeout(connectTimeoutTimer);
      connectTimeoutTimer = null;
    }

    hadConnectedOnce = true;
    backoffMs = INITIAL_BACKOFF_MS;

    const queued = pendingOutbound
      .splice(0)
      .filter((p) => (p as { op?: string }).op !== 'subscribe');
    setConnectionState('connected');
    resubscribeScans();

    for (const payload of queued) {
      ws.send(JSON.stringify(payload));
    }

    startPingLoop();
  };

  ws.onmessage = (ev) => {
    if (typeof ev.data === 'string') {
      handleMessage(ev.data);
    }
  };

  ws.onclose = () => {
    if (generation !== connectGeneration) {
      return;
    }

    clearTimers();
    socket = null;
    activeConnectURL = '';

    if (getAccessToken() === '') {
      setConnectionState('disconnected');

      return;
    }

    scheduleReconnect();
  };

  ws.onerror = () => {
    ws.close();
  };
}

export const realtime = {
  connect(): void {
    if (getAccessToken() === '') {
      return;
    }

    connectInternal();
  },

  disconnect(): void {
    connectGeneration += 1;
    clearTimers();
    activeScanIds.clear();
    hadConnectedOnce = false;
    activeConnectURL = '';
    pendingOutbound.length = 0;

    if (socket) {
      socket.onopen = null;
      socket.onmessage = null;
      socket.onclose = null;
      socket.onerror = null;
      socket.close();
      socket = null;
    }

    setConnectionState('disconnected');
  },

  getConnectionState(): RealtimeConnectionState {
    return connectionState;
  },

  subscribeConnection(listener: ConnectionListener): () => void {
    connectionListeners.add(listener);
    listener(connectionState);

    return () => {
      connectionListeners.delete(listener);
    };
  },

  subscribe(types: string[], handler: Handler): () => void {
    const sub: GlobalSubscription = {
      types: new Set(types),
      handler,
    };
    globalSubs.add(sub);

    return () => {
      globalSubs.delete(sub);
    };
  },

  refresh(newToken: string): void {
    if (newToken === '') {
      return;
    }

    sendJSON({ op: 'refresh', token: newToken });
  },

  subscribeScan(scanId: number, handler: Handler): () => void {
    activeScanIds.add(scanId);
    scanSubs.set(scanId, { handler });

    sendJSON({ op: 'subscribe', scan_id: scanId });

    if (
      !socket ||
      socket.readyState === WebSocket.CLOSED ||
      socket.readyState === WebSocket.CLOSING
    ) {
      connectInternal();
    }

    return () => {
      activeScanIds.delete(scanId);
      scanSubs.delete(scanId);
      sendJSON({ op: 'unsubscribe', scan_id: scanId });
    };
  },
};

export function handleRealtimeAuthFailure(): void {
  clearAuthTokens();
  realtime.disconnect();
  emitUnauthorized();
}
