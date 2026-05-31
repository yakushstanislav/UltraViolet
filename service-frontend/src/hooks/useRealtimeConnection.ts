import { useEffect, useState } from 'react';

import {
  realtime,
  type RealtimeConnectionState,
} from '@services/realtimeClient';

export function useRealtimeConnection(): RealtimeConnectionState {
  const [state, setState] = useState<RealtimeConnectionState>(
    realtime.getConnectionState(),
  );

  useEffect(() => realtime.subscribeConnection(setState), []);

  return state;
}
