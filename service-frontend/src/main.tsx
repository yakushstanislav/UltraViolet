import React from 'react';
import ReactDOM from 'react-dom/client';
import { Provider } from 'react-redux';
import { BrowserRouter } from 'react-router-dom';
import { Toaster } from 'sonner';

import '@fontsource/jetbrains-mono/latin-400.css';
import '@fontsource/jetbrains-mono/latin-600.css';
import '@fontsource/space-grotesk/latin-400.css';
import '@fontsource/space-grotesk/latin-500.css';
import '@fontsource/space-grotesk/latin-600.css';
import '@fontsource/space-grotesk/latin-700.css';

import { clearChunkReloadFlag } from '@helpers/chunkLoadError';
import { registerViteChunkRecovery } from '@helpers/registerViteChunkRecovery';

import { App } from './app/App';
import { AppDocumentI18n } from './i18n/AppDocumentI18n';
import './i18n/i18n';
import { bootstrapAuth, loadMe, resetAuth } from './features/Auth/authSlice';
import { setAuthHooks } from './services/authEvents';
import { realtime } from './services/realtimeClient';
import { store } from './store/store';
import { ThemeProvider, useTheme } from './theme/ThemeProvider';
import './index.css';
import './styles/mobile.css';

registerViteChunkRecovery();
clearChunkReloadFlag();

void store.dispatch(bootstrapAuth());

setAuthHooks({
  onUnauthorized: () => {
    store.dispatch(resetAuth());
  },
  onForbidden: () => {
    void store.dispatch(loadMe());
  },
});

let lastAuthenticated = false;
store.subscribe(() => {
  const role = store.getState().auth.role;
  const authenticated = role !== null;

  if (authenticated === lastAuthenticated) {
    return;
  }

  lastAuthenticated = authenticated;

  if (authenticated) {
    realtime.connect();
  } else {
    realtime.disconnect();
  }
});

function AppToaster() {
  const { theme } = useTheme();
  return <Toaster richColors theme={theme} />;
}

const rootEl = document.getElementById('root');

if (!rootEl) {
  throw new Error('#root element not found');
}

const routerBaseName = (import.meta.env.BASE_URL ?? '/').replace(/\/$/, '') || '/';

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <Provider store={store}>
      <ThemeProvider>
        <BrowserRouter basename={routerBaseName}>
          <AppDocumentI18n />
          <App />
          <AppToaster />
        </BrowserRouter>
      </ThemeProvider>
    </Provider>
  </React.StrictMode>
);
