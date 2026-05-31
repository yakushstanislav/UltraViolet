import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { visualizer } from 'rollup-plugin-visualizer';
import { defineConfig } from 'vite';
import compression from 'vite-plugin-compression';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function readPackageVersion(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(path.resolve(__dirname, 'package.json'), 'utf8'),
    ) as { version?: string };

    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function readBuildSha(): string {
  try {
    return execSync('git rev-parse --short HEAD', { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim();
  } catch {
    return 'dev';
  }
}

function normalizeBasePath(raw: string | undefined): string {
  if (!raw || raw === '/') {
    return '/';
  }

  let value = raw.startsWith('/') ? raw : `/${raw}`;
  if (!value.endsWith('/')) {
    value = `${value}/`;
  }

  return value;
}

const basePath = normalizeBasePath(process.env.VITE_BASE_PATH);

export default defineConfig({
  base: basePath,
  define: {
    __BUILD_SHA__: JSON.stringify(readBuildSha()),
    __APP_VERSION__: JSON.stringify(readPackageVersion()),
  },
  plugins: [
    react(),
    tailwindcss(),
    compression({ algorithm: 'gzip', ext: '.gz' }),
    compression({ algorithm: 'brotliCompress', ext: '.br' }),
    visualizer({ open: false, filename: 'dist/stats.html' }),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@app': path.resolve(__dirname, './src/app'),
      '@components': path.resolve(__dirname, './src/components'),
      '@features': path.resolve(__dirname, './src/features'),
      '@helpers': path.resolve(__dirname, './src/helpers'),
      '@hooks': path.resolve(__dirname, './src/hooks'),
      '@schemas': path.resolve(__dirname, './src/schemas'),
      '@services': path.resolve(__dirname, './src/services'),
      '@storage': path.resolve(__dirname, './src/storage'),
      '@store': path.resolve(__dirname, './src/store'),
      '@i18n': path.resolve(__dirname, './src/i18n'),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    // Mirror production nginx: browser calls /api/v1/... → uv-api on :8080.
    // Use 127.0.0.1 (not localhost): on macOS localhost may resolve to ::1 while
    // Docker publishes IPv4 only → intermittent ECONNREFUSED on /api/v1/scans etc.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
        configure: (proxy) => {
          proxy.on('error', (err, _req, res) => {
            console.warn('[vite] /api proxy:', err.message);

            if (res.writeHead && !res.headersSent) {
              res.writeHead(502, { 'Content-Type': 'application/json' });
              res.end(
                JSON.stringify({
                  error: 'api_unreachable',
                  message:
                    'uv-api on 127.0.0.1:8080 is not reachable.',
                })
              );
            }
          });
        },
      },
      '/realtime': {
        target: 'http://127.0.0.1:8081',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/realtime/, ''),
        ws: true,
        configure: (proxy) => {
          proxy.on('error', (err) => {
            console.warn('[vite] /realtime proxy:', err.message);
          });
        },
      },
    },
  },
  build: {
    modulePreload: {
      resolveDependencies(_filename, deps) {
        return deps.filter(
          (dep) =>
            !dep.includes('leaflet-vendor') && !dep.includes('cobe-vendor')
        );
      },
    },
    minify: 'terser',
    terserOptions: {
      compress: {
        pure_funcs: ['console.log', 'console.debug', 'console.info'],
        drop_debugger: true,
      },
    },
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('/src/data/')) {
            return 'static-data';
          }

          if (id.includes('leaflet')) {
            return 'leaflet-vendor';
          }

          if (id.includes('cobe')) {
            return 'cobe-vendor';
          }

          if (!id.includes('node_modules')) {
            return;
          }

          if (
            id.includes('react') ||
            id.includes('react-dom') ||
            id.includes('react-router')
          ) {
            return 'react-vendor';
          }

          if (
            id.includes('@reduxjs/toolkit') ||
            id.includes('react-redux') ||
            id.includes('redux')
          ) {
            return 'redux-vendor';
          }

          if (id.includes('zod') || id.includes('react-hook-form')) {
            return 'forms-vendor';
          }

          if (id.includes('dayjs')) {
            return 'date-vendor';
          }

          if (id.includes('axios')) {
            return 'network-vendor';
          }
        },
      },
    },
    chunkSizeWarningLimit: 1000,
  },
});
