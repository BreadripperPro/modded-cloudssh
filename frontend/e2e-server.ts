import type { Plugin } from 'vite';

export const E2E_UNMOCKED_API_HEADER = 'x-cloudssh-e2e-unmocked-api';

export function isApiUrl(url: URL): boolean {
  return url.pathname === '/api' || url.pathname.startsWith('/api/');
}

/** Dev-server-only safety net: never turn a missing E2E API mock into the SPA HTML. */
export function e2eApiIsolation(): Plugin {
  return {
    name: 'cloudssh-e2e-api-isolation',
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        const url = new URL(request.url || '/', 'http://127.0.0.1');
        if (!isApiUrl(url)) {
          next();
          return;
        }

        response.writeHead(501, {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          [E2E_UNMOCKED_API_HEADER]: 'true',
        });
        // Never include query values, request bodies or credentials in diagnostics.
        response.end(JSON.stringify({
          error: 'Unmocked E2E API request',
          method: request.method,
          path: url.pathname,
        }));
      });
    },
  };
}
