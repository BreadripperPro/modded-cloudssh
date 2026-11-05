import type { Page } from './fixtures';

export interface CloudTheme {
  id: string;
  name: string;
  data: unknown;
  createdAt: number;
}

type ThemeMethod = 'GET' | 'PUT' | 'DELETE';

/** Stateful fake backend, installed explicitly only by theme-sync business tests. */
export async function mockThemeLibrary(page: Page, options: {
  methods: ThemeMethod[];
  themes?: CloudTheme[];
  activeId?: string | null;
  failures?: Partial<Record<ThemeMethod, number | 'network'>>;
}) {
  let themes = structuredClone(options.themes || []);
  let activeId = options.activeId || null;
  const requests: Array<{
    method: string;
    id: string | null;
    body: unknown;
    status: number | 'network';
  }> = [];

  await page.route((url) => url.pathname === '/api/user/theme', async (route) => {
    const request = route.request();
    const method = request.method() as ThemeMethod;
    if (!options.methods.includes(method)) return route.fallback();
    const url = new URL(request.url());
    const body: unknown = method === 'PUT' ? request.postDataJSON() : null;
    const failure = options.failures?.[method];
    requests.push({ method, id: url.searchParams.get('id'), body, status: failure || 200 });
    if (failure === 'network') return route.abort('failed');
    if (failure) {
      return route.fulfill({ status: failure, json: { error: 'Theme service unavailable' } });
    }

    if (method === 'GET') {
      return route.fulfill({ json: { themes, activeId, theme: null } });
    }
    if (method === 'PUT') {
      const payload = body as { themes: CloudTheme[]; active_id: string | null };
      themes = structuredClone(payload.themes);
      activeId = payload.active_id;
    } else {
      const id = url.searchParams.get('id');
      themes = id ? themes.filter((theme) => theme.id !== id) : [];
      if (!themes.some((theme) => theme.id === activeId)) activeId = themes[0]?.id || null;
    }
    return route.fulfill({ json: { success: true } });
  });

  return {
    requests,
    get cloud() {
      return structuredClone({ themes, activeId });
    },
  };
}
