import { expect, test } from './fixtures';
import { mockThemeLibrary, type CloudTheme } from './theme-mocks';

const remoteTheme: CloudTheme = {
  id: 'cth_remote',
  name: 'Cloud Theme',
  createdAt: 1,
  data: {
    schemaVersion: 4,
    name: 'Cloud Theme',
    baseTheme: 'cyberpunk',
    colorScheme: 'dark',
    ui: { '--accent': '#00ffaa' },
  },
};

test.beforeEach(async ({ page }) => {
  await page.route('**/api/auth/me', (route) =>
    route.fulfill({
      json: { id: 1, github_id: 1, username: 'theme-tester', avatar_url: '' },
    })
  );
  await page.route('**/api/servers', (route) => route.fulfill({ json: [] }));
});

test('GET 成功恢复多主题库，使用云端 activeId 且不误入旧版回退请求', async ({ page }) => {
  const api = await mockThemeLibrary(page, {
    methods: ['GET'],
    themes: [remoteTheme],
    activeId: remoteTheme.id,
  });
  const received = page.waitForResponse(
    (response) => new URL(response.url()).pathname === '/api/user/theme'
  );
  await page.goto('/?lang=en-US');
  const response = await received;
  expect(response.status()).toBe(200);
  expect(response.headers()['content-type']).toContain('application/json');
  await expect(page.locator('#user-space-section')).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'custom');
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem('cloudssh_active_custom_theme_id')))
    .toBe(remoteTheme.id);
  expect(api.requests.map((request) => request.method)).toEqual(['GET']);
  expect(await page.evaluate(() => localStorage.getItem('cloudssh_custom_themes'))).toContain(
    'Cloud Theme'
  );
});

for (const failure of [503, 'network'] as const) {
  test(`GET 失败（${failure}）保留本地主题库与用户选择，页面继续可用`, async ({ page }) => {
    const localTheme = { ...remoteTheme, id: 'cth_local', name: 'Local Theme' };
    await page.addInitScript((theme) => {
      localStorage.setItem('cloudssh_custom_themes', JSON.stringify([theme]));
      localStorage.setItem('cloudssh_active_custom_theme_id', theme.id);
      localStorage.setItem('cloudssh_theme_selection', 'standard-light');
    }, localTheme);
    const api = await mockThemeLibrary(page, { methods: ['GET'], failures: { GET: failure } });
    await page.goto('/?lang=en-US');
    await expect(page.locator('#user-space-section')).toBeVisible();
    // The current compatibility path tries one legacy GET after the library GET fails.
    await expect.poll(() => api.requests.length).toBe(2);
    expect(
      api.requests.every((request) => request.method === 'GET' && request.status === failure)
    ).toBe(true);
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'standard-light');
    expect(await page.evaluate(() => localStorage.getItem('cloudssh_custom_themes'))).toContain(
      'Local Theme'
    );
    expect(await page.evaluate(() => localStorage.getItem('cloudssh_active_custom_theme_id'))).toBe(
      localTheme.id
    );
  });
}

test('PUT 失败明确返回 false，保留本地资产而不伪造云端持久化成功', async ({ page }) => {
  const api = await mockThemeLibrary(page, { methods: ['GET', 'PUT'], failures: { PUT: 503 } });
  await page.goto('/?lang=en-US');
  await expect(page.locator('#user-space-section')).toBeVisible();
  await expect
    .poll(() => api.requests.filter((request) => request.method === 'GET').length)
    .toBe(2);
  const result = await page.evaluate(async (data) => {
    const { customThemeStore: store } = await (window as any).eval(
      "import('/src/custom-theme-manager.ts')"
    );
    const item = await store.addTheme('Local Unsynced Theme', data);
    return { id: item.id, synced: await store.syncToCloud() };
  }, remoteTheme.data);
  expect(result.synced).toBe(false);
  expect(api.cloud.themes).toEqual([]);
  expect(api.requests).toContainEqual(expect.objectContaining({
    method: 'PUT',
    status: 503,
    body: expect.objectContaining({
      active_id: result.id,
      themes: [expect.objectContaining({ id: result.id, name: 'Local Unsynced Theme' })],
    }),
  }));
  expect(await page.evaluate(() => localStorage.getItem('cloudssh_custom_themes'))).toContain(
    'Local Unsynced Theme'
  );
});

test('带 id 的 DELETE 失败返回 false，云端和调用前本地资产保持原样', async ({ page }) => {
  const api = await mockThemeLibrary(page, {
    methods: ['GET', 'DELETE'],
    themes: [remoteTheme],
    activeId: remoteTheme.id,
    failures: { DELETE: 503 },
  });
  await page.goto('/?lang=en-US');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'custom');
  const deleted = await page.evaluate(async (id) => {
    const { customThemeStore: store } = await (window as any).eval(
      "import('/src/custom-theme-manager.ts')"
    );
    // Test the HTTP result contract directly; removeTheme() is intentionally local-first.
    return store.deleteFromCloud(id);
  }, remoteTheme.id);
  expect(deleted).toBe(false);
  expect(api.requests.filter((request) => request.method === 'DELETE')).toEqual([
    expect.objectContaining({ id: remoteTheme.id, status: 503 }),
  ]);
  expect(api.cloud.themes.map((theme) => theme.id)).toEqual([remoteTheme.id]);
  expect(await page.evaluate(() => localStorage.getItem('cloudssh_custom_themes'))).toContain(
    remoteTheme.id
  );
});
