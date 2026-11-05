import type { Page } from '@playwright/test';

export const OPTIONAL_THIRD_PARTY_ASSETS =
  /https:\/\/(fonts\.googleapis\.com|fonts\.gstatic\.com|challenges\.cloudflare\.com)\/.*/;

export async function blockOptionalThirdPartyAssets(page: Page): Promise<void> {
  await page.route(OPTIONAL_THIRD_PARTY_ASSETS, (route) => route.abort());
}

// Base API reads are installed automatically by fixtures.ts, independently of these helpers.
export async function mockAnonymousSession(page: Page): Promise<void> {
  await blockOptionalThirdPartyAssets(page);
  await page.route('**/api/auth/me', (route) =>
    route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: '{"error":"unauthorized"}',
    })
  );
}
