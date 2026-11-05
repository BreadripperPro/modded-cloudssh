import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { isApiUrl } from '../frontend/e2e-server';
import viteConfig from '../frontend/vite.config';

const ts = createRequire(import.meta.url)('typescript') as typeof import('typescript');

function specFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? specFiles(path) : entry.name.endsWith('.spec.ts') ? [path] : [];
  });
}

describe('E2E 网络隔离门禁', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('所有浏览器 spec 必须从自动 fixture 导入 test，不得绕过请求守卫', () => {
    const violations: string[] = [];
    for (const path of specFiles(resolve('tests/e2e'))) {
      const source = ts.createSourceFile(
        path, readFileSync(path, 'utf8'), ts.ScriptTarget.Latest, true
      );
      let hasFixtureTest = false;
      for (const statement of source.statements) {
        if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) {
          continue;
        }
        const clause = statement.importClause;
        if (!clause || clause.isTypeOnly) continue;
        const module = statement.moduleSpecifier.text;
        const bindings = clause.namedBindings;
        if (module === '@playwright/test') {
          violations.push(`${path}: use ./fixtures instead of raw Playwright imports`);
        }
        if (module === './fixtures' && bindings && ts.isNamedImports(bindings)) {
          hasFixtureTest ||= bindings.elements.some((item) =>
            !item.isTypeOnly && (item.propertyName?.text || item.name.text) === 'test'
          );
        }
      }
      if (!hasFixtureTest) violations.push(`${path}: missing automatic fixture test import`);
    }
    expect(violations).toEqual([]);
  });

  it('API 路径边界与查询参数不混淆', () => {
    expect(isApiUrl(new URL('http://127.0.0.1/api'))).toBe(true);
    expect(isApiUrl(new URL('http://127.0.0.1/api/user/theme?id=one'))).toBe(true);
    expect(isApiUrl(new URL('http://127.0.0.1/api-not-an-endpoint'))).toBe(false);
    expect(isApiUrl(new URL('http://127.0.0.1/?next=/api/user/theme'))).toBe(false);
  });

  it('只有 E2E 启用 JSON 拒绝兜底，普通开发保留 Worker 代理', () => {
    vi.stubEnv('E2E_TEST', '');
    const development = viteConfig({ command: 'serve', mode: 'development' });
    expect(development.server?.proxy).toEqual({
      '/api': { target: 'http://localhost:8787', ws: true },
    });
    expect(development.plugins).toEqual([]);
    const e2e = viteConfig({ command: 'serve', mode: 'e2e' });
    expect(e2e.server?.proxy).toBeUndefined();
    expect(e2e.plugins).toEqual([expect.objectContaining({ name: 'cloudssh-e2e-api-isolation' })]);
  });
});
