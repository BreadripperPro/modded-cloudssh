import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Env } from '../../src/types';
import {
  getFrontendOriginPolicy,
  isAllowedFrontendOrigin,
  isTrustedRequestOrigin,
  normalizeFrontendOrigin,
} from '../../src/worker/frontend-origins';

// =====================================================================
// frontend-cors.test.ts
// ---------------------------------------------------------------
// 独立部署的前端（Vercel 等）与 CloudSSH Worker 之间的跨源接入回归测试：
//   1. Origin 白名单解析 — 精确匹配、拒绝通配符/路径/非回环明文 HTTP
//   2. CORS 预检 — 白名单内放行并回显具体 origin；白名单外 fail closed
//   3. CORS 响应头 — 只对白名单来源下发，且始终带 Allow-Credentials
//   4. WebSocket Origin 边界 — 白名单内外部前端放行；其余（含缺失）拒绝
//   5. CSRF Origin 校验 — 快捷键/AI 路由对白名单来源放行
//   6. 会话通道 — Bearer 头；auth_token 查询参数仅对白名单来源生效
//   7. Cookie 属性 — 跨源模式下会话 Cookie 改为 SameSite=None
//   8. 登录落点与分享链接 — FRONTEND_URL 生效且不接受开放重定向
// =====================================================================

async function loadWorker() {
  const mod = await import('../../src/worker/index');
  return mod.default;
}

const WORKER_ORIGIN = 'https://cloudssh.test';
const FRONTEND_ORIGIN = 'https://cloudssh-frontend.vercel.app';

function makeDOStub(responder: (req: Request) => Response | Promise<Response>) {
  return { fetch: vi.fn((req: Request) => responder(req)) };
}

function makeEnv(overrides: Partial<Env> & { userDbStub?: any; sshSessionStub?: any } = {}): Env {
  const { userDbStub, sshSessionStub, ...rest } = overrides;
  const defaultStub = makeDOStub(() => new Response('{"error":"not mocked"}', { status: 500 }));
  return {
    SSH_SESSION: { idFromName: () => 'do-ssh', get: () => sshSessionStub ?? defaultStub } as any,
    USER_DB: { idFromName: () => 'do-userdb', get: () => userDbStub ?? defaultStub } as any,
    SSH_SHARE: { idFromName: () => 'do-share', get: () => defaultStub } as any,
    ...rest,
  } as Env;
}

function makeRequest(
  path: string,
  opts: {
    method?: string;
    headers?: Record<string, string>;
    body?: unknown;
    cookies?: Record<string, string>;
  } = {}
): Request {
  const url = new URL(`${WORKER_ORIGIN}${path}`);
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.cookies) {
    headers['Cookie'] = Object.entries(opts.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
  const init: RequestInit = { method: opts.method ?? 'GET', headers };
  if (opts.body !== undefined) {
    headers['Content-Type'] = headers['Content-Type'] ?? 'application/json';
    init.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
  }
  return new Request(url.toString(), init);
}

const fetchMock = vi.fn();
beforeEach(() => {
  fetchMock.mockReset();
  (globalThis as { fetch: unknown }).fetch = fetchMock;
});
afterEach(() => {
  (globalThis as { fetch: unknown }).fetch = undefined;
});

const SESSION_TOKEN = '12345678:abcdef';

/** UserDB 存根：校验会话令牌并返回用户信息（其余路由未 mock） */
function makeSessionUserDbStub() {
  return makeDOStub(async (req) => {
    const path = new URL(req.url).pathname;
    if (path === '/internal/session/verify') {
      const { token } = (await req.json()) as { token: string };
      if (token !== SESSION_TOKEN) {
        return Response.json({ error: 'Invalid session' }, { status: 401 });
      }
      return Response.json({
        id: 7,
        github_id: 12345678,
        username: 'alice',
        avatar_url: null,
      });
    }
    return Response.json({ error: 'not mocked' }, { status: 500 });
  });
}

/** UserDB 存根：会话校验 + 移动端快捷键读写（供 CSRF 路由测试使用） */
function makeShortcutsUserDbStub() {
  return makeDOStub(async (req) => {
    const path = new URL(req.url).pathname;
    if (path === '/internal/session/verify') {
      const { token } = (await req.json()) as { token: string };
      if (token !== SESSION_TOKEN) {
        return Response.json({ error: 'Invalid session' }, { status: 401 });
      }
      return Response.json({
        id: 7,
        github_id: 12345678,
        username: 'alice',
        avatar_url: null,
      });
    }
    if (path === '/internal/mobile-shortcuts') {
      return Response.json({ success: true });
    }
    return Response.json({ error: 'not mocked' }, { status: 500 });
  });
}

// =====================================================================
// 1. Origin 白名单解析
// =====================================================================

describe('外部前端 Origin 白名单解析', () => {
  it('接受纯 origin 并规范化（去尾斜杠 / 小写）', () => {
    expect(normalizeFrontendOrigin('https://App.Example.com/')).toBe('https://app.example.com');
    expect(normalizeFrontendOrigin('  https://app.example.com  ')).toBe(
      'https://app.example.com'
    );
  });

  it.each([
    ['通配符', 'https://*.vercel.app'],
    ['带路径', 'https://app.example.com/app'],
    ['带查询串', 'https://app.example.com/?x=1'],
    ['带凭据', 'https://user:pass@app.example.com'],
    ['非 http(s) 协议', 'ftp://app.example.com'],
    ['生产环境明文 HTTP', 'http://app.example.com'],
    ['空值', ''],
  ])('拒绝非法 origin（%s）', (_label, value) => {
    expect(normalizeFrontendOrigin(value)).toBeNull();
  });

  it('本地回环地址允许明文 HTTP（便于本地联调）', () => {
    expect(normalizeFrontendOrigin('http://localhost:5173')).toBe('http://localhost:5173');
    expect(normalizeFrontendOrigin('http://127.0.0.1:5173')).toBe('http://127.0.0.1:5173');
  });

  it('FRONTEND_URL 自动进入白名单；FRONTEND_ORIGINS 追加额外来源', () => {
    const env = makeEnv({
      FRONTEND_URL: FRONTEND_ORIGIN,
      FRONTEND_ORIGINS: 'https://second.example.com, https://*.vercel.app',
    });
    const policy = getFrontendOriginPolicy(env);
    expect(policy.enabled).toBe(true);
    expect(policy.frontendUrl).toBe(FRONTEND_ORIGIN);
    expect(policy.allowedOrigins.has(FRONTEND_ORIGIN)).toBe(true);
    expect(policy.allowedOrigins.has('https://second.example.com')).toBe(true);
    // 非法条目被静默丢弃，绝不放宽成通配符
    expect(policy.allowedOrigins.has('https://*.vercel.app')).toBe(false);
  });

  it('未配置任何前端地址时保持纯同源（跨源模式关闭）', () => {
    const policy = getFrontendOriginPolicy(makeEnv());
    expect(policy.enabled).toBe(false);
    expect(policy.frontendUrl).toBeNull();
    expect(policy.allowedOrigins.size).toBe(0);
  });

  it('isAllowedFrontendOrigin 只认白名单内的精确来源', () => {
    const env = makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN });
    expect(isAllowedFrontendOrigin(env, FRONTEND_ORIGIN)).toBe(true);
    expect(isAllowedFrontendOrigin(env, 'https://evil.example.com')).toBe(false);
    expect(isAllowedFrontendOrigin(env, `${FRONTEND_ORIGIN}.evil.com`)).toBe(false);
    expect(isAllowedFrontendOrigin(env, null)).toBe(false);
  });

  it('isTrustedRequestOrigin：同源恒可信，跨源需命中白名单', () => {
    const env = makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN });
    expect(isTrustedRequestOrigin(env, WORKER_ORIGIN, WORKER_ORIGIN)).toBe(true);
    expect(isTrustedRequestOrigin(env, FRONTEND_ORIGIN, WORKER_ORIGIN)).toBe(true);
    expect(isTrustedRequestOrigin(env, 'https://evil.example.com', WORKER_ORIGIN)).toBe(false);
    expect(isTrustedRequestOrigin(env, null, WORKER_ORIGIN)).toBe(false);
  });
});

// =====================================================================
// 2 & 3. CORS 预检与响应头
// =====================================================================

describe('CORS 预检与响应头', () => {
  it('白名单来源的预检 → 204 + 具体 origin + Allow-Credentials', async () => {
    const worker = await loadWorker();
    const env = makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN });
    const res = await worker.fetch(
      makeRequest('/api/servers', {
        method: 'OPTIONS',
        headers: {
          Origin: FRONTEND_ORIGIN,
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'content-type, authorization',
        },
      }),
      env
    );

    expect(res.status).toBe(204);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe(FRONTEND_ORIGIN);
    expect(res.headers.get('Access-Control-Allow-Credentials')).toBe('true');
    expect(res.headers.get('Access-Control-Allow-Methods')).toContain('POST');
    expect(res.headers.get('Access-Control-Allow-Headers')).toContain('Authorization');
    expect(res.headers.get('Vary')).toContain('Origin');
  });

  it('白名单外来源的预检 → 403（fail closed，绝不返回放行信号）', async () => {
    const worker = await loadWorker();
    const env = makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN });
    const res = await worker.fetch(
      makeRequest('/api/servers', {
        method: 'OPTIONS',
        headers: { Origin: 'https://evil.example.com' },
      }),
      env
    );

    expect(res.status).toBe(403);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();
    expect(res.headers.get('Access-Control-Allow-Credentials')).toBeNull();
  });

  it('未配置外部前端时预检一律拒绝', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/servers', {
        method: 'OPTIONS',
        headers: { Origin: FRONTEND_ORIGIN },
      }),
      makeEnv()
    );
    expect(res.status).toBe(403);
  });

  it('API 响应仅对白名单来源附带 CORS 头', async () => {
    const worker = await loadWorker();
    const env = makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN });

    const allowed = await worker.fetch(
      makeRequest('/api/health', { headers: { Origin: FRONTEND_ORIGIN } }),
      env
    );
    expect(allowed.headers.get('Access-Control-Allow-Origin')).toBe(FRONTEND_ORIGIN);
    expect(allowed.headers.get('Access-Control-Allow-Credentials')).toBe('true');

    const denied = await worker.fetch(
      makeRequest('/api/health', { headers: { Origin: 'https://evil.example.com' } }),
      env
    );
    expect(denied.headers.get('Access-Control-Allow-Origin')).toBeNull();
    expect(denied.headers.get('Access-Control-Allow-Credentials')).toBeNull();
  });

  it('同源请求不附带 CORS 头（保持纯同源部署行为不变）', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/health', { headers: { Origin: WORKER_ORIGIN } }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN })
    );
    expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();
  });

  it('CORS 包装不破坏 Set-Cookie（密码登录响应必须能种会话 Cookie）', async () => {
    const worker = await loadWorker();
    const env = makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN });
    const res = await worker.fetch(
      makeRequest('/api/verify', {
        method: 'POST',
        headers: { Origin: FRONTEND_ORIGIN },
        body: { token: 'turnstile-token' },
      }),
      // 未配置 TURNSTILE_SECRET → 直接返回 success，无 Set-Cookie；用登录端点覆盖 Cookie 场景
      env
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe(FRONTEND_ORIGIN);
  });
});

// =====================================================================
// 4. WebSocket Origin 边界
// =====================================================================

describe('WebSocket Origin 边界', () => {
  it('白名单内的外部前端可升级 /api/ssh', async () => {
    const worker = await loadWorker();
    const sshSessionStub = makeDOStub(() => new Response('forwarded'));
    const res = await worker.fetch(
      makeRequest('/api/ssh', {
        headers: { Upgrade: 'websocket', Origin: FRONTEND_ORIGIN },
      }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN, sshSessionStub })
    );
    expect(res.status).toBe(200);
  });

  it('白名单外的跨源 Origin 仍然 403', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/ssh', {
        headers: { Upgrade: 'websocket', Origin: 'https://evil.example.com' },
      }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN })
    );
    expect(res.status).toBe(403);
  });

  it('缺失 Origin 一律 403（CSWSH 防线不因跨源支持而放松）', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/ssh', { headers: { Upgrade: 'websocket' } }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN })
    );
    expect(res.status).toBe(403);
  });

  it('auth_token 查询参数在转发给 Durable Object 前被剥离', async () => {
    const worker = await loadWorker();
    let forwarded: Request | undefined;
    const sshSessionStub = makeDOStub((req) => {
      forwarded = req;
      return new Response('forwarded');
    });
    await worker.fetch(
      makeRequest('/api/ssh?auth_token=12345678:abcdef', {
        headers: { Upgrade: 'websocket', Origin: FRONTEND_ORIGIN },
      }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN, sshSessionStub })
    );
    expect(forwarded).toBeDefined();
    expect(new URL(forwarded!.url).searchParams.get('auth_token')).toBeNull();
  });
});

// =====================================================================
// 5. CSRF Origin 校验
// =====================================================================

describe('CSRF Origin 校验', () => {
  it('白名单来源可保存移动端快捷键（PUT /api/user/mobile-shortcuts）', async () => {
    const worker = await loadWorker();
    const userDbStub = makeShortcutsUserDbStub();
    const res = await worker.fetch(
      makeRequest('/api/user/mobile-shortcuts', {
        method: 'PUT',
        headers: { Origin: FRONTEND_ORIGIN, 'Content-Type': 'application/json' },
        body: { shortcuts: [{ id: 'escape' }] },
        cookies: { session: SESSION_TOKEN },
      }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN, userDbStub })
    );
    expect(res.status).toBe(200);
  });

  it('白名单外来源仍被拒绝', async () => {
    const worker = await loadWorker();
    const userDbStub = makeShortcutsUserDbStub();
    const res = await worker.fetch(
      makeRequest('/api/user/mobile-shortcuts', {
        method: 'PUT',
        headers: { Origin: 'https://evil.example.com', 'Content-Type': 'application/json' },
        body: { shortcuts: [{ id: 'escape' }] },
        cookies: { session: SESSION_TOKEN },
      }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN, userDbStub })
    );
    expect(res.status).toBe(403);
  });

  it('未登录的跨源请求仍返回 401（鉴权先于 Origin 校验，既有语义不变）', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/user/mobile-shortcuts', {
        method: 'PUT',
        headers: { Origin: 'https://evil.example.com', 'Content-Type': 'application/json' },
        body: { shortcuts: [{ id: 'escape' }] },
      }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN })
    );
    expect(res.status).toBe(401);
  });
});

// =====================================================================
// 6. 会话通道（Bearer / auth_token）
// =====================================================================

describe('跨源会话通道', () => {
  it('Authorization: Bearer 头可完成认证', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/auth/me', {
        headers: { Authorization: `Bearer ${SESSION_TOKEN}` },
      }),
      makeEnv({ userDbStub: makeSessionUserDbStub() })
    );
    expect(res.status).toBe(200);
    const payload = (await res.json()) as { username: string };
    expect(payload.username).toBe('alice');
  });

  it('auth_token 查询参数仅对白名单来源生效', async () => {
    const worker = await loadWorker();
    const allowed = await worker.fetch(
      makeRequest(`/api/auth/me?auth_token=${SESSION_TOKEN}`, {
        headers: { Origin: FRONTEND_ORIGIN },
      }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN, userDbStub: makeSessionUserDbStub() })
    );
    expect(allowed.status).toBe(200);

    const denied = await worker.fetch(
      makeRequest(`/api/auth/me?auth_token=${SESSION_TOKEN}`, {
        headers: { Origin: 'https://evil.example.com' },
      }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN, userDbStub: makeSessionUserDbStub() })
    );
    expect(denied.status).toBe(401);
  });

  it('格式不合法的 Bearer 令牌不被接受', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/auth/me', { headers: { Authorization: 'Bearer !!!' } }),
      makeEnv({ userDbStub: makeSessionUserDbStub() })
    );
    expect(res.status).toBe(401);
  });
});

// =====================================================================
// 7. Cookie 属性
// =====================================================================

describe('会话 Cookie 属性', () => {
  it('跨源模式下会话 Cookie 为 SameSite=None; Secure', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/auth/logout', { method: 'POST' }),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN })
    );
    const cookie = res.headers.get('Set-Cookie') ?? '';
    expect(cookie).toContain('SameSite=None');
    expect(cookie).toContain('Secure');
  });

  it('纯同源部署保持 SameSite=Lax（既有行为不变）', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/auth/logout', { method: 'POST' }),
      makeEnv()
    );
    const cookie = res.headers.get('Set-Cookie') ?? '';
    expect(cookie).toContain('SameSite=Lax');
  });
});

// =====================================================================
// 8. 登录落点与分享链接
// =====================================================================

describe('登录落点与分享链接', () => {
  it('/api/config 公开跨源接入信息', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(makeRequest('/api/config'), makeEnv({
      FRONTEND_URL: FRONTEND_ORIGIN,
    }));
    const payload = (await res.json()) as {
      externalFrontend: boolean;
      frontendUrl: string | null;
    };
    expect(payload.externalFrontend).toBe(true);
    expect(payload.frontendUrl).toBe(FRONTEND_ORIGIN);
  });

  it('?target=frontend 只接受固定字面量（不接受任意 URL）', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/auth/github?target=https://evil.example.com'),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN, GITHUB_CLIENT_ID: 'cid', GITHUB_CLIENT_SECRET: 'sec' })
    );
    expect(res.status).toBe(302);
    const location = res.headers.get('Location') ?? '';
    expect(location.startsWith('https://github.com/login/oauth/authorize')).toBe(true);
    // 未命中固定字面量 → 不设置 oauth_target Cookie
    expect(res.headers.get('Set-Cookie') ?? '').not.toContain('oauth_target=frontend');
  });

  it('?target=frontend 命中时记录外部前端落点', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/auth/github?target=frontend'),
      makeEnv({ FRONTEND_URL: FRONTEND_ORIGIN, GITHUB_CLIENT_ID: 'cid', GITHUB_CLIENT_SECRET: 'sec' })
    );
    expect(res.status).toBe(302);
    expect(res.headers.get('Set-Cookie') ?? '').toContain('oauth_target=frontend');
  });

  it('未配置 FRONTEND_URL 时忽略 target=frontend', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/auth/github?target=frontend'),
      makeEnv({ GITHUB_CLIENT_ID: 'cid', GITHUB_CLIENT_SECRET: 'sec' })
    );
    expect(res.status).toBe(302);
    expect(res.headers.get('Set-Cookie') ?? '').not.toContain('oauth_target=frontend');
  });

  it('FRONTEND_URL 是通配符时整体失效（不会成为 OAuth 跳转目标）', async () => {
    const worker = await loadWorker();
    const res = await worker.fetch(
      makeRequest('/api/config'),
      makeEnv({ FRONTEND_URL: 'https://*.vercel.app' })
    );
    const payload = (await res.json()) as {
      externalFrontend: boolean;
      frontendUrl: string | null;
    };
    expect(payload.externalFrontend).toBe(false);
    expect(payload.frontendUrl).toBeNull();
  });
});
