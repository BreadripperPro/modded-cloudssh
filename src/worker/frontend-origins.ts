import type { Env } from '../types';

/**
 * 外部前端（独立部署的 SPA，例如 Vercel）与 CloudSSH Worker 之间的跨源接入策略。
 *
 * 设计要点（安全优先）：
 * - 只接受 **精确 origin** 白名单；不支持通配符（如 `*.vercel.app`）。
 *   通配符会让任意第三方站点（例如别人的 Vercel 预览部署）都能带着用户
 *   的会话调用本 Worker 的 API，等同于把账号交出去，因此一律拒绝。
 * - 白名单条目必须是不带路径/查询串/片段的纯 origin，且生产环境必须是 HTTPS。
 *   只有回环地址（localhost / 127.0.0.1 / ::1）允许明文 HTTP，便于本地联调。
 * - CORS 响应永远回显「白名单内的具体 origin」并附带
 *   `Access-Control-Allow-Credentials: true`，绝不使用 `*`（与凭据模式互斥）。
 * - 跨源模式下会话 Cookie 改为 `SameSite=None; Secure`；若浏览器屏蔽第三方
 *   Cookie，前端可退回到 `Authorization: Bearer <session-token>` 通道。
 */

/** 允许跨源 API 访问的请求方法 */
const CORS_ALLOWED_METHODS = 'GET, POST, PUT, DELETE, OPTIONS';

/** 允许跨源 API 访问的请求头（Authorization 用于 Bearer 会话令牌通道） */
const CORS_ALLOWED_HEADERS = 'Content-Type, Authorization';

/** 预检结果缓存时长（秒） */
const CORS_MAX_AGE_SECONDS = '86400';

/** 跨源模式下前端会话令牌在 WebSocket 握手中的查询参数名 */
export const WS_AUTH_TOKEN_PARAM = 'auth_token';

export interface FrontendOriginPolicy {
  /** 允许发起跨源请求的外部前端 origin 集合（精确匹配） */
  allowedOrigins: Set<string>;
  /** 外部前端主地址：OAuth 登录后跳转与分享链接使用；未配置时为 null */
  frontendUrl: string | null;
  /** 是否启用跨源模式（白名单非空即启用） */
  enabled: boolean;
}

/** 是否为允许明文 HTTP 的回环主机名 */
function isLoopbackHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[/, '').replace(/\]$/, '');
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.localhost');
}

/** 单个 DNS 标签：字母/数字开头结尾，中间可含连字符（不含下划线与通配符） */
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * 校验主机名必须是「精确可寻址」的主机名。
 *
 * 关键点：`new URL('https://*.vercel.app')` **不会抛错**，WHATWG URL 解析器
 * 会把 `*.vercel.app` 当作普通主机名。若不做这一步校验，通配符会被写进
 * 白名单：既让运维误以为「已放行整个 vercel.app」，又可能把
 * `FRONTEND_URL` 变成不可解析的 OAuth 跳转目标（令牌随之泄漏到未知站点）。
 * 因此这里显式拒绝通配符与非法 DNS 标签（空标签、下划线、超长标签等）。
 */
function isValidFrontendHostname(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (!host) return false;

  // 通配符主机名一律拒绝——白名单只支持精确 origin
  if (host.includes('*')) return false;

  // IPv6 字面量：WHATWG URL 的 hostname 带方括号
  if (host.startsWith('[')) {
    return host.endsWith(']') && /^[0-9a-f:.]+$/.test(host.slice(1, -1));
  }

  // IPv4 字面量
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return host.split('.').every((part) => part.length > 0 && Number(part) <= 255);
  }

  const labels = host.split('.');
  if (labels.some((label) => label.length === 0 || label.length > 63)) return false;
  return labels.every((label) => DNS_LABEL_PATTERN.test(label));
}

/**
 * 规范化并校验一个外部前端 origin。
 *
 * 返回值形如 `https://app.example.com`（无尾斜杠）；非法输入返回 null。
 * 校验失败的原因包括：非 http(s)、含凭据、通配符/非法主机名、含路径/查询串/片段、
 * 非回环的明文 HTTP。
 */
export function normalizeFrontendOrigin(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed === '*') return null;

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password) return null;
  // 主机名必须是精确可寻址的主机名（拒绝 *.vercel.app 这类通配符与非法标签）
  if (!isValidFrontendHostname(url.hostname)) return null;
  // 只接受纯 origin：不允许携带路径、查询串或片段
  if (url.pathname !== '/' && url.pathname !== '') return null;
  if (url.search || url.hash) return null;
  // 生产环境强制 HTTPS；明文 HTTP 仅放行本地回环地址
  if (url.protocol === 'http:' && !isLoopbackHostname(url.hostname)) return null;

  return url.origin.toLowerCase();
}

/**
 * 记录已被丢弃的非法白名单条目（每个条目只告警一次，避免每请求刷日志）。
 *
 * 静默忽略会让「前端连不上」这类问题极难排查，因此这里明确提示运维：
 * 该条目既不是通配符放行，也不会退化为同源放行。
 */
const warnedInvalidOrigins = new Set<string>();

function warnInvalidOrigin(source: 'FRONTEND_URL' | 'FRONTEND_ORIGINS', raw: string): void {
  const key = `${source}:${raw}`;
  if (warnedInvalidOrigins.has(key)) return;
  warnedInvalidOrigins.add(key);
  console.warn(
    `[FrontendOrigins] ${source} 忽略了非法 origin（必须是精确 origin，禁止通配符）: ${raw}`
  );
}

/**
 * 解析当前部署的跨源接入策略。
 *
 * - `FRONTEND_URL`：外部前端主地址（自动加入白名单），用于登录后跳转与分享链接。
 * - `FRONTEND_ORIGINS`：额外的外部前端 origin 白名单（逗号分隔，精确匹配）。
 *
 * 两者都为空时保持「纯同源」行为：不返回任何 CORS 头，Origin 校验依旧严格。
 */
export function getFrontendOriginPolicy(env: Env): FrontendOriginPolicy {
  const allowedOrigins = new Set<string>();
  let frontendUrl: string | null = null;

  const configuredUrl = normalizeFrontendOrigin(env.FRONTEND_URL);
  if (configuredUrl) {
    frontendUrl = configuredUrl;
    allowedOrigins.add(configuredUrl);
  } else if (typeof env.FRONTEND_URL === 'string' && env.FRONTEND_URL.trim() !== '') {
    warnInvalidOrigin('FRONTEND_URL', env.FRONTEND_URL);
  }

  const rawOrigins = env.FRONTEND_ORIGINS;
  if (typeof rawOrigins === 'string' && rawOrigins.trim() !== '') {
    for (const entry of rawOrigins.split(',')) {
      const normalized = normalizeFrontendOrigin(entry);
      if (normalized) {
        allowedOrigins.add(normalized);
      } else if (entry.trim() !== '') {
        warnInvalidOrigin('FRONTEND_ORIGINS', entry);
      }
    }
  }

  return { allowedOrigins, frontendUrl, enabled: allowedOrigins.size > 0 };
}

/** 判断某个 Origin 是否在外部前端白名单内 */
export function isAllowedFrontendOrigin(
  env: Env,
  origin: string | null | undefined
): boolean {
  if (!origin) return false;
  const normalized = normalizeFrontendOrigin(origin);
  if (!normalized) return false;
  return getFrontendOriginPolicy(env).allowedOrigins.has(normalized);
}

/** 同源比较（大小写不敏感；浏览器发送的 Origin 已是规范化形式） */
function isSameOrigin(a: string, b: string): boolean {
  return a === b || a.toLowerCase() === b.toLowerCase();
}

/**
 * CSRF 防护用的「可信来源」判定：同源恒可信；跨源时必须命中外部前端白名单。
 *
 * 注意：调用方仍需自行决定「Origin 缺失」是否放行——保持既有语义不变。
 */
export function isTrustedRequestOrigin(
  env: Env,
  origin: string | null | undefined,
  requestOrigin: string
): boolean {
  if (!origin) return false;
  if (isSameOrigin(origin, requestOrigin)) return true;
  return isAllowedFrontendOrigin(env, origin);
}

/**
 * 跨源模式下会话 Cookie 的 SameSite 属性。
 *
 * - 同源部署：保持 `Lax`（与既有行为完全一致）。
 * - 跨源部署：必须为 `None`，否则浏览器不会在跨站 fetch 中携带会话 Cookie。
 */
export function sessionCookieSameSite(env: Env): 'None' | 'Lax' {
  return getFrontendOriginPolicy(env).enabled ? 'None' : 'Lax';
}

/** Turnstile 校验 Cookie 的 SameSite 属性（跨源模式需要 None 才能随 WS 握手发送） */
export function verifiedCookieSameSite(env: Env): 'None' | 'Strict' {
  return getFrontendOriginPolicy(env).enabled ? 'None' : 'Strict';
}

/**
 * 登录后跳转 / 分享链接使用的前端地址。
 * 未配置外部前端时回退到 Worker 自身 origin（既有行为）。
 */
export function getFrontendRedirectUrl(env: Env, fallbackOrigin: string): string {
  const policy = getFrontendOriginPolicy(env);
  return policy.frontendUrl ?? fallbackOrigin;
}

/**
 * 构造 CORS 预检（OPTIONS）响应。
 *
 * 返回 null 表示「该 Origin 不在白名单内」——调用方应直接拒绝而不是放行。
 */
export function createCorsPreflightResponse(request: Request, env: Env): Response | null {
  const origin = request.headers.get('Origin');
  if (!origin) return null;

  const normalized = normalizeFrontendOrigin(origin);
  if (!normalized) return null;
  if (!getFrontendOriginPolicy(env).allowedOrigins.has(normalized)) return null;

  const headers = new Headers();
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Access-Control-Allow-Credentials', 'true');
  headers.set('Access-Control-Allow-Methods', CORS_ALLOWED_METHODS);
  headers.set('Access-Control-Allow-Headers', CORS_ALLOWED_HEADERS);
  headers.set('Access-Control-Max-Age', CORS_MAX_AGE_SECONDS);
  headers.set('Vary', 'Origin');

  return new Response(null, { status: 204, headers });
}

/** 给响应补上 CORS 头；来源不在白名单内时原样返回 */
export function applyCorsHeaders(response: Response, request: Request, env: Env): Response {
  const origin = request.headers.get('Origin');
  if (!origin) return response;

  const normalized = normalizeFrontendOrigin(origin);
  if (!normalized) return response;
  if (!getFrontendOriginPolicy(env).allowedOrigins.has(normalized)) return response;

  // WebSocket 升级响应（101）带 webSocket 属性，不能重建 Response
  if (response.status === 101 || (response as unknown as { webSocket?: unknown }).webSocket) {
    return response;
  }

  const apply = (headers: Headers): void => {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Access-Control-Allow-Credentials', 'true');
    headers.append('Vary', 'Origin');
  };

  try {
    // 绝大多数响应（Response.json / new Response / DO stub）头可变，直接就地写入
    apply(response.headers);
    return response;
  } catch {
    // 不可变头（例如来自 caches.default.match() 的缓存响应）→ 复制后重建
  }

  const headers = new Headers(response.headers);
  apply(headers);
  const body =
    response.status === 204 || response.status === 205 || response.status === 304
      ? null
      : response.body;
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
