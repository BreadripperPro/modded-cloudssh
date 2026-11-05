/**
 * 后端 API 基址、运行时配置与会话令牌通道。
 *
 * 两种部署形态：
 * - 同源（CloudSSH Worker 自带前端）：`apiBaseUrl` 为空，所有请求走相对路径 `/api/*`，
 *   行为与改造前完全一致（Cookie 会话、无 Authorization 头）。
 * - 跨源（独立部署的前端，例如 Vercel）：`public/config.js` 注入 `apiBaseUrl`，
 *   请求带上 `credentials: 'include'` 走 CORS；浏览器屏蔽第三方 Cookie 时，
 *   退回到 `Authorization: Bearer <session-token>` 通道。
 *
 * 安全约束：
 * - `apiBaseUrl` 只能来自随包发布的配置文件（或构建期环境变量），
 *   **绝不**从 URL 查询参数/哈希读取。否则攻击者可用构造链接把用户的凭据
 *   引到他控制的服务器（凭据外带）。
 * - 会话令牌只保存在 localStorage，并仅在跨源部署时启用；同源部署沿用 HttpOnly Cookie。
 */

/** localStorage 中会话令牌的键名 */
const SESSION_TOKEN_STORAGE_KEY = 'cloudssh_session_token';

/** WebSocket 握手中的会话令牌参数名（与 Worker 端保持一致） */
const WS_AUTH_TOKEN_PARAM = 'auth_token';

export interface CloudSSHRuntimeConfig {
  /** Worker 后端 origin（不含尾斜杠）；留空表示同源部署 */
  apiBaseUrl?: string;
}

declare global {
  interface Window {
    __CLOUDSSH_CONFIG__?: CloudSSHRuntimeConfig;
  }
}

let cachedBaseUrl: string | null = null;
let authRequiredState = false;

/** 读取由 public/config.js 注入的运行时配置 */
function readRuntimeConfig(): CloudSSHRuntimeConfig {
  if (typeof window === 'undefined') return {};
  const injected = window.__CLOUDSSH_CONFIG__;
  return injected && typeof injected === 'object' ? injected : {};
}

/** 读取构建期环境变量（VITE_CLOUDSSH_API_BASE_URL），失败时返回空串 */
function readBuildTimeBaseUrl(): string {
  try {
    const env = (import.meta as unknown as { env?: Record<string, string | undefined> }).env;
    return env?.VITE_CLOUDSSH_API_BASE_URL ?? '';
  } catch {
    return '';
  }
}

/**
 * 规范化 API 基址：只接受不带路径/查询串/凭据的 http(s) origin。
 * 非法输入一律降级为「同源」，避免把请求发到意外的目标。
 */
export function normalizeApiBaseUrl(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  if (!trimmed) return '';

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return '';
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return '';
  if (url.username || url.password) return '';
  if (url.pathname !== '/' && url.pathname !== '') return '';
  if (url.search || url.hash) return '';
  return url.origin;
}

/** 后端 API 基址（空串 = 同源） */
export function getApiBaseUrl(): string {
  if (cachedBaseUrl !== null) return cachedBaseUrl;
  const runtime = normalizeApiBaseUrl(readRuntimeConfig().apiBaseUrl);
  cachedBaseUrl = runtime || normalizeApiBaseUrl(readBuildTimeBaseUrl());
  return cachedBaseUrl;
}

/** 是否为跨源部署（后端与当前页面不同源） */
export function isCrossOriginDeployment(): boolean {
  const base = getApiBaseUrl();
  if (!base) return false;
  return base !== window.location.origin;
}

/** 拼接后端绝对地址 */
export function apiUrl(path: string): string {
  const base = getApiBaseUrl();
  if (!base) return path;
  return path.startsWith('/') ? `${base}${path}` : `${base}/${path}`;
}

/** localStorage 中的会话令牌（跨源部署的 Bearer 通道） */
export function getSessionToken(): string | null {
  if (!isCrossOriginDeployment()) return null;
  try {
    const token = localStorage.getItem(SESSION_TOKEN_STORAGE_KEY);
    return token && token.length > 0 ? token : null;
  } catch {
    // 隐私模式等存储不可用场景静默降级为纯 Cookie 会话
    return null;
  }
}

/** 写入/清除会话令牌 */
export function setSessionToken(token: string | null): void {
  if (!isCrossOriginDeployment()) {
    clearSessionToken();
    return;
  }
  try {
    if (token && token.length > 0) {
      localStorage.setItem(SESSION_TOKEN_STORAGE_KEY, token);
    } else {
      localStorage.removeItem(SESSION_TOKEN_STORAGE_KEY);
    }
  } catch {
    /* 存储不可用时忽略：Cookie 通道仍然有效 */
  }
}

/** 清除会话令牌（登出时调用） */
export function clearSessionToken(): void {
  try {
    localStorage.removeItem(SESSION_TOKEN_STORAGE_KEY);
  } catch {
    /* 忽略 */
  }
}

/**
 * 统一的 API 请求入口：自动拼接后端基址、带上 Cookie 与 Bearer 令牌。
 *
 * - 同源部署：完全沿用原生 `fetch` 语义（不注入额外 headers / credentials），
 *   与改造前行为逐字节一致。
 * - 跨源部署：`credentials: 'include'` 让浏览器携带后端域下的会话 Cookie；
 *   存在会话令牌时附加 `Authorization: Bearer`，用于浏览器屏蔽第三方 Cookie 的兜底。
 */
export function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  if (!isCrossOriginDeployment()) {
    return fetch(apiUrl(path), init);
  }

  const headers = new Headers(init.headers);
  const token = getSessionToken();
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  return fetch(apiUrl(path), {
    ...init,
    headers,
    credentials: init.credentials ?? 'include',
  });
}

/** 后端 WebSocket 基址（ws:// 或 wss://） */
export function getApiSocketOrigin(): string {
  const base = getApiBaseUrl() || window.location.origin;
  return base.replace(/^http/, 'ws');
}

/** 判断某个 ws/wss origin 是否是允许的后端来源 */
export function isAllowedApiSocketOrigin(origin: string): boolean {
  if (origin === window.location.origin.replace(/^http/, 'ws')) return true;
  const base = getApiBaseUrl();
  if (!base) return false;
  return origin === base.replace(/^http/, 'ws');
}

/** 构造指向后端的 WebSocket URL */
export function apiSocketUrl(
  path: string,
  params?: URLSearchParams | Record<string, string | undefined>
): string {
  const origin = getApiSocketOrigin();
  const url = new URL(`${origin}${path.startsWith('/') ? path : `/${path}`}`);
  if (params) {
    if (typeof URLSearchParams !== 'undefined' && params instanceof URLSearchParams) {
      params.forEach((value, key) => url.searchParams.set(key, value));
    } else {
      for (const [key, value] of Object.entries(params as Record<string, string | undefined>)) {
        if (value !== undefined) url.searchParams.set(key, value);
      }
    }
  }
  return url.toString();
}

/**
 * 记录后端是否要求登录（`REQUIRE_GITHUB_AUTH` 等）。
 *
 * 只有在「必须登录」的部署里，WebSocket 握手阶段才需要携带会话凭据；
 * 默认放行的部署不把会话令牌写进 URL（避免长期令牌进入边缘日志）。
 */
export function setAuthRequired(required: boolean): void {
  authRequiredState = required === true;
}

/** 当前部署是否要求登录 */
export function isAuthRequired(): boolean {
  return authRequiredState;
}

/**
 * 为 WebSocket URL 附加会话令牌。
 *
 * 浏览器无法为 WebSocket 握手自定义请求头，因此在「必须登录 + 跨源前端」
 * 的组合下用查询参数传递；Worker 入口校验后会在转发给 Durable Object 前剥离。
 */
export function withSessionTokenForSocket(wsUrl: string): string {
  if (!isAuthRequired()) return wsUrl;
  const token = getSessionToken();
  if (!token) return wsUrl;
  try {
    const url = new URL(wsUrl);
    if (url.searchParams.has(WS_AUTH_TOKEN_PARAM)) return url.toString();
    url.searchParams.set(WS_AUTH_TOKEN_PARAM, token);
    return url.toString();
  } catch {
    return wsUrl;
  }
}

/**
 * 消费 OAuth 回调通过 URL 片段带回的会话令牌，并立即从地址栏移除。
 *
 * 片段不会随请求发往服务端，因此不会进入访问日志；读取后用 replaceState
 * 抹掉，避免令牌残留在浏览器历史里。
 */
export function consumeSessionTokenFromLocation(): string | null {
  const hash = window.location.hash;
  if (!hash.startsWith('#token=')) return null;

  const params = new URLSearchParams(hash.slice(1));
  const token = params.get('token');
  history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
  if (!token) return null;

  setSessionToken(token);
  return token;
}

/** 后端公开配置（/api/config） */
export interface ApiConfig {
  turnstileEnabled: boolean;
  sitekey: string;
  githubAuthEnabled: boolean;
  githubAuthRequired: boolean;
  sshSharingEnabled?: boolean;
  authMode?: 'password' | 'cf_access' | 'github' | 'anonymous';
  passwordAuth?: { kdf: string; iterations: number; salt: string } | null;
  passwordHashInvalid?: boolean;
  externalFrontend?: boolean;
  frontendUrl?: string | null;
}

/**
 * 读取后端公开配置，并同步「是否要求登录」状态（供 WebSocket 鉴权通道使用）。
 *
 * 结果在页面生命周期内缓存：公开配置在运行期不会变化，避免重复请求。
 */
let configPromise: Promise<ApiConfig> | null = null;

export async function fetchApiConfig(): Promise<ApiConfig> {
  if (!configPromise) {
    configPromise = apiFetch('/api/config')
      .then((response) => response.json() as Promise<ApiConfig>)
      .then((config) => {
        setAuthRequired(config.githubAuthRequired === true);
        return config;
      })
      .catch((error) => {
        // 失败不缓存，允许后续重试
        configPromise = null;
        throw error;
      });
  }
  return configPromise;
}
