import {
  normalizeResponseDiagnostics, RESPONSE_PARAMETERS, type ResponseDiagnostics,
} from '../../agent-response-diagnostics';

type Parameter = NonNullable<ResponseDiagnostics['parameter']>;

function parameter(value: unknown): Parameter | undefined {
  if (typeof value !== 'string') return undefined;
  if (/^tools(?:\[\d+\]|\.\d+)?\.strict$/.test(value)) return 'tools.strict';
  if (value === 'text.format.type' || value === 'response_format') return 'text.format';
  return RESPONSE_PARAMETERS.find(item => item === value);
}

/** Inspect a bounded error in memory. Never retain or display its free-form message. */
export function providerError(value: unknown): {
  diagnostics: ResponseDiagnostics;
  unsupported?: Parameter;
} {
  if (!value || typeof value !== 'object') return { diagnostics: {} };
  const root = value as Record<string, unknown>;
  const raw = root.error && typeof root.error === 'object'
    ? root.error as Record<string, unknown> : root;
  const message = typeof raw.message === 'string' ? raw.message.slice(0, 4096) : '';
  const terminalCode = ['context_length_exceeded', 'max_tokens_exceeded', 'model_not_found',
    'unsupported_model', 'invalid_api_key', 'authentication_error', 'permission_denied',
    'rate_limit_exceeded', 'insufficient_quota', 'content_policy_violation'].includes(String(raw.code));
  const explicitlyUnsupported = !terminalCode && (
    /^unsupported_(parameter|value|feature)$/.test(String(raw.code)) ||
    /\b(unsupported|not supported|does not support|not support|unrecognized parameter|unknown parameter)\b/i.test(message));
  let param = parameter(raw.param);
  if (explicitlyUnsupported) {
    if (param === 'tools' && /\bstrict\b/i.test(message)) param = 'tools.strict';
    if (!param) {
      // Only known parameter names, never arbitrary quoted tokens or provider text.
      param = [...RESPONSE_PARAMETERS].sort((a, b) => b.length - a.length).find(name =>
        new RegExp(`(?:^|[^a-zA-Z0-9_])${name.replaceAll('.', '\\.')}\\b`, 'i').test(message));
    }
  }
  const diagnostics = normalizeResponseDiagnostics({
    parameter: param,
    providerCode: typeof raw.code === 'string' ? raw.code : raw.type,
  });
  return { diagnostics, ...(explicitlyUnsupported && param ? { unsupported: param } : {}) };
}

export function retryAfterMs(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = /^\d+(?:\.\d+)?$/.test(value.trim()) ? Number(value) : NaN;
  const ms = Number.isFinite(seconds) ? seconds * 1000 : Date.parse(value) - Date.now();
  return Number.isFinite(ms) ? Math.max(0, Math.min(ms, 30_000)) : undefined;
}
