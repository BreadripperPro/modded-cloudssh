// Shared browser/Worker policy. These are user-selected limits, not a guessed model registry.
export interface AIModelBudgets {
  context_window: number;
  max_output_tokens: number;
}
export const DEFAULT_AI_MODEL_BUDGETS: AIModelBudgets = {
  context_window: 64_000,
  max_output_tokens: 8192,
};

export function resolveAIModelBudgets(
  value: { context_window?: unknown; max_output_tokens?: unknown },
  defaults: AIModelBudgets = DEFAULT_AI_MODEL_BUDGETS
): AIModelBudgets {
  const context = value.context_window ?? defaults.context_window;
  const output = value.max_output_tokens ?? defaults.max_output_tokens;
  if (typeof context !== 'number' || !Number.isInteger(context) || context < 8192 || context > 1_000_000 ||
    typeof output !== 'number' || !Number.isInteger(output) || output < 256 || output > 128_000 ||
    output >= context) {
    throw new Error('Invalid AI token budgets');
  }
  return { context_window: context, max_output_tokens: output };
}
