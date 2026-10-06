/**
 * Masks literal secrets embedded in function bodies, column defaults and the like.
 * Applied when writing rules.json, when rendering HTML and to every log line.
 */

export const REDACTED = "[REDACTED]";

const SECRET_PATTERNS: RegExp[] = [
  // Connection URIs: masked as a whole, credentials or not, because the host name is environment info too
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s'"`<>)]+/gi,
  // user:password@ in any URI scheme
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s/'"`<>:@]+:[^\s/'"`<>@]+@[^\s'"`<>]+/gi,
  // JWTs (including Supabase anon / service_role keys)
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+/g,
  // sk- style API keys (OpenAI, Anthropic, Stripe, ...)
  /\bsk-[A-Za-z0-9_-]{16,}/g,
  // Supabase's newer API key format
  /\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{10,}/g,
  // AWS access key IDs
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  // Long hex strings (32+ digits). UUIDs contain hyphens and are not matched
  /\b[0-9a-fA-F]{32,}\b/g
];

export function redactString(value: string): string {
  let out = value;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, REDACTED);
  }
  return out;
}

/** Deep-copies a value, redacting every string in it. */
export function redactDeep<T>(value: T): T {
  if (typeof value === "string") return redactString(value) as T;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v)) as T;
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v);
    return out as T;
  }
  return value;
}
