export interface ActiveSecretDescriptor {
  id: string;
  valueBytes: Uint8Array;
}

interface ReplacementRule {
  needle: string;
  replacement: string;
}

const textDecoder = new TextDecoder();

function stripBase64Padding(value: string): string {
  return value.replace(/=+$/, "");
}

/**
 * Builds candidate encoded representations for a secret value:
 * - Raw UTF-8 string
 * - Trimmed UTF-8 string (if trailing newline was present)
 * - Standard Base64 (with and without `=` padding)
 * - URL-safe Base64 (`base64url`, with and without `=` padding)
 * - URL-encoded (`encodeURIComponent`)
 */
function buildSecretVariants(valueBytes: Uint8Array): string[] {
  if (valueBytes.byteLength === 0) {
    return [];
  }

  const variants = new Set<string>();
  const utf8 = textDecoder.decode(valueBytes);
  if (utf8.length > 0) {
    variants.add(utf8);
    const trimmed = utf8.trim();
    if (trimmed.length >= 4) {
      variants.add(trimmed);
    }
    const urlEncoded = encodeURIComponent(utf8);
    if (urlEncoded.length > 0) {
      variants.add(urlEncoded);
      const lowerUrl = urlEncoded.replace(/%[0-9A-Fa-f]{2}/g, (m) => m.toLowerCase());
      if (lowerUrl !== urlEncoded) {
        variants.add(lowerUrl);
      }
      const upperUrl = urlEncoded.replace(/%[0-9A-Fa-f]{2}/g, (m) => m.toUpperCase());
      if (upperUrl !== urlEncoded) {
        variants.add(upperUrl);
      }
    }
  }

  const buf = Buffer.from(valueBytes);
  const stdBase64 = buf.toString("base64");
  if (stdBase64.length >= 4) {
    variants.add(stdBase64);
    const unpaddedStd = stripBase64Padding(stdBase64);
    if (unpaddedStd.length >= 4) {
      variants.add(unpaddedStd);
    }
  }

  const urlBase64 = buf.toString("base64url");
  if (urlBase64.length >= 4) {
    variants.add(urlBase64);
  }

  return Array.from(variants);
}

/**
 * Replaces raw UTF-8, Base64-encoded, and URL-encoded occurrences of any active secret
 * in `text` (`stdout`, `stderr`, or HTTP payloads) with `[REDACTED:${id}]`.
 */
export function scrubSecretsFromText(
  text: string,
  activeSecrets: ReadonlyArray<ActiveSecretDescriptor>,
): string {
  if (!text || activeSecrets.length === 0) {
    return text;
  }

  const rules: ReplacementRule[] = [];
  for (const secret of activeSecrets) {
    if (secret.valueBytes.byteLength === 0) {
      continue;
    }
    const replacement = `[REDACTED:${secret.id}]`;
    for (const needle of buildSecretVariants(secret.valueBytes)) {
      rules.push({ needle, replacement });
    }
  }

  if (rules.length === 0) {
    return text;
  }

  // Sort longest needle first so partial encodings do not shadow full secret matches
  rules.sort((a, b) => b.needle.length - a.needle.length);

  let scrubbed = text;
  for (const rule of rules) {
    if (scrubbed.includes(rule.needle)) {
      scrubbed = scrubbed.split(rule.needle).join(rule.replacement);
    }
  }
  return scrubbed;
}

const SENSITIVE_HEADER_NAMES = new Set([
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "x-auth-token",
  "cookie",
  "set-cookie",
]);

/**
 * Scrubs active secrets from HTTP headers and redacts echoed credential headers.
 */
export function scrubHeaders(
  headers: Readonly<Record<string, string>>,
  activeSecrets: ReadonlyArray<ActiveSecretDescriptor>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const scrubbedValue = scrubSecretsFromText(value, activeSecrets);
    if (SENSITIVE_HEADER_NAMES.has(key.toLowerCase()) && scrubbedValue === value && value !== "") {
      // Even if a server transformed or echoed an auth header in a non-standard format,
      // ensure raw sensitive headers are never leaked back into LLM context.
      out[key] = "[REDACTED:HEADER]";
    } else {
      out[key] = scrubbedValue;
    }
  }
  return out;
}
