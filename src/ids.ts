import { z } from "zod";

export const ID_PREFIXES = ["sec", "vlt", "usr", "agt", "fld", "aud", "lease"] as const;

export type IdPrefix = (typeof ID_PREFIXES)[number];

export type PrefixedId<P extends IdPrefix = IdPrefix> = `${P}_${string}`;

const CROCKFORD_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";
const CROCKFORD_DECODE_MAP = new Map<string, number>();
for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
  const ch = CROCKFORD_ALPHABET[i]!;
  CROCKFORD_DECODE_MAP.set(ch, i);
  CROCKFORD_DECODE_MAP.set(ch.toUpperCase(), i);
}

const ULID_BODY_REGEX = /^[0-7][0-9a-hjkmnp-tv-z]{25}$/i;

const OPAQUE_HANDLE_EXACT_REGEX = /^\{\{vault:((?:sec|lease)_[0-7][0-9a-hjkmnp-tv-z]{25})\}\}$/i;

const OPAQUE_HANDLE_GLOBAL_REGEX = /\{\{vault:((?:sec|lease)_[0-7][0-9a-hjkmnp-tv-z]{25})\}\}/gi;

/**
 * Encodes a 48-bit millisecond timestamp into 10 Crockford Base32 characters.
 */
function encodeTime(timestampMs: number): string {
  if (!Number.isInteger(timestampMs) || timestampMs < 0 || timestampMs > 0xffffffffffff) {
    throw new RangeError(`Timestamp out of 48-bit ULID range: ${timestampMs}`);
  }
  let value = timestampMs;
  const chars = new Array<string>(10);
  for (let i = 9; i >= 0; i--) {
    const mod = value % 32;
    chars[i] = CROCKFORD_ALPHABET[mod]!;
    value = Math.floor(value / 32);
  }
  return chars.join("");
}

/**
 * Encodes 80 bits (10 bytes) of cryptographic randomness into 16 Crockford Base32 characters.
 */
function encodeRandom80Bits(randomBytes: Uint8Array): string {
  if (randomBytes.byteLength !== 10) {
    throw new RangeError(`Expected 10 random bytes, received ${randomBytes.byteLength}`);
  }
  let acc = 0n;
  for (const byte of randomBytes) {
    acc = (acc << 8n) | BigInt(byte);
  }
  const chars = new Array<string>(16);
  for (let i = 15; i >= 0; i--) {
    const idx = Number(acc & 31n);
    chars[i] = CROCKFORD_ALPHABET[idx]!;
    acc >>= 5n;
  }
  return chars.join("");
}

/**
 * Generates a deterministic-format, millisecond-sortable, lowercase Crockford Base32
 * ULID with the given entity prefix (`sec_`, `vlt_`, `usr_`, `agt_`, `fld_`, `aud_`, `lease_`).
 */
export function generateId<P extends IdPrefix>(
  prefix: P,
  timestampMs: number = Date.now(),
  randomBytes?: Uint8Array,
): PrefixedId<P> {
  if (!ID_PREFIXES.includes(prefix)) {
    throw new Error(`Invalid entity ID prefix: ${prefix}`);
  }
  const entropy = randomBytes ?? globalThis.crypto.getRandomValues(new Uint8Array(10));
  const timePart = encodeTime(timestampMs);
  const randomPart = encodeRandom80Bits(entropy);
  return `${prefix}_${timePart}${randomPart}`;
}

/**
 * Validates whether a string is a canonical prefixed ULID.
 * Optionally enforces a specific prefix.
 */
export function isValidId<P extends IdPrefix = IdPrefix>(
  value: unknown,
  expectedPrefix?: P,
): value is PrefixedId<P> {
  if (typeof value !== "string") {
    return false;
  }
  const separatorIdx = value.indexOf("_");
  if (separatorIdx <= 0) {
    return false;
  }
  const prefix = value.slice(0, separatorIdx);
  const body = value.slice(separatorIdx + 1);

  if (expectedPrefix !== undefined) {
    if (prefix !== expectedPrefix) {
      return false;
    }
  } else if (!ID_PREFIXES.includes(prefix as IdPrefix)) {
    return false;
  }

  return ULID_BODY_REGEX.test(body);
}

/**
 * Asserts that `value` is a valid prefixed ULID, throwing an Error otherwise.
 */
export function assertValidId<P extends IdPrefix = IdPrefix>(
  value: string,
  expectedPrefix?: P,
): PrefixedId<P> {
  if (!isValidId(value, expectedPrefix)) {
    const expectedLabel = expectedPrefix ? `${expectedPrefix}_<ulid>` : "<prefix>_<ulid>";
    throw new Error(`Invalid identifier "${value}" (expected ${expectedLabel})`);
  }
  return value;
}

/**
 * Extracts the 48-bit Unix timestamp (in milliseconds) embedded in a prefixed ULID.
 */
export function extractTimestampMs(id: string): number {
  assertValidId(id);
  const separatorIdx = id.indexOf("_");
  const timeChars = id.slice(separatorIdx + 1, separatorIdx + 11);
  let timestampMs = 0;
  for (let i = 0; i < 10; i++) {
    const val = CROCKFORD_DECODE_MAP.get(timeChars[i]!);
    if (val === undefined) {
      throw new Error(`Invalid Crockford character in ULID timestamp: ${timeChars[i]}`);
    }
    timestampMs = timestampMs * 32 + val;
  }
  return timestampMs;
}

/**
 * Creates a Zod schema for a specific prefixed ULID type.
 */
export function prefixedIdSchema<P extends IdPrefix>(prefix: P) {
  return z.string().refine((val): val is PrefixedId<P> => isValidId(val, prefix), {
    message: `Expected valid ${prefix}_<ulid> identifier`,
  });
}

export const anyVaultIdSchema = z.string().refine((val): val is PrefixedId => isValidId(val), {
  message: "Expected valid prefixed ULID identifier",
});

export type SecretOrLeaseId = PrefixedId<"sec"> | PrefixedId<"lease">;

/**
 * Formats a `sec_<ulid>` or `lease_<ulid>` identifier into an opaque surrogate template handle
 * (`{{vault:sec_<ulid>}}` or `{{vault:lease_<ulid>}}`) safe for LLM context windows.
 */
export function formatOpaqueHandle(id: string): string {
  const normalizedId = id.toLowerCase();
  if (!isValidId(normalizedId, "sec") && !isValidId(normalizedId, "lease")) {
    throw new Error(
      `Opaque handles can only wrap sec_<ulid> or lease_<ulid> identifiers (received "${id}")`,
    );
  }
  return `{{vault:${normalizedId}}}`;
}

export interface ParsedOpaqueHandle {
  kind: "sec" | "lease";
  id: SecretOrLeaseId;
  handle: string;
}

/**
 * Parses either an opaque template handle (`{{vault:sec_<ulid>}}` / `{{vault:lease_<ulid>}}`)
 * or a direct `sec_<ulid>` / `lease_<ulid>` identifier. Returns `null` if invalid.
 */
export function parseOpaqueHandle(input: string): ParsedOpaqueHandle | null {
  const trimmed = input.trim();
  const match = OPAQUE_HANDLE_EXACT_REGEX.exec(trimmed);
  const candidateId = match ? match[1]! : trimmed;

  if (isValidId(candidateId, "sec")) {
    const normalized = candidateId.toLowerCase() as SecretOrLeaseId;
    return {
      kind: "sec",
      id: normalized,
      handle: formatOpaqueHandle(normalized),
    };
  }
  if (isValidId(candidateId, "lease")) {
    const normalized = candidateId.toLowerCase() as SecretOrLeaseId;
    return {
      kind: "lease",
      id: normalized,
      handle: formatOpaqueHandle(normalized),
    };
  }
  return null;
}

/**
 * Resolves all `{{vault:sec_<ulid>}}` and `{{vault:lease_<ulid>}}` template occurrences
 * within `input` (or a bare `sec_<ulid>` / `lease_<ulid>` string) using `resolver`.
 */
export function resolveTemplateHandles(
  input: string,
  resolver: (id: SecretOrLeaseId, kind: "sec" | "lease") => string | Uint8Array,
): { resolved: string; referencedIds: SecretOrLeaseId[] } {
  const referencedIds: SecretOrLeaseId[] = [];
  const decoder = new TextDecoder();

  // Check if the entire string is a bare sec_<ulid> or lease_<ulid>
  if (isValidId(input, "sec") || isValidId(input, "lease")) {
    const kind = input.startsWith("sec_") ? "sec" : "lease";
    referencedIds.push(input);
    const raw = resolver(input, kind);
    const resolved = typeof raw === "string" ? raw : decoder.decode(raw);
    return { resolved, referencedIds };
  }

  const resolved = input.replace(OPAQUE_HANDLE_GLOBAL_REGEX, (_fullMatch, rawId: string) => {
    const parsed = parseOpaqueHandle(rawId);
    if (!parsed) {
      throw new Error(`Invalid opaque vault handle reference: ${rawId}`);
    }
    if (!referencedIds.includes(parsed.id)) {
      referencedIds.push(parsed.id);
    }
    const secretVal = resolver(parsed.id, parsed.kind);
    return typeof secretVal === "string" ? secretVal : decoder.decode(secretVal);
  });

  return { resolved, referencedIds };
}
