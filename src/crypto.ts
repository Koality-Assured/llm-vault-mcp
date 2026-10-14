const textEncoder = new TextEncoder();

export interface CanonicalAadParams {
  tenantId: string;
  vaultId: string;
  secretId: string;
  version: number;
  keyVersion: number;
}

export interface EncryptedEnvelope {
  ciphertext: Uint8Array;
  iv: Uint8Array;
}

const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BITS = 128;
const AES_KEY_BYTES = 32;

function assertNonEmptyNoColon(label: string, value: string): void {
  if (!value || value.trim().length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  if (value.includes(":")) {
    throw new Error(`${label} must not contain ':' delimiter`);
  }
}

function assertPositiveInt(label: string, value: number): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer >= 1 (received ${value})`);
  }
}

/**
 * Formats the canonical Additional Authenticated Data (AAD) string:
 * `${tenantId}:${vaultId}:${secretId}:${version}:${keyVersion}`
 */
export function formatCanonicalAadString(params: CanonicalAadParams): string {
  assertNonEmptyNoColon("tenantId", params.tenantId);
  assertNonEmptyNoColon("vaultId", params.vaultId);
  assertNonEmptyNoColon("secretId", params.secretId);
  assertPositiveInt("version", params.version);
  assertPositiveInt("keyVersion", params.keyVersion);

  return `${params.tenantId}:${params.vaultId}:${params.secretId}:${params.version}:${params.keyVersion}`;
}

/**
 * Builds canonical Additional Authenticated Data (AAD) as UTF-8 bytes:
 * `UTF8("${tenantId}:${vaultId}:${secretId}:${version}:${keyVersion}")`
 */
export function buildCanonicalAad(params: CanonicalAadParams): Uint8Array {
  return textEncoder.encode(formatCanonicalAadString(params));
}

/**
 * Overwrites a `Uint8Array` buffer with zeroes in-place so sensitive plaintext
 * or raw key material does not linger in MCP process memory.
 */
export function zeroizeBuffer(buf: Uint8Array): void {
  buf.fill(0);
}

/**
 * Converts a `Uint8Array` view to an exact `ArrayBuffer` slice suitable for W3C WebCrypto calls.
 */
function toBufferSource(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/**
 * Imports a 32-byte raw key as a W3C WebCrypto `AES-GCM` `CryptoKey`.
 */
export async function importAesGcmKey(
  rawKeyBytes: Uint8Array,
  usages: KeyUsage[] = ["encrypt", "decrypt"],
  extractable = false,
): Promise<CryptoKey> {
  if (rawKeyBytes.byteLength !== AES_KEY_BYTES) {
    throw new Error(
      `AES-256-GCM key must be exactly ${AES_KEY_BYTES} bytes (received ${rawKeyBytes.byteLength})`,
    );
  }
  return globalThis.crypto.subtle.importKey(
    "raw",
    toBufferSource(rawKeyBytes),
    { name: "AES-GCM", length: 256 },
    extractable,
    usages,
  );
}

async function resolveAesKey(
  key: CryptoKey | Uint8Array,
  requiredUsage: "encrypt" | "decrypt",
): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    return importAesGcmKey(key, [requiredUsage], false);
  }
  return key;
}

/**
 * Encrypts `plaintext` with `AES-256-GCM` using a fresh 96-bit (12-byte) IV and canonical AAD.
 */
export async function encryptWithAad(
  key: CryptoKey | Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<EncryptedEnvelope> {
  if (aad.byteLength === 0) {
    throw new Error("Canonical AAD must not be empty");
  }
  const cryptoKey = await resolveAesKey(key, "encrypt");
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toBufferSource(iv),
      additionalData: toBufferSource(aad),
      tagLength: AES_GCM_TAG_BITS,
    },
    cryptoKey,
    toBufferSource(plaintext),
  );
  return {
    ciphertext: new Uint8Array(encryptedBuffer),
    iv,
  };
}

/**
 * Decrypts `ciphertext` with `AES-256-GCM` and verifies the 128-bit authentication tag
 * against the supplied 96-bit `iv` and canonical `aad`.
 */
export async function decryptWithAad(
  key: CryptoKey | Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (iv.byteLength !== AES_GCM_IV_BYTES) {
    throw new Error(`AES-256-GCM IV must be ${AES_GCM_IV_BYTES} bytes (received ${iv.byteLength})`);
  }
  if (aad.byteLength === 0) {
    throw new Error("Canonical AAD must not be empty");
  }
  const cryptoKey = await resolveAesKey(key, "decrypt");
  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toBufferSource(iv),
      additionalData: toBufferSource(aad),
      tagLength: AES_GCM_TAG_BITS,
    },
    cryptoKey,
    toBufferSource(ciphertext),
  );
  return new Uint8Array(decryptedBuffer);
}

/**
 * Builds canonical AAD for wrapping/unwrapping an `AgentEncryptedVaultKey`:
 * `UTF8("${tenantId}:${vaultId}:${agentId}:${keyVersion}")`
 */
export function buildAgentKeyWrapAad(params: {
  tenantId: string;
  vaultId: string;
  agentId: string;
  keyVersion: number;
}): Uint8Array {
  assertNonEmptyNoColon("tenantId", params.tenantId);
  assertNonEmptyNoColon("vaultId", params.vaultId);
  assertNonEmptyNoColon("agentId", params.agentId);
  assertPositiveInt("keyVersion", params.keyVersion);
  return textEncoder.encode(
    `${params.tenantId}:${params.vaultId}:${params.agentId}:${params.keyVersion}`,
  );
}

/**
 * Wraps a 256-bit `VaultKey` for a specific `agt_<ulid>` agent using `AgentDecryptionKey`.
 */
export async function wrapVaultKeyForAgent(
  agentDecryptionKey: CryptoKey | Uint8Array,
  vaultKeyBytes: Uint8Array,
  wrapAad: Uint8Array,
): Promise<EncryptedEnvelope> {
  if (vaultKeyBytes.byteLength !== AES_KEY_BYTES) {
    throw new Error(
      `VaultKey must be exactly ${AES_KEY_BYTES} bytes (received ${vaultKeyBytes.byteLength})`,
    );
  }
  return encryptWithAad(agentDecryptionKey, vaultKeyBytes, wrapAad);
}

/**
 * Unwraps `AgentEncryptedVaultKey` locally inside the MCP process using the workstation's
 * `AgentDecryptionKey` and imports it as a non-extractable `AES-256-GCM` `CryptoKey`.
 * Temporary unwrapped key bytes are zeroized immediately after import.
 */
export async function unwrapVaultKeyForAgent(
  agentDecryptionKey: CryptoKey | Uint8Array,
  encryptedVaultKey: Uint8Array,
  iv: Uint8Array,
  wrapAad: Uint8Array,
  extractable = false,
): Promise<CryptoKey> {
  const rawVaultKey = await decryptWithAad(agentDecryptionKey, encryptedVaultKey, iv, wrapAad);
  try {
    return await importAesGcmKey(rawVaultKey, ["encrypt", "decrypt"], extractable);
  } finally {
    zeroizeBuffer(rawVaultKey);
  }
}

/**
 * Computes a keyed `HMAC-SHA256` blind index (lowercase hex) for exact tag matching
 * without exposing plaintext tag labels in SQL queries.
 */
export async function computeTagBlindIndex(
  vaultSearchKey: CryptoKey | Uint8Array,
  tag: string,
): Promise<string> {
  const normalized = tag.trim().toLowerCase();
  if (normalized.length === 0) {
    throw new Error("Tag for blind index computation must not be empty");
  }
  const hmacKey =
    vaultSearchKey instanceof Uint8Array
      ? await globalThis.crypto.subtle.importKey(
          "raw",
          toBufferSource(vaultSearchKey),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign"],
        )
      : vaultSearchKey;

  const signature = await globalThis.crypto.subtle.sign(
    "HMAC",
    hmacKey,
    toBufferSource(textEncoder.encode(normalized)),
  );
  return bytesToHex(new Uint8Array(signature));
}

/**
 * Computes `HMAC-SHA256` over arbitrary UTF-8 data (used for audit log hash-chain verification).
 */
export async function computeHmacSha256Hex(
  key: CryptoKey | Uint8Array,
  message: string,
): Promise<string> {
  const hmacKey =
    key instanceof Uint8Array
      ? await globalThis.crypto.subtle.importKey(
          "raw",
          toBufferSource(key),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign"],
        )
      : key;
  const sig = await globalThis.crypto.subtle.sign(
    "HMAC",
    hmacKey,
    toBufferSource(textEncoder.encode(message)),
  );
  return bytesToHex(new Uint8Array(sig));
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Invalid hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.byteLength; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
