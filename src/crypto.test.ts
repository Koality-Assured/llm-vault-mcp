import { describe, expect, it } from "vitest";

import {
  buildAgentKeyWrapAad,
  buildCanonicalAad,
  computeTagBlindIndex,
  decryptWithAad,
  encryptWithAad,
  formatCanonicalAadString,
  unwrapVaultKeyForAgent,
  wrapVaultKeyForAgent,
  zeroizeBuffer,
} from "./crypto.js";
import { generateId } from "./ids.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

describe("local zero-knowledge WebCrypto engine", () => {
  it("builds canonical AAD and rejects colon injection or invalid versions", () => {
    const vaultId = generateId("vlt", 1760000000000);
    const secretId = generateId("sec", 1760000000000);
    const aadStr = formatCanonicalAadString({
      tenantId: "tnt_acme",
      vaultId,
      secretId,
      version: 3,
      keyVersion: 2,
    });
    expect(aadStr).toBe(`tnt_acme:${vaultId}:${secretId}:3:2`);

    expect(() =>
      buildCanonicalAad({
        tenantId: "tnt:injected",
        vaultId,
        secretId,
        version: 1,
        keyVersion: 1,
      }),
    ).toThrow(/must not contain ':'/);

    expect(() =>
      buildCanonicalAad({
        tenantId: "tnt_acme",
        vaultId,
        secretId,
        version: 0,
        keyVersion: 1,
      }),
    ).toThrow(/positive integer/);
  });

  it("encrypts and decrypts with AES-256-GCM and rejects any AAD or ciphertext tampering", async () => {
    const rawKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const vaultId = generateId("vlt", 1760000000000);
    const secretId = generateId("sec", 1760000000000);
    const aad = buildCanonicalAad({
      tenantId: "tnt_01",
      vaultId,
      secretId,
      version: 1,
      keyVersion: 1,
    });

    const plaintext = encoder.encode("super-secret-api-key-9999");
    const { ciphertext, iv } = await encryptWithAad(rawKey, plaintext, aad);
    expect(iv.byteLength).toBe(12);
    expect(ciphertext.byteLength).toBe(plaintext.byteLength + 16);

    const decrypted = await decryptWithAad(rawKey, ciphertext, iv, aad);
    expect(decoder.decode(decrypted)).toBe("super-secret-api-key-9999");

    // Mismatched version in AAD (ciphertext transplanting attack) must fail
    const wrongVersionAad = buildCanonicalAad({
      tenantId: "tnt_01",
      vaultId,
      secretId,
      version: 2,
      keyVersion: 1,
    });
    await expect(decryptWithAad(rawKey, ciphertext, iv, wrongVersionAad)).rejects.toThrow();

    // Tampered ciphertext byte must fail GCM authentication tag verification
    const tamperedCiphertext = new Uint8Array(ciphertext);
    tamperedCiphertext[0] = (tamperedCiphertext[0] ?? 0) ^ 0xff;
    await expect(decryptWithAad(rawKey, tamperedCiphertext, iv, aad)).rejects.toThrow();
  });

  it("wraps and unwraps AgentEncryptedVaultKey using AgentDecryptionKey", async () => {
    const agentDecryptionKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const vaultKeyBytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const vaultId = generateId("vlt", 1760000000000);
    const agentId = generateId("agt", 1760000000000);
    const secretId = generateId("sec", 1760000000000);

    const wrapAad = buildAgentKeyWrapAad({
      tenantId: "tnt_prod",
      vaultId,
      agentId,
      keyVersion: 1,
    });

    const wrapped = await wrapVaultKeyForAgent(agentDecryptionKey, vaultKeyBytes, wrapAad);
    const unwrappedCryptoKey = await unwrapVaultKeyForAgent(
      agentDecryptionKey,
      wrapped.ciphertext,
      wrapped.iv,
      wrapAad,
    );

    const secretAad = buildCanonicalAad({
      tenantId: "tnt_prod",
      vaultId,
      secretId,
      version: 1,
      keyVersion: 1,
    });
    const envelope = await encryptWithAad(
      unwrappedCryptoKey,
      encoder.encode("db-password-xyz"),
      secretAad,
    );
    const out = await decryptWithAad(vaultKeyBytes, envelope.ciphertext, envelope.iv, secretAad);
    expect(decoder.decode(out)).toBe("db-password-xyz");
  });

  it("computes deterministic keyed HMAC-SHA256 blind indexes for normalized tags", async () => {
    const searchKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const idx1 = await computeTagBlindIndex(searchKey, "Production");
    const idx2 = await computeTagBlindIndex(searchKey, "  production  ");
    const idx3 = await computeTagBlindIndex(searchKey, "staging");

    expect(idx1).toMatch(/^[0-9a-f]{64}$/);
    expect(idx1).toBe(idx2);
    expect(idx1).not.toBe(idx3);
  });

  it("zeroizes Uint8Array buffers in-place", () => {
    const buf = new Uint8Array([10, 20, 30, 40, 255]);
    zeroizeBuffer(buf);
    expect(Array.from(buf)).toEqual([0, 0, 0, 0, 0]);
  });
});
