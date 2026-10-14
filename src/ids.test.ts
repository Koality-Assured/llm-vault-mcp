import { describe, expect, it } from "vitest";

import {
  assertValidId,
  extractTimestampMs,
  formatOpaqueHandle,
  generateId,
  ID_PREFIXES,
  isValidId,
  parseOpaqueHandle,
  resolveTemplateHandles,
} from "./ids.js";

describe("ids & opaque handles", () => {
  it("generates valid Crockford Base32 ULIDs for all 7 entity prefixes", () => {
    const fixedTime = 1760456722123;
    for (const prefix of ID_PREFIXES) {
      const id = generateId(prefix, fixedTime);
      expect(id.startsWith(`${prefix}_`)).toBe(true);
      expect(isValidId(id, prefix)).toBe(true);
      expect(isValidId(id)).toBe(true);
      expect(assertValidId(id, prefix)).toBe(id);
      expect(extractTimestampMs(id)).toBe(fixedTime);
    }
  });

  it("maintains lexicographical sort order across increasing timestamps", () => {
    const fixedEntropy = new Uint8Array(10).fill(7);
    const id1 = generateId("sec", 1760000000000, fixedEntropy);
    const id2 = generateId("sec", 1760000000001, fixedEntropy);
    const id3 = generateId("sec", 1760000050000, fixedEntropy);
    expect([id3, id1, id2].sort()).toEqual([id1, id2, id3]);
  });

  it("rejects malformed identifiers and disallowed Crockford characters", () => {
    expect(isValidId("sec_short")).toBe(false);
    expect(isValidId("unknown_01jk7a89b2c3d4e5f6g7h8j9k0")).toBe(false);
    // 'i', 'l', 'o', 'u' are excluded from Crockford Base32
    expect(isValidId("sec_01jk7a89b2c3d4e5f6g7h8j9ki")).toBe(false);
    expect(isValidId("sec_01jk7a89b2c3d4e5f6g7h8j9ko")).toBe(false);
    expect(isValidId("sec_01jk7a89b2c3d4e5f6g7h8j9k0", "vlt")).toBe(false);
    expect(() => assertValidId("vlt_invalid", "vlt")).toThrow(/Invalid identifier/);
  });

  it("formats and parses opaque handles for sec_ and lease_ only", () => {
    const secId = generateId("sec", 1760000000000);
    const leaseId = generateId("lease", 1760000000000);
    const vltId = generateId("vlt", 1760000000000);

    const secHandle = formatOpaqueHandle(secId);
    expect(secHandle).toBe(`{{vault:${secId}}}`);
    expect(parseOpaqueHandle(secHandle)).toEqual({
      kind: "sec",
      id: secId,
      handle: secHandle,
    });
    expect(parseOpaqueHandle(secId)).toEqual({
      kind: "sec",
      id: secId,
      handle: secHandle,
    });

    const leaseHandle = formatOpaqueHandle(leaseId);
    expect(leaseHandle).toBe(`{{vault:${leaseId}}}`);
    expect(parseOpaqueHandle(leaseHandle)).toEqual({
      kind: "lease",
      id: leaseId,
      handle: leaseHandle,
    });

    expect(() => formatOpaqueHandle(vltId)).toThrow(/Opaque handles can only wrap/);
    expect(parseOpaqueHandle(vltId)).toBeNull();
  });

  it("resolves template strings containing multiple opaque handles", () => {
    const secId = generateId("sec", 1760000000100);
    const leaseId = generateId("lease", 1760000000200);
    const template = `Bearer {{vault:${secId}}} / Lease={{vault:${leaseId}}}`;

    const { resolved, referencedIds } = resolveTemplateHandles(template, (id, kind) => {
      if (id === secId && kind === "sec") {
        return "sk-live-secret-token";
      }
      if (id === leaseId && kind === "lease") {
        return new TextEncoder().encode("ephemeral-db-pass");
      }
      throw new Error("Unexpected id");
    });

    expect(resolved).toBe("Bearer sk-live-secret-token / Lease=ephemeral-db-pass");
    expect(referencedIds).toEqual([secId, leaseId]);
  });
});
