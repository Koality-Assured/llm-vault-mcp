import { describe, expect, it, vi } from "vitest";

import { generateId } from "./ids.js";
import { LeaseManager } from "./lease-manager.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

describe("LeaseManager ephemeral secret leasing & TTL zeroization", () => {
  it("acquires a lease, resolves bytes before expiry, and zeroizes buffer on TTL expiration", () => {
    vi.useFakeTimers();
    try {
      let currentNow = 1760000000000;
      const manager = new LeaseManager(() => currentNow);
      const secretId = generateId("sec", currentNow);
      const vaultId = generateId("vlt", currentNow);

      const lease = manager.acquireLease({
        secretId,
        vaultId,
        secretBytes: encoder.encode("ephemeral-rotating-secret-value"),
        ttlSeconds: 30,
      });

      expect(lease.leaseId.startsWith("lease_")).toBe(true);
      expect(lease.handle).toBe(`{{vault:${lease.leaseId}}}`);

      const resolved = manager.resolveLeaseBytes(lease.leaseId);
      const internalBufferRef = resolved.valueBytes;
      expect(decoder.decode(internalBufferRef)).toBe("ephemeral-rotating-secret-value");

      // Advance clock and timers past 30s TTL
      currentNow += 31_000;
      vi.advanceTimersByTime(31_000);

      // Buffer must be completely zeroed in memory
      expect(internalBufferRef.every((byte) => byte === 0)).toBe(true);
      expect(() => manager.resolveLeaseBytes(lease.leaseId)).toThrow(/expired or does not exist/);
    } finally {
      vi.useRealTimers();
    }
  });

  it("zeroizes lease memory immediately on manual revocation or disposeAll", () => {
    const manager = new LeaseManager();
    const secretId = generateId("sec");
    const vaultId = generateId("vlt");

    const lease = manager.acquireLease({
      secretId,
      vaultId,
      secretBytes: encoder.encode("revoke-me-immediately"),
      ttlSeconds: 120,
    });

    const bufRef = manager.resolveLeaseBytes(lease.leaseId).valueBytes;
    expect(manager.revokeLease(lease.leaseId)).toBe(true);
    expect(bufRef.every((byte) => byte === 0)).toBe(true);
    expect(() => manager.resolveLeaseBytes(lease.leaseId)).toThrow(/expired or does not exist/);
  });

  it("enforces TTL bounds", () => {
    const manager = new LeaseManager();
    const secretId = generateId("sec");
    const vaultId = generateId("vlt");

    expect(() =>
      manager.acquireLease({
        secretId,
        vaultId,
        secretBytes: encoder.encode("abc"),
        ttlSeconds: 0,
      }),
    ).toThrow(RangeError);

    expect(() =>
      manager.acquireLease({
        secretId,
        vaultId,
        secretBytes: encoder.encode("abc"),
        ttlSeconds: 3600,
      }),
    ).toThrow(RangeError);
  });
});
