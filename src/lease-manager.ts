import { zeroizeBuffer } from "./crypto.js";
import { formatOpaqueHandle, generateId, isValidId, type PrefixedId } from "./ids.js";

export const MIN_LEASE_TTL_SECONDS = 1;
export const MAX_LEASE_TTL_SECONDS = 900; // 15 minutes max per spec [M-1]
export const DEFAULT_LEASE_TTL_SECONDS = 60;

export interface AcquireLeaseInput {
  secretId: PrefixedId<"sec">;
  vaultId: PrefixedId<"vlt">;
  secretBytes: Uint8Array;
  ttlSeconds?: number;
}

export interface LeaseMetadata {
  leaseId: PrefixedId<"lease">;
  handle: string;
  secretId: PrefixedId<"sec">;
  vaultId: PrefixedId<"vlt">;
  createdAtMs: number;
  expiresAtMs: number;
  ttlSeconds: number;
}

interface InternalLeaseRecord extends LeaseMetadata {
  valueBytes: Uint8Array;
  timer: ReturnType<typeof setTimeout>;
  invalidated: boolean;
}

/**
 * Manages time-bounded `lease_<ulid>` handles in MCP memory and automatically
 * invokes `zeroizeBuffer` when a lease's TTL expires or is revoked.
 */
export class LeaseManager {
  private readonly leases = new Map<PrefixedId<"lease">, InternalLeaseRecord>();
  private readonly nowFn: () => number;

  constructor(nowFn: () => number = () => Date.now()) {
    this.nowFn = nowFn;
  }

  /**
   * Acquires an ephemeral lease holding a private copy of `secretBytes` in memory.
   * When `ttlSeconds` elapses, the buffer is overwritten with zeroes and invalidated.
   */
  public acquireLease(input: AcquireLeaseInput): LeaseMetadata {
    if (!isValidId(input.secretId, "sec")) {
      throw new Error(`Invalid secretId for lease: ${input.secretId}`);
    }
    if (!isValidId(input.vaultId, "vlt")) {
      throw new Error(`Invalid vaultId for lease: ${input.vaultId}`);
    }
    const ttlSeconds = input.ttlSeconds ?? DEFAULT_LEASE_TTL_SECONDS;
    if (
      !Number.isInteger(ttlSeconds) ||
      ttlSeconds < MIN_LEASE_TTL_SECONDS ||
      ttlSeconds > MAX_LEASE_TTL_SECONDS
    ) {
      throw new RangeError(
        `Lease ttlSeconds must be an integer between ${MIN_LEASE_TTL_SECONDS} and ${MAX_LEASE_TTL_SECONDS} (received ${ttlSeconds})`,
      );
    }

    const nowMs = this.nowFn();
    const leaseId = generateId("lease", nowMs);
    const handle = formatOpaqueHandle(leaseId);
    const expiresAtMs = nowMs + ttlSeconds * 1000;

    // Copy secret bytes into a dedicated buffer owned by this lease
    const ownedBuffer = new Uint8Array(input.secretBytes.byteLength);
    ownedBuffer.set(input.secretBytes);

    const timer = setTimeout(() => {
      this.invalidateRecord(leaseId);
    }, ttlSeconds * 1000);
    // Do not prevent the Node.js event loop from exiting on shutdown
    timer.unref?.();

    const record: InternalLeaseRecord = {
      leaseId,
      handle,
      secretId: input.secretId,
      vaultId: input.vaultId,
      createdAtMs: nowMs,
      expiresAtMs,
      ttlSeconds,
      valueBytes: ownedBuffer,
      timer,
      invalidated: false,
    };

    this.leases.set(leaseId, record);

    return {
      leaseId,
      handle,
      secretId: record.secretId,
      vaultId: record.vaultId,
      createdAtMs: record.createdAtMs,
      expiresAtMs: record.expiresAtMs,
      ttlSeconds: record.ttlSeconds,
    };
  }

  /**
   * Resolves a `lease_<ulid>` handle to its underlying `Uint8Array` secret bytes
   * if and only if the lease is active and within its TTL window.
   */
  public resolveLeaseBytes(leaseId: string): {
    leaseId: PrefixedId<"lease">;
    secretId: PrefixedId<"sec">;
    vaultId: PrefixedId<"vlt">;
    valueBytes: Uint8Array;
  } {
    if (!isValidId(leaseId, "lease")) {
      throw new Error(`Invalid lease identifier: ${leaseId}`);
    }
    const record = this.leases.get(leaseId);
    if (!record || record.invalidated) {
      throw new Error(`Lease "${leaseId}" is expired or does not exist`);
    }

    if (this.nowFn() >= record.expiresAtMs) {
      this.invalidateRecord(leaseId);
      throw new Error(`Lease "${leaseId}" has expired`);
    }

    return {
      leaseId: record.leaseId,
      secretId: record.secretId,
      vaultId: record.vaultId,
      valueBytes: record.valueBytes,
    };
  }

  /**
   * Inspects the raw buffer reference for testing zeroization guarantees.
   */
  public getActiveLeaseCount(): number {
    this.purgeExpiredLeases();
    return this.leases.size;
  }

  /**
   * Explicitly revokes a lease and zeroes its in-memory `Uint8Array` immediately.
   */
  public revokeLease(leaseId: string): boolean {
    if (!isValidId(leaseId, "lease")) {
      return false;
    }
    return this.invalidateRecord(leaseId);
  }

  /**
   * Sweeps all leases whose `expiresAtMs <= now` and zeroes their buffers.
   */
  public purgeExpiredLeases(): number {
    const nowMs = this.nowFn();
    let purged = 0;
    for (const [leaseId, record] of this.leases.entries()) {
      if (nowMs >= record.expiresAtMs || record.invalidated) {
        if (this.invalidateRecord(leaseId)) {
          purged++;
        }
      }
    }
    return purged;
  }

  /**
   * Zeroizes and clears all active leases on server shutdown.
   */
  public disposeAll(): void {
    for (const leaseId of Array.from(this.leases.keys())) {
      this.invalidateRecord(leaseId);
    }
  }

  private invalidateRecord(leaseId: PrefixedId<"lease">): boolean {
    const record = this.leases.get(leaseId);
    if (!record) {
      return false;
    }
    clearTimeout(record.timer);
    zeroizeBuffer(record.valueBytes);
    record.invalidated = true;
    this.leases.delete(leaseId);
    return true;
  }
}
