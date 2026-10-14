import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import {
  buildAgentKeyWrapAad,
  buildCanonicalAad,
  bytesToHex,
  computeHmacSha256Hex,
  computeTagBlindIndex,
  decryptWithAad,
  encryptWithAad,
  unwrapVaultKeyForAgent,
  wrapVaultKeyForAgent,
  zeroizeBuffer,
} from "./crypto.js";
import {
  formatOpaqueHandle,
  generateId,
  isValidId,
  parseOpaqueHandle,
  prefixedIdSchema,
  resolveTemplateHandles,
  type PrefixedId,
} from "./ids.js";
import {
  DEFAULT_LEASE_TTL_SECONDS,
  LeaseManager,
  MAX_LEASE_TTL_SECONDS,
  MIN_LEASE_TTL_SECONDS,
} from "./lease-manager.js";
import { scrubHeaders, scrubSecretsFromText, type ActiveSecretDescriptor } from "./scrubber.js";

const execFileAsync = promisify(execFile);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export type DeploymentMode = "standalone" | "enterprise";

export type PermissionScope =
  | "secrets:create"
  | "secrets:read"
  | "secrets:reveal"
  | "secrets:update"
  | "secrets:delete"
  | "secrets:rollback"
  | "agent:lease:acquire"
  | "agent:exec:run"
  | "agent:exec:http_proxy"
  | "admin:audit:read";

export interface SecretCleartextMetadata {
  name: string;
  description: string;
  tags: string[];
  folderId?: PrefixedId<"fld"> | undefined;
}

export interface StoredCiphertextSecretRecord {
  id: PrefixedId<"sec">;
  tenantId: string;
  vaultId: PrefixedId<"vlt">;
  folderId?: PrefixedId<"fld"> | undefined;
  version: number;
  keyVersion: number;
  tagBlindIndexes: string[];
  encryptedMetadata: Uint8Array;
  metadataIv: Uint8Array;
  encryptedPayload: Uint8Array;
  payloadIv: Uint8Array;
  createdAt: string;
  updatedAt: string;
}

export interface StoredVaultEnvelope {
  vaultId: PrefixedId<"vlt">;
  tenantId: string;
  keyVersion: number;
  agentEncryptedVaultKey: Uint8Array;
  agentWrapIv: Uint8Array;
  vaultSearchKey: Uint8Array;
}

export interface AuditLogEvent {
  id: PrefixedId<"aud">;
  timestamp: string;
  actorId: PrefixedId<"agt"> | PrefixedId<"usr">;
  action: string;
  targetId: string;
  prevEventHash: string;
  eventHash: string;
}

export interface CommandRunnerResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type CommandRunner = (
  command: string,
  args: ReadonlyArray<string>,
  env: Record<string, string>,
  cwd?: string,
) => Promise<CommandRunnerResult>;

export interface HttpProxyResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
}

export type HttpFetcher = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string | undefined;
  },
) => Promise<HttpProxyResponse>;

export type OobConfirmationHandler = (prompt: {
  reason: string;
  targetId: string;
  actorId: PrefixedId<"agt">;
}) => Promise<boolean>;

export type OobSecretPromptHandler = (prompt: {
  vaultId: PrefixedId<"vlt">;
  name: string;
  promptMessage: string;
}) => Promise<Uint8Array>;

export interface VaultRuntimeOptions {
  tenantId?: string;
  agentId?: PrefixedId<"agt">;
  deploymentMode?: DeploymentMode;
  keychainUnlocked?: boolean;
  allowRawContextReveal?: boolean;
  scopes?: ReadonlyArray<PermissionScope>;
  agentDecryptionKey?: Uint8Array;
  auditLogKey?: Uint8Array;
  leaseManager?: LeaseManager;
  commandRunner?: CommandRunner;
  httpFetcher?: HttpFetcher;
  oobConfirmHandler?: OobConfirmationHandler;
  oobSecretPromptHandler?: OobSecretPromptHandler;
}

const GENESIS_PREV_HASH = "0".repeat(64);

const DEFAULT_SCOPES: ReadonlyArray<PermissionScope> = [
  "secrets:create",
  "secrets:read",
  "secrets:reveal",
  "secrets:update",
  "agent:lease:acquire",
  "agent:exec:run",
  "agent:exec:http_proxy",
  "admin:audit:read",
];

async function defaultCommandRunner(
  command: string,
  args: ReadonlyArray<string>,
  env: Record<string, string>,
  cwd?: string,
): Promise<CommandRunnerResult> {
  try {
    const { stdout, stderr } = await execFileAsync(command, [...args], {
      env: { ...process.env, ...env },
      cwd,
      shell: false,
      windowsHide: true,
      maxBuffer: 4 * 1024 * 1024,
    });
    return {
      exitCode: 0,
      stdout: String(stdout),
      stderr: String(stderr),
    };
  } catch (err: unknown) {
    const execErr = err as {
      code?: number | string;
      stdout?: string;
      stderr?: string;
      message?: string;
    };
    return {
      exitCode: typeof execErr.code === "number" ? execErr.code : 1,
      stdout: typeof execErr.stdout === "string" ? execErr.stdout : "",
      stderr:
        typeof execErr.stderr === "string"
          ? execErr.stderr
          : (execErr.message ?? "Command execution failed"),
    };
  }
}

async function defaultHttpFetcher(
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string | undefined;
  },
): Promise<HttpProxyResponse> {
  const fetchInit: RequestInit = {
    method: init.method,
    headers: init.headers,
  };
  if (init.body !== undefined) {
    fetchInit.body = init.body;
  }
  const res = await fetch(url, fetchInit);
  const headers: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    headers[key] = value;
  });
  const body = await res.text();
  return {
    status: res.status,
    statusText: res.statusText,
    headers,
    body,
  };
}

/**
 * Zero-Knowledge Vault Runtime for `llm-vault-mcp`.
 * Holds only ciphertext secret records and `AgentEncryptedVaultKey` envelopes,
 * unwrapping keys and decrypting payloads on-demand inside the MCP process via WebCrypto.
 */
export class VaultRuntime {
  public readonly tenantId: string;
  public readonly agentId: PrefixedId<"agt">;
  public readonly deploymentMode: DeploymentMode;
  public readonly keychainUnlocked: boolean;
  public readonly allowRawContextReveal: boolean;
  public readonly scopes: Set<PermissionScope>;
  public readonly leaseManager: LeaseManager;

  private readonly agentDecryptionKey: Uint8Array;
  private readonly auditLogKey: Uint8Array;
  private readonly vaults = new Map<PrefixedId<"vlt">, StoredVaultEnvelope>();
  private readonly secrets = new Map<PrefixedId<"sec">, StoredCiphertextSecretRecord>();
  private readonly auditLogs: AuditLogEvent[] = [];
  private readonly commandRunner: CommandRunner;
  private readonly httpFetcher: HttpFetcher;
  private readonly oobConfirmHandler: OobConfirmationHandler;
  private readonly oobSecretPromptHandler: OobSecretPromptHandler;

  constructor(options: VaultRuntimeOptions = {}) {
    this.tenantId = options.tenantId ?? "tnt_default";
    this.agentId = options.agentId ?? generateId("agt", 1760000000000);
    this.deploymentMode = options.deploymentMode ?? "standalone";
    this.keychainUnlocked = options.keychainUnlocked ?? true;
    this.allowRawContextReveal = options.allowRawContextReveal ?? false;
    this.scopes = new Set(options.scopes ?? DEFAULT_SCOPES);
    this.leaseManager = options.leaseManager ?? new LeaseManager();
    this.agentDecryptionKey =
      options.agentDecryptionKey ?? globalThis.crypto.getRandomValues(new Uint8Array(32));
    this.auditLogKey = options.auditLogKey ?? globalThis.crypto.getRandomValues(new Uint8Array(32));
    this.commandRunner = options.commandRunner ?? defaultCommandRunner;
    this.httpFetcher = options.httpFetcher ?? defaultHttpFetcher;
    this.oobConfirmHandler = options.oobConfirmHandler ?? (async () => false);
    this.oobSecretPromptHandler =
      options.oobSecretPromptHandler ??
      (async () => {
        throw new Error(
          "No interactive OOB TTY/OS prompt handler configured for this headless MCP session",
        );
      });
  }

  public assertScope(required: PermissionScope): void {
    if (!this.keychainUnlocked) {
      throw new Error("OS keychain is locked: AgentDecryptionKey is unavailable");
    }
    if (!this.scopes.has(required)) {
      throw new Error(
        `Permission denied: agent "${this.agentId}" lacks required scope "${required}"`,
      );
    }
  }

  /**
   * Provisions a vault container by wrapping a random 256-bit `VaultKey` under
   * the workstation's `AgentDecryptionKey` (`AgentEncryptedVaultKey`), then immediately
   * zeroizing the raw `VaultKey` bytes.
   */
  public async provisionVault(
    vaultId: PrefixedId<"vlt"> = generateId("vlt"),
    keyVersion = 1,
  ): Promise<PrefixedId<"vlt">> {
    const rawVaultKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const vaultSearchKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
    try {
      const wrapAad = buildAgentKeyWrapAad({
        tenantId: this.tenantId,
        vaultId,
        agentId: this.agentId,
        keyVersion,
      });
      const { ciphertext, iv } = await wrapVaultKeyForAgent(
        this.agentDecryptionKey,
        rawVaultKey,
        wrapAad,
      );
      this.vaults.set(vaultId, {
        vaultId,
        tenantId: this.tenantId,
        keyVersion,
        agentEncryptedVaultKey: ciphertext,
        agentWrapIv: iv,
        vaultSearchKey,
      });
      await this.appendAuditEvent("vaults:provision", vaultId);
      return vaultId;
    } finally {
      zeroizeBuffer(rawVaultKey);
    }
  }

  public async ensureDefaultVault(): Promise<PrefixedId<"vlt">> {
    const first = this.vaults.keys().next();
    if (!first.done) {
      return first.value;
    }
    return this.provisionVault();
  }

  private async unwrapVaultKey(vaultId: PrefixedId<"vlt">): Promise<{
    vaultKey: CryptoKey;
    envelope: StoredVaultEnvelope;
  }> {
    const envelope = this.vaults.get(vaultId);
    if (!envelope) {
      throw new Error(
        `Vault "${vaultId}" is not registered or accessible to agent "${this.agentId}"`,
      );
    }
    const wrapAad = buildAgentKeyWrapAad({
      tenantId: envelope.tenantId,
      vaultId: envelope.vaultId,
      agentId: this.agentId,
      keyVersion: envelope.keyVersion,
    });
    const vaultKey = await unwrapVaultKeyForAgent(
      this.agentDecryptionKey,
      envelope.agentEncryptedVaultKey,
      envelope.agentWrapIv,
      wrapAad,
      false,
    );
    return { vaultKey, envelope };
  }

  /**
   * Encrypts a secret's metadata and payload locally using the vault's unwrapped `VaultKey`
   * and canonical AAD, computes `HMAC-SHA256` blind indexes for tags, and stores only ciphertext.
   */
  public async storeEncryptedSecret(params: {
    vaultId: PrefixedId<"vlt">;
    secretId?: PrefixedId<"sec"> | undefined;
    name: string;
    description?: string | undefined;
    tags?: ReadonlyArray<string> | undefined;
    folderId?: PrefixedId<"fld"> | undefined;
    plaintextBytes: Uint8Array;
  }): Promise<{
    id: PrefixedId<"sec">;
    vaultId: PrefixedId<"vlt">;
    version: number;
    handle: string;
  }> {
    const { vaultKey, envelope } = await this.unwrapVaultKey(params.vaultId);
    const existing = params.secretId ? this.secrets.get(params.secretId) : undefined;
    const secretId = params.secretId ?? generateId("sec");
    const version = existing ? existing.version + 1 : 1;

    const aad = buildCanonicalAad({
      tenantId: envelope.tenantId,
      vaultId: envelope.vaultId,
      secretId,
      version,
      keyVersion: envelope.keyVersion,
    });

    const normalizedTags = Array.from(
      new Set((params.tags ?? []).map((t) => t.trim().toLowerCase()).filter((t) => t.length > 0)),
    );

    const metadataObj: SecretCleartextMetadata = {
      name: params.name,
      description: params.description ?? "",
      tags: normalizedTags,
      ...(params.folderId ? { folderId: params.folderId } : {}),
    };

    const metadataBytes = textEncoder.encode(JSON.stringify(metadataObj));
    const encryptedMeta = await encryptWithAad(vaultKey, metadataBytes, aad);
    const encryptedPayload = await encryptWithAad(vaultKey, params.plaintextBytes, aad);

    const tagBlindIndexes: string[] = [];
    for (const tag of normalizedTags) {
      tagBlindIndexes.push(await computeTagBlindIndex(envelope.vaultSearchKey, tag));
    }

    const nowIso = new Date().toISOString();
    const record: StoredCiphertextSecretRecord = {
      id: secretId,
      tenantId: envelope.tenantId,
      vaultId: envelope.vaultId,
      folderId: params.folderId,
      version,
      keyVersion: envelope.keyVersion,
      tagBlindIndexes,
      encryptedMetadata: encryptedMeta.ciphertext,
      metadataIv: encryptedMeta.iv,
      encryptedPayload: encryptedPayload.ciphertext,
      payloadIv: encryptedPayload.iv,
      createdAt: existing?.createdAt ?? nowIso,
      updatedAt: nowIso,
    };

    this.secrets.set(secretId, record);
    await this.appendAuditEvent(existing ? "secrets:update" : "secrets:create", secretId);

    return {
      id: secretId,
      vaultId: envelope.vaultId,
      version,
      handle: formatOpaqueHandle(secretId),
    };
  }

  /**
   * Decrypts only the metadata header (`encrypted_metadata`) for a stored secret.
   */
  public async decryptSecretMetadata(record: StoredCiphertextSecretRecord): Promise<{
    id: PrefixedId<"sec">;
    vaultId: PrefixedId<"vlt">;
    version: number;
    name: string;
    description: string;
    tags: string[];
    folderId?: PrefixedId<"fld"> | undefined;
    handle: string;
  }> {
    const { vaultKey } = await this.unwrapVaultKey(record.vaultId);
    const aad = buildCanonicalAad({
      tenantId: record.tenantId,
      vaultId: record.vaultId,
      secretId: record.id,
      version: record.version,
      keyVersion: record.keyVersion,
    });
    const decryptedBytes = await decryptWithAad(
      vaultKey,
      record.encryptedMetadata,
      record.metadataIv,
      aad,
    );
    try {
      const parsed = JSON.parse(textDecoder.decode(decryptedBytes)) as SecretCleartextMetadata;
      return {
        id: record.id,
        vaultId: record.vaultId,
        version: record.version,
        name: parsed.name,
        description: parsed.description,
        tags: parsed.tags,
        folderId: record.folderId ?? parsed.folderId,
        handle: formatOpaqueHandle(record.id),
      };
    } finally {
      zeroizeBuffer(decryptedBytes);
    }
  }

  /**
   * Decrypts a single secret's `encrypted_payload` on-demand into a transient `Uint8Array`
   * after recording an immutable `aud_<ulid>` reveal event.
   */
  public async decryptSecretPayloadBytes(secretId: PrefixedId<"sec">): Promise<{
    record: StoredCiphertextSecretRecord;
    plaintextBytes: Uint8Array;
  }> {
    this.assertScope("secrets:reveal");
    const record = this.secrets.get(secretId);
    if (!record) {
      throw new Error(`Secret "${secretId}" not found`);
    }
    const { vaultKey } = await this.unwrapVaultKey(record.vaultId);
    const aad = buildCanonicalAad({
      tenantId: record.tenantId,
      vaultId: record.vaultId,
      secretId: record.id,
      version: record.version,
      keyVersion: record.keyVersion,
    });
    const plaintextBytes = await decryptWithAad(
      vaultKey,
      record.encryptedPayload,
      record.payloadIv,
      aad,
    );
    await this.appendAuditEvent("secrets:reveal", secretId);
    return { record, plaintextBytes };
  }

  public getStatus() {
    return {
      status: this.keychainUnlocked ? ("ready" as const) : ("locked" as const),
      deploymentMode: this.deploymentMode,
      tenantId: this.tenantId,
      agentId: this.agentId,
      keychainUnlocked: this.keychainUnlocked,
      allowRawContextReveal: this.allowRawContextReveal,
      accessibleVaultIds: Array.from(this.vaults.keys()),
      activeLeaseCount: this.leaseManager.getActiveLeaseCount(),
      scopes: Array.from(this.scopes),
    };
  }

  public async searchSecrets(filter: {
    query?: string | undefined;
    tag?: string | undefined;
    vaultId?: PrefixedId<"vlt"> | undefined;
    folderId?: PrefixedId<"fld"> | undefined;
  }) {
    this.assertScope("secrets:read");
    const normalizedQuery = filter.query?.trim().toLowerCase();
    const normalizedTag = filter.tag?.trim().toLowerCase();

    const results: Array<{
      id: PrefixedId<"sec">;
      vaultId: PrefixedId<"vlt">;
      version: number;
      name: string;
      description: string;
      tags: string[];
      folderId?: PrefixedId<"fld"> | undefined;
      handle: string;
    }> = [];

    for (const record of this.secrets.values()) {
      if (filter.vaultId && record.vaultId !== filter.vaultId) {
        continue;
      }
      if (filter.folderId && record.folderId !== filter.folderId) {
        continue;
      }
      if (normalizedTag) {
        const envelope = this.vaults.get(record.vaultId);
        if (!envelope) {
          continue;
        }
        const expectedBlindIndex = await computeTagBlindIndex(
          envelope.vaultSearchKey,
          normalizedTag,
        );
        if (!record.tagBlindIndexes.includes(expectedBlindIndex)) {
          continue;
        }
      }

      const meta = await this.decryptSecretMetadata(record);
      if (normalizedQuery && normalizedQuery.length > 0) {
        const haystack = `${meta.name}\n${meta.description}\n${meta.tags.join(" ")}`.toLowerCase();
        if (!haystack.includes(normalizedQuery)) {
          continue;
        }
      }
      results.push(meta);
    }

    await this.appendAuditEvent("secrets:search", filter.vaultId ?? "*");
    return results;
  }

  public async listTags(vaultId?: PrefixedId<"vlt">): Promise<string[]> {
    this.assertScope("secrets:read");
    const tagSet = new Set<string>();
    for (const record of this.secrets.values()) {
      if (vaultId && record.vaultId !== vaultId) {
        continue;
      }
      const meta = await this.decryptSecretMetadata(record);
      for (const tag of meta.tags) {
        tagSet.add(tag);
      }
    }
    return Array.from(tagSet).sort();
  }

  /**
   * Resolves a secret for the agent. Returns an opaque `{{vault:sec_<ulid>}}` handle by default.
   * Blocks raw plaintext reveal unless BOTH `allowRawContextReveal: true` is configured on the
   * agent policy AND out-of-band human confirmation (`oobConfirmHandler`) approves the request.
   */
  public async getSecret(params: {
    secretId: PrefixedId<"sec">;
    requestRawPlaintext?: boolean | undefined;
    breakGlassReason?: string | undefined;
  }): Promise<{
    id: PrefixedId<"sec">;
    vaultId: PrefixedId<"vlt">;
    name: string;
    version: number;
    handle: string;
    redacted: boolean;
    plaintextValue?: string;
  }> {
    this.assertScope("secrets:read");
    const record = this.secrets.get(params.secretId);
    if (!record) {
      throw new Error(`Secret "${params.secretId}" not found`);
    }
    const meta = await this.decryptSecretMetadata(record);

    if (!params.requestRawPlaintext) {
      return {
        id: meta.id,
        vaultId: meta.vaultId,
        name: meta.name,
        version: meta.version,
        handle: meta.handle,
        redacted: true,
      };
    }

    // Raw context reveal requested — enforce Zero-Context Policy + OOB human gate
    if (!this.allowRawContextReveal) {
      await this.appendAuditEvent("secrets:reveal_blocked_policy", params.secretId);
      throw new Error(
        `ZERO_CONTEXT_POLICY_VIOLATION: Raw plaintext reveal is disabled on agent "${this.agentId}". Use opaque handle "${meta.handle}" with vault_run_command, vault_inject_env, or vault_http_proxy.`,
      );
    }

    const approved = await this.oobConfirmHandler({
      reason: params.breakGlassReason ?? "Agent requested raw plaintext reveal",
      targetId: params.secretId,
      actorId: this.agentId,
    });

    if (!approved) {
      await this.appendAuditEvent("secrets:reveal_blocked_oob", params.secretId);
      throw new Error(
        `OOB_APPROVAL_REQUIRED: Out-of-band human operator denied or did not approve raw plaintext reveal for "${params.secretId}".`,
      );
    }

    const { plaintextBytes } = await this.decryptSecretPayloadBytes(params.secretId);
    try {
      return {
        id: meta.id,
        vaultId: meta.vaultId,
        name: meta.name,
        version: meta.version,
        handle: meta.handle,
        redacted: false,
        plaintextValue: textDecoder.decode(plaintextBytes),
      };
    } finally {
      zeroizeBuffer(plaintextBytes);
    }
  }

  /**
   * Acquires a time-bounded `lease_<ulid>` handle for `secretId`.
   */
  public async leaseSecret(params: {
    secretId: PrefixedId<"sec">;
    ttlSeconds?: number | undefined;
  }) {
    this.assertScope("agent:lease:acquire");
    const { record, plaintextBytes } = await this.decryptSecretPayloadBytes(params.secretId);
    try {
      const lease = this.leaseManager.acquireLease({
        secretId: record.id,
        vaultId: record.vaultId,
        secretBytes: plaintextBytes,
        ...(params.ttlSeconds !== undefined ? { ttlSeconds: params.ttlSeconds } : {}),
      });
      await this.appendAuditEvent("agent:lease:acquire", lease.leaseId);
      return {
        leaseId: lease.leaseId,
        handle: lease.handle,
        secretId: lease.secretId,
        vaultId: lease.vaultId,
        ttlSeconds: lease.ttlSeconds,
        expiresAt: new Date(lease.expiresAtMs).toISOString(),
      };
    } finally {
      zeroizeBuffer(plaintextBytes);
    }
  }

  /**
   * Internal helper to resolve a map of strings containing `{{vault:sec_<ulid>}}` or
   * `{{vault:lease_<ulid>}}` (or bare `sec_`/`lease_` IDs), returning the resolved map,
   * active secret descriptors for output scrubbing, and a cleanup callback that zeroizes
   * all transient decrypted buffers.
   */
  private async resolveSecretMapForExecution(entries: Readonly<Record<string, string>>): Promise<{
    resolvedMap: Record<string, string>;
    activeSecrets: ActiveSecretDescriptor[];
    cleanup: () => void;
  }> {
    const transientBuffers: Uint8Array[] = [];
    const activeSecrets: ActiveSecretDescriptor[] = [];
    const decryptedById = new Map<string, Uint8Array>();

    try {
      // Pre-scan all referenced handles across all entry values
      for (const rawValue of Object.values(entries)) {
        const direct = parseOpaqueHandle(rawValue);
        const handleMatches = direct
          ? [direct.id]
          : Array.from(
              rawValue.matchAll(/\{\{vault:((?:sec|lease)_[0-7][0-9a-hjkmnp-tv-z]{25})\}\}/g),
              (m) => m[1]!,
            );

        for (const id of handleMatches) {
          if (decryptedById.has(id)) {
            continue;
          }
          if (isValidId(id, "sec")) {
            const { plaintextBytes } = await this.decryptSecretPayloadBytes(id);
            transientBuffers.push(plaintextBytes);
            decryptedById.set(id, plaintextBytes);
            activeSecrets.push({ id, valueBytes: plaintextBytes });
          } else if (isValidId(id, "lease")) {
            const leaseData = this.leaseManager.resolveLeaseBytes(id);
            const copy = new Uint8Array(leaseData.valueBytes.byteLength);
            copy.set(leaseData.valueBytes);
            transientBuffers.push(copy);
            decryptedById.set(id, copy);
            activeSecrets.push({ id: leaseData.secretId, valueBytes: copy });
            activeSecrets.push({ id: leaseData.leaseId, valueBytes: copy });
          }
        }
      }

      const resolvedMap: Record<string, string> = {};
      for (const [key, rawValue] of Object.entries(entries)) {
        const { resolved } = resolveTemplateHandles(rawValue, (id) => {
          const bytes = decryptedById.get(id);
          if (!bytes) {
            throw new Error(`Unresolved secret or lease handle: ${id}`);
          }
          return bytes;
        });
        resolvedMap[key] = resolved;
      }

      return {
        resolvedMap,
        activeSecrets,
        cleanup: () => {
          for (const buf of transientBuffers) {
            zeroizeBuffer(buf);
          }
        },
      };
    } catch (err) {
      for (const buf of transientBuffers) {
        zeroizeBuffer(buf);
      }
      throw err;
    }
  }

  /**
   * Executes a subprocess with `sec_<ulid>` / `lease_<ulid>` handles injected into `env`
   * and scrubs `stdout` and `stderr` across raw UTF-8, Base64, and URL-encoded forms.
   */
  public async runCommandWithInjectedSecrets(params: {
    command: string;
    args?: ReadonlyArray<string> | undefined;
    env: Readonly<Record<string, string>>;
    cwd?: string | undefined;
  }): Promise<{
    exitCode: number;
    stdout: string;
    stderr: string;
    injectedEnvKeys: string[];
  }> {
    this.assertScope("agent:exec:run");
    const { resolvedMap, activeSecrets, cleanup } = await this.resolveSecretMapForExecution(
      params.env,
    );
    try {
      const execResult = await this.commandRunner(
        params.command,
        params.args ?? [],
        resolvedMap,
        params.cwd,
      );
      const scrubbedStdout = scrubSecretsFromText(execResult.stdout, activeSecrets);
      const scrubbedStderr = scrubSecretsFromText(execResult.stderr, activeSecrets);
      await this.appendAuditEvent("agent:exec:run", params.command);

      return {
        exitCode: execResult.exitCode,
        stdout: scrubbedStdout,
        stderr: scrubbedStderr,
        injectedEnvKeys: Object.keys(params.env),
      };
    } finally {
      cleanup();
    }
  }

  /**
   * Executes an outbound HTTP request with `{{vault:sec_<ulid>}}` / `{{vault:lease_<ulid>}}`
   * resolved in headers, scrubbing any echoed credentials from response headers and body.
   */
  public async executeHttpProxy(params: {
    url: string;
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | undefined;
    headers: Readonly<Record<string, string>>;
    body?: string | undefined;
  }): Promise<HttpProxyResponse> {
    this.assertScope("agent:exec:http_proxy");
    const { resolvedMap, activeSecrets, cleanup } = await this.resolveSecretMapForExecution(
      params.headers,
    );
    try {
      const response = await this.httpFetcher(params.url, {
        method: params.method ?? "GET",
        headers: resolvedMap,
        body: params.body,
      });

      const safeHeaders = scrubHeaders(response.headers, activeSecrets);
      const safeBody = scrubSecretsFromText(response.body, activeSecrets);
      await this.appendAuditEvent("agent:exec:http_proxy", params.url);

      return {
        status: response.status,
        statusText: response.statusText,
        headers: safeHeaders,
        body: safeBody,
      };
    } finally {
      cleanup();
    }
  }

  /**
   * Generates a high-entropy secret inside `llm-vault-mcp` via `crypto.getRandomValues()`,
   * encrypts it with the target vault's `VaultKey` + canonical AAD, zeroes the transient buffer,
   * and returns ONLY `{ id, vaultId, version, handle }` to the agent.
   */
  public async generateAndStoreSecret(params: {
    vaultId?: PrefixedId<"vlt"> | undefined;
    secretId?: PrefixedId<"sec"> | undefined;
    name: string;
    description?: string | undefined;
    tags?: ReadonlyArray<string> | undefined;
    folderId?: PrefixedId<"fld"> | undefined;
    byteLength?: number | undefined;
    encoding?: "hex" | "base64url" | undefined;
  }) {
    this.assertScope("secrets:create");
    const targetVaultId = params.vaultId ?? (await this.ensureDefaultVault());
    const byteLength = params.byteLength ?? 32;
    const encoding = params.encoding ?? "base64url";

    const rawRandom = globalThis.crypto.getRandomValues(new Uint8Array(byteLength));
    const formattedSecret =
      encoding === "hex" ? bytesToHex(rawRandom) : Buffer.from(rawRandom).toString("base64url");
    const plaintextBytes = textEncoder.encode(formattedSecret);

    try {
      return await this.storeEncryptedSecret({
        vaultId: targetVaultId,
        secretId: params.secretId,
        name: params.name,
        description: params.description,
        tags: params.tags,
        folderId: params.folderId,
        plaintextBytes,
      });
    } finally {
      zeroizeBuffer(rawRandom);
      zeroizeBuffer(plaintextBytes);
    }
  }

  /**
   * Prompts a human operator out-of-band (OOB) for a secret value, encrypts it locally
   * with `VaultKey` + canonical AAD, zeroes the plaintext buffer, and returns only metadata.
   */
  public async promptSecretOob(params: {
    vaultId?: PrefixedId<"vlt"> | undefined;
    secretId?: PrefixedId<"sec"> | undefined;
    name: string;
    description?: string | undefined;
    tags?: ReadonlyArray<string> | undefined;
    folderId?: PrefixedId<"fld"> | undefined;
    promptMessage?: string | undefined;
  }) {
    this.assertScope("secrets:create");
    const targetVaultId = params.vaultId ?? (await this.ensureDefaultVault());
    const secretBytes = await this.oobSecretPromptHandler({
      vaultId: targetVaultId,
      name: params.name,
      promptMessage:
        params.promptMessage ??
        `Enter secret value for "${params.name}" in vault ${targetVaultId}:`,
    });

    try {
      if (secretBytes.byteLength === 0) {
        throw new Error("OOB secret entry returned an empty secret");
      }
      return await this.storeEncryptedSecret({
        vaultId: targetVaultId,
        secretId: params.secretId,
        name: params.name,
        description: params.description,
        tags: params.tags,
        folderId: params.folderId,
        plaintextBytes: secretBytes,
      });
    } finally {
      zeroizeBuffer(secretBytes);
    }
  }

  /**
   * Appends a tamper-evident, hash-chained `aud_<ulid>` record signed with `HMAC-SHA256`.
   */
  public async appendAuditEvent(action: string, targetId: string): Promise<AuditLogEvent> {
    const id = generateId("aud");
    const timestamp = new Date().toISOString();
    const prevEventHash =
      this.auditLogs.length > 0
        ? this.auditLogs[this.auditLogs.length - 1]!.eventHash
        : GENESIS_PREV_HASH;

    const canonicalPayload = JSON.stringify({
      id,
      timestamp,
      actorId: this.agentId,
      action,
      targetId,
      prevEventHash,
    });
    const eventHash = await computeHmacSha256Hex(this.auditLogKey, canonicalPayload);

    const event: AuditLogEvent = {
      id,
      timestamp,
      actorId: this.agentId,
      action,
      targetId,
      prevEventHash,
      eventHash,
    };
    this.auditLogs.push(event);
    return event;
  }

  /**
   * Queries read-only audit logs and verifies cryptographic hash-chain integrity (`[M-2]`, `[H-4]`).
   */
  public async queryAuditLogs(params: {
    limit?: number | undefined;
    actionFilter?: string | undefined;
  }): Promise<{
    chainValid: boolean;
    totalEvents: number;
    events: AuditLogEvent[];
  }> {
    this.assertScope("admin:audit:read");

    let expectedPrev = GENESIS_PREV_HASH;
    let chainValid = true;

    for (const evt of this.auditLogs) {
      if (evt.prevEventHash !== expectedPrev) {
        chainValid = false;
        break;
      }
      const canonicalPayload = JSON.stringify({
        id: evt.id,
        timestamp: evt.timestamp,
        actorId: evt.actorId,
        action: evt.action,
        targetId: evt.targetId,
        prevEventHash: evt.prevEventHash,
      });
      const recomputed = await computeHmacSha256Hex(this.auditLogKey, canonicalPayload);
      if (recomputed !== evt.eventHash) {
        chainValid = false;
        break;
      }
      expectedPrev = evt.eventHash;
    }

    const filtered = params.actionFilter
      ? this.auditLogs.filter((e) => e.action === params.actionFilter)
      : [...this.auditLogs];
    const limit = params.limit ?? 50;
    const events = filtered.slice(-limit);

    return {
      chainValid,
      totalEvents: this.auditLogs.length,
      events,
    };
  }
}

function jsonResult(value: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value) }],
  };
}

function errorResult(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  return {
    content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
    isError: true,
  };
}

export const REGISTERED_TOOL_NAMES = [
  "vault_status",
  "vault_search",
  "vault_list_tags",
  "vault_get_secret",
  "vault_lease_secret",
  "vault_run_command",
  "vault_inject_env",
  "vault_http_proxy",
  "vault_generate_and_store_secret",
  "vault_prompt_secret_oob",
  "vault_admin_audit_logs",
] as const;

/**
 * Creates and configures the `llm-vault-mcp` server instance with all zero-context tools.
 * Note: Administrative user, role, and IdP mutation tools are intentionally excluded (`[H-4]`).
 */
export function createVaultMcpServer(runtime: VaultRuntime = new VaultRuntime()): McpServer {
  const server = new McpServer({
    name: "llm-vault-mcp",
    version: "0.1.0",
  });

  server.registerTool(
    "vault_status",
    {
      description:
        "Query active MCP vault connection status, agt_<ulid> identity, OS keychain unlock state, and permission scopes.",
      inputSchema: {},
    },
    async () => jsonResult(runtime.getStatus()),
  );

  server.registerTool(
    "vault_search",
    {
      description:
        "Search accessible vaults by keyword, tag blind index, or folder. Decrypts item metadata locally and returns safe summaries with opaque handles.",
      inputSchema: {
        query: z.string().optional(),
        tag: z.string().min(1).optional(),
        vaultId: prefixedIdSchema("vlt").optional(),
        folderId: prefixedIdSchema("fld").optional(),
      },
    },
    async (args) => {
      try {
        return jsonResult(await runtime.searchSecrets(args));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "vault_list_tags",
    {
      description: "List unique decrypted tag labels across accessible vaults.",
      inputSchema: {
        vaultId: prefixedIdSchema("vlt").optional(),
      },
    },
    async ({ vaultId }) => {
      try {
        return jsonResult({ tags: await runtime.listTags(vaultId) });
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "vault_get_secret",
    {
      description:
        "Resolve a secret by sec_<ulid> and return an opaque surrogate handle ({{vault:sec_<ulid>}}) by default. Raw plaintext reveal is blocked unless break-glass policy and out-of-band human confirmation are satisfied.",
      inputSchema: {
        secretId: prefixedIdSchema("sec"),
        requestRawPlaintext: z.boolean().optional(),
        breakGlassReason: z.string().min(1).optional(),
      },
    },
    async (args) => {
      try {
        return jsonResult(await runtime.getSecret(args));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "vault_lease_secret",
    {
      description:
        "Acquire a time-bounded lease_<ulid> handle holding decrypted secret bytes in MCP memory. Automatically zeroes the buffer upon TTL expiration.",
      inputSchema: {
        secretId: prefixedIdSchema("sec"),
        ttlSeconds: z
          .number()
          .int()
          .min(MIN_LEASE_TTL_SECONDS)
          .max(MAX_LEASE_TTL_SECONDS)
          .default(DEFAULT_LEASE_TTL_SECONDS)
          .optional(),
      },
    },
    async (args) => {
      try {
        return jsonResult(await runtime.leaseSecret(args));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  const execInputSchema = {
    command: z.string().min(1),
    args: z.array(z.string()).optional(),
    env: z.record(z.string(), z.string()),
    cwd: z.string().min(1).optional(),
  };

  server.registerTool(
    "vault_run_command",
    {
      description:
        "Execute a subprocess with {{vault:sec_<ulid>}} or {{vault:lease_<ulid>}} handles injected into environment variables, scrubbing stdout and stderr for raw, Base64, and URL-encoded secret leaks.",
      inputSchema: execInputSchema,
    },
    async (args) => {
      try {
        return jsonResult(await runtime.runCommandWithInjectedSecrets(args));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "vault_inject_env",
    {
      description:
        "Resolve opaque secret or lease handles into a subprocess execution environment and return scrubbed command output.",
      inputSchema: execInputSchema,
    },
    async (args) => {
      try {
        return jsonResult(await runtime.runCommandWithInjectedSecrets(args));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "vault_http_proxy",
    {
      description:
        "Execute an outbound HTTP request with {{vault:sec_<ulid>}} or {{vault:lease_<ulid>}} handles injected into request headers and scrub echoed credentials from response headers and body.",
      inputSchema: {
        url: z.string().url(),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).optional(),
        headers: z.record(z.string(), z.string()),
        body: z.string().optional(),
      },
    },
    async (args) => {
      try {
        return jsonResult(await runtime.executeHttpProxy(args));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "vault_generate_and_store_secret",
    {
      description:
        "Generate a high-entropy secret inside llm-vault-mcp via crypto.getRandomValues(), encrypt it locally with VaultKey and canonical AAD, and return only { id, vaultId, version, handle }.",
      inputSchema: {
        vaultId: prefixedIdSchema("vlt").optional(),
        secretId: prefixedIdSchema("sec").optional(),
        name: z.string().min(1),
        description: z.string().optional(),
        tags: z.array(z.string().min(1)).optional(),
        folderId: prefixedIdSchema("fld").optional(),
        byteLength: z.number().int().min(16).max(256).optional(),
        encoding: z.enum(["hex", "base64url"]).optional(),
      },
    },
    async (args) => {
      try {
        return jsonResult(await runtime.generateAndStoreSecret(args));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "vault_prompt_secret_oob",
    {
      description:
        "Prompt a human operator out-of-band (OOB) to enter a secret directly into client-side WebCrypto encryption without exposing the value in chat context.",
      inputSchema: {
        vaultId: prefixedIdSchema("vlt").optional(),
        secretId: prefixedIdSchema("sec").optional(),
        name: z.string().min(1),
        description: z.string().optional(),
        tags: z.array(z.string().min(1)).optional(),
        folderId: prefixedIdSchema("fld").optional(),
        promptMessage: z.string().min(1).optional(),
      },
    },
    async (args) => {
      try {
        return jsonResult(await runtime.promptSecretOob(args));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "vault_admin_audit_logs",
    {
      description:
        "Read-only query and HMAC-SHA256 hash-chain verification of aud_<ulid> audit logs for ComplianceAuditor tokens. User, role, and IdP admin mutations are excluded from MCP.",
      inputSchema: {
        limit: z.number().int().min(1).max(500).optional(),
        actionFilter: z.string().min(1).optional(),
      },
    },
    async (args) => {
      try {
        return jsonResult(await runtime.queryAuditLogs(args));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  return server;
}
