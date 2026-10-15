import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";

import { buildAgentKeyWrapAad, formatApiEnvelope, wrapVaultKeyForAgent } from "./crypto.js";
import { generateId } from "./ids.js";
import {
  createVaultMcpServer,
  REGISTERED_TOOL_NAMES,
  VaultRuntime,
  type HttpFetcher,
  type VaultRuntimeOptions,
} from "./tools.js";
import { assertSupportedTransport } from "./transports.js";

const encoder = new TextEncoder();
const textDecoder = new TextDecoder();

async function createConnectedTestPair(options: VaultRuntimeOptions = {}) {
  const runtime = new VaultRuntime(options);
  const vaultId = await runtime.ensureDefaultVault();
  const server = createVaultMcpServer(runtime);
  const client = new Client({ name: "test-agent-client", version: "0.1.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { runtime, vaultId, server, client };
}

function parseToolJson<T>(result: Awaited<ReturnType<Client["callTool"]>>): T {
  const content = result.content as Array<{ type: string; text: string }>;
  return JSON.parse(content[0]!.text) as T;
}

describe("llm-vault-mcp zero-context tool contracts", () => {
  it("registers the exact zero-context tool catalog and excludes admin user/role/IdP mutation tools", async () => {
    const { client } = await createConnectedTestPair();
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);

    expect(names.sort()).toEqual([...REGISTERED_TOOL_NAMES].sort());
    expect(names).not.toContain("vault_admin_create_user");
    expect(names).not.toContain("vault_admin_list_users");
    expect(names).not.toContain("vault_admin_update_role");
    expect(names).not.toContain("vault_admin_update_idp");
  });

  it("generates secrets locally, searches via blind-indexed tags, and returns opaque handles by default", async () => {
    const { client, vaultId } = await createConnectedTestPair();

    const genRes = await client.callTool({
      name: "vault_generate_and_store_secret",
      arguments: {
        vaultId,
        name: "Stripe Production Key",
        description: "Primary billing webhook secret",
        tags: ["Production", "Billing"],
        byteLength: 32,
        encoding: "hex",
      },
    });
    const created = parseToolJson<{
      id: string;
      vaultId: string;
      version: number;
      handle: string;
    }>(genRes);

    expect(created.id).toMatch(/^sec_[0-7][0-9a-hjkmnp-tv-z]{25}$/);
    expect(created.version).toBe(1);
    expect(created.handle).toBe(`{{vault:${created.id}}}`);
    // Ensure generated secret value is never returned in tool output
    expect(JSON.stringify(created)).not.toContain("plaintext");

    const tagsRes = await client.callTool({
      name: "vault_list_tags",
      arguments: { vaultId },
    });
    expect(parseToolJson<{ tags: string[] }>(tagsRes).tags).toEqual(["billing", "production"]);

    const searchRes = await client.callTool({
      name: "vault_search",
      arguments: { tag: "BILLING", query: "stripe" },
    });
    const matches = parseToolJson<Array<{ id: string; name: string; handle: string }>>(searchRes);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.id).toBe(created.id);
    expect(matches[0]?.handle).toBe(created.handle);

    // Default vault_get_secret returns opaque handle with redacted: true
    const getRes = await client.callTool({
      name: "vault_get_secret",
      arguments: { secretId: created.id },
    });
    const got = parseToolJson<{
      id: string;
      handle: string;
      redacted: boolean;
      plaintextValue?: string;
    }>(getRes);
    expect(got.handle).toBe(created.handle);
    expect(got.redacted).toBe(true);
    expect(got.plaintextValue).toBeUndefined();

    // Requesting raw plaintext when allowRawContextReveal is false is blocked
    const blockedRes = await client.callTool({
      name: "vault_get_secret",
      arguments: {
        secretId: created.id,
        requestRawPlaintext: true,
        breakGlassReason: "Trying to read raw secret",
      },
    });
    expect(blockedRes.isError).toBe(true);
    expect(parseToolJson<{ error: string }>(blockedRes).error).toContain(
      "ZERO_CONTEXT_POLICY_VIOLATION",
    );
  });

  it("enforces OOB human confirmation when break-glass raw reveal is enabled on agent policy", async () => {
    let oobApproved = false;
    const { client, runtime, vaultId } = await createConnectedTestPair({
      allowRawContextReveal: true,
      oobConfirmHandler: async () => oobApproved,
    });

    const stored = await runtime.storeEncryptedSecret({
      vaultId,
      name: "BreakGlass Secret",
      plaintextBytes: encoder.encode("top-secret-break-glass-val"),
    });

    // Denied when OOB returns false
    const deniedRes = await client.callTool({
      name: "vault_get_secret",
      arguments: {
        secretId: stored.id,
        requestRawPlaintext: true,
        breakGlassReason: "Emergency outage triage",
      },
    });
    expect(deniedRes.isError).toBe(true);
    expect(parseToolJson<{ error: string }>(deniedRes).error).toContain("OOB_APPROVAL_REQUIRED");

    // Permitted only when both allowRawContextReveal and OOB approval succeed
    oobApproved = true;
    const approvedRes = await client.callTool({
      name: "vault_get_secret",
      arguments: {
        secretId: stored.id,
        requestRawPlaintext: true,
        breakGlassReason: "Emergency outage triage",
      },
    });
    expect(approvedRes.isError).toBeFalsy();
    const revealed = parseToolJson<{ redacted: boolean; plaintextValue: string }>(approvedRes);
    expect(revealed.redacted).toBe(false);
    expect(revealed.plaintextValue).toBe("top-secret-break-glass-val");
  });

  it("injects secrets and leases into vault_run_command and scrubs raw/Base64/URL-encoded leaks", async () => {
    let capturedEnv: Record<string, string> = {};
    const rawSecretValue = "sk-ant-api03-secret-value-12345";

    const { client, vaultId } = await createConnectedTestPair({
      oobSecretPromptHandler: async () => encoder.encode(rawSecretValue),
      commandRunner: async (_cmd, _args, env) => {
        capturedEnv = env;
        const val = env.API_TOKEN ?? "";
        const b64 = Buffer.from(val, "utf8").toString("base64");
        const urlEnc = encodeURIComponent(val);
        return {
          exitCode: 0,
          stdout: `Loaded API_TOKEN=${val} and b64=${b64}`,
          stderr: `Debug trace url=${urlEnc}`,
        };
      },
    });

    const oobRes = await client.callTool({
      name: "vault_prompt_secret_oob",
      arguments: {
        vaultId,
        name: "Anthropic Key",
        tags: ["ai"],
      },
    });
    const secretMeta = parseToolJson<{ id: string; handle: string }>(oobRes);

    // Acquire a lease handle for the secret
    const leaseRes = await client.callTool({
      name: "vault_lease_secret",
      arguments: {
        secretId: secretMeta.id,
        ttlSeconds: 60,
      },
    });
    const leaseMeta = parseToolJson<{ leaseId: string; handle: string }>(leaseRes);

    // Execute command using the lease handle
    const runRes = await client.callTool({
      name: "vault_run_command",
      arguments: {
        command: "node",
        args: ["deploy.js"],
        env: {
          API_TOKEN: leaseMeta.handle,
        },
      },
    });

    const output = parseToolJson<{
      exitCode: number;
      stdout: string;
      stderr: string;
      injectedEnvKeys: string[];
    }>(runRes);

    // Subprocess received the real decrypted credential
    expect(capturedEnv.API_TOKEN).toBe(rawSecretValue);
    // LLM tool return has all raw, Base64, and URL-encoded occurrences scrubbed!
    expect(output.stdout).not.toContain(rawSecretValue);
    expect(output.stdout).not.toContain(Buffer.from(rawSecretValue).toString("base64"));
    expect(output.stderr).not.toContain(encodeURIComponent(rawSecretValue));
    expect(output.stdout).toContain(`[REDACTED:${secretMeta.id}]`);
    expect(output.stderr).toContain(`[REDACTED:${secretMeta.id}]`);
  });

  it("injects credentials into vault_http_proxy and scrubs echoed secrets from response headers and body", async () => {
    let wireHeaders: Record<string, string> = {};
    const secretToken = "ghp_verySecretGitHubTokenValue98765";

    const { client, runtime, vaultId } = await createConnectedTestPair({
      httpFetcher: async (_url, init) => {
        wireHeaders = init.headers;
        return {
          status: 200,
          statusText: "OK",
          headers: {
            "content-type": "application/json",
            "x-debug-echo": init.headers.Authorization ?? "",
          },
          body: JSON.stringify({
            ok: true,
            echoedTokenBase64: Buffer.from(secretToken).toString("base64"),
          }),
        };
      },
    });

    const stored = await runtime.storeEncryptedSecret({
      vaultId,
      name: "GitHub PAT",
      plaintextBytes: encoder.encode(secretToken),
    });

    const proxyRes = await client.callTool({
      name: "vault_http_proxy",
      arguments: {
        url: "https://api.github.com/user",
        method: "GET",
        headers: {
          Authorization: `Bearer ${stored.handle}`,
        },
      },
    });

    const httpOut = parseToolJson<{
      status: number;
      headers: Record<string, string>;
      body: string;
    }>(proxyRes);

    expect(wireHeaders.Authorization).toBe(`Bearer ${secretToken}`);
    expect(httpOut.status).toBe(200);
    expect(httpOut.headers["x-debug-echo"]).toBe(`Bearer [REDACTED:${stored.id}]`);
    expect(httpOut.body).not.toContain(Buffer.from(secretToken).toString("base64"));
    expect(httpOut.body).toContain(`[REDACTED:${stored.id}]`);
  });

  it("verifies HMAC-SHA256 hash-chained audit logs via vault_admin_audit_logs", async () => {
    const { client } = await createConnectedTestPair();

    await client.callTool({
      name: "vault_generate_and_store_secret",
      arguments: { name: "Audited Secret" },
    });

    const auditRes = await client.callTool({
      name: "vault_admin_audit_logs",
      arguments: { limit: 20 },
    });
    const auditData = parseToolJson<{
      chainValid: boolean;
      totalEvents: number;
      events: Array<{ id: string; action: string; prevEventHash: string; eventHash: string }>;
    }>(auditRes);

    expect(auditData.chainValid).toBe(true);
    expect(auditData.totalEvents).toBeGreaterThanOrEqual(2);
    expect(auditData.events[0]?.prevEventHash).toBe("0".repeat(64));
    expect(auditData.events[1]?.prevEventHash).toBe(auditData.events[0]?.eventHash);
  });

  it("operates in Remote API Client Mode: delegates encrypted storage and reveal while keeping decryption local", async () => {
    const agentId = generateId("agt");
    const vaultId = generateId("vlt");
    const agentDecryptionKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const rawVaultKey = globalThis.crypto.getRandomValues(new Uint8Array(32));

    // Pre-wrap VaultKey for this agent identity
    const wrapAad = buildAgentKeyWrapAad({
      tenantId: "tnt_default",
      vaultId,
      agentId,
      keyVersion: 1,
    });
    const wrappedKeyEnv = await wrapVaultKeyForAgent(agentDecryptionKey, rawVaultKey, wrapAad);
    const apiWrappedKey = formatApiEnvelope(wrappedKeyEnv, textDecoder.decode(wrapAad), 1);

    // Mock remote server state
    const remoteSecrets = new Map<string, Record<string, unknown>>();
    const postedBodies: string[] = [];

    const mockFetcher: HttpFetcher = async (url, init) => {
      expect(init.headers["authorization"]).toBe("Bearer agt_secret_token_123");

      if (url.endsWith("/api/v1/vaults") && init.method === "GET") {
        return {
          status: 200,
          statusText: "OK",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ vaults: [{ id: vaultId, keyVersion: 1 }] }),
        };
      }

      if (url.includes(`/api/v1/agents/${agentId}/vault-key`) && init.method === "GET") {
        return {
          status: 200,
          statusText: "OK",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            vaultId,
            keyVersion: 1,
            agentEncryptedVaultKey: apiWrappedKey,
          }),
        };
      }

      if (url.includes(`/api/v1/vaults/${vaultId}/secrets`) && init.method === "POST") {
        postedBodies.push(init.body!);
        const parsed = JSON.parse(init.body!);
        parsed.vaultId = vaultId;
        remoteSecrets.set(parsed.id, parsed);
        return {
          status: 201,
          statusText: "Created",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ id: parsed.id, vaultId, version: 1 }),
        };
      }

      if (url.includes(`/api/v1/vaults/${vaultId}/secrets`) && init.method === "GET") {
        return {
          status: 200,
          statusText: "OK",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ secrets: Array.from(remoteSecrets.values()) }),
        };
      }

      const revealMatch = url.match(/\/api\/v1\/secrets\/(sec_[^/]+)\/reveal$/);
      if (revealMatch && init.method === "POST") {
        const secId = revealMatch[1]!;
        const sec = remoteSecrets.get(secId);
        if (!sec) {
          return { status: 404, statusText: "Not Found", headers: {}, body: "{}" };
        }
        return {
          status: 200,
          statusText: "OK",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            id: secId,
            vaultId,
            version: 1,
            keyVersion: 1,
            encryptedPayload: sec.encryptedPayload,
            encryptedVaultKey: apiWrappedKey,
            auditEventId: generateId("aud"),
          }),
        };
      }

      return { status: 404, statusText: "Not Found", headers: {}, body: "{}" };
    };

    const { client } = await createConnectedTestPair({
      agentId,
      remoteApiUrl: "https://vault.internal.corp",
      agentToken: "agt_secret_token_123",
      agentDecryptionKey,
      httpFetcher: mockFetcher,
    });

    // 1. Generate & store secret via MCP
    const genRes = await client.callTool({
      name: "vault_generate_and_store_secret",
      arguments: {
        vaultId,
        name: "Remote Stored Database Password",
        description: "Postgres connection credential",
        tags: ["database", "postgres"],
        byteLength: 32,
      },
    });
    const created = parseToolJson<{ id: string; handle: string }>(genRes);
    expect(created.id).toMatch(/^sec_/);

    // 2. Verify that what was sent over the wire to the API server is strictly ciphertext
    expect(postedBodies).toHaveLength(1);
    const wireBody = postedBodies[0]!;
    expect(wireBody).toContain("AES-256-GCM");
    expect(wireBody).not.toContain("Remote Stored Database Password");
    expect(wireBody).not.toContain("postgres");

    // 3. Search secrets via remote API
    const searchRes = await client.callTool({
      name: "vault_search",
      arguments: { query: "postgres" },
    });
    const searchMatches = parseToolJson<Array<{ id: string; name: string }>>(searchRes);
    expect(searchMatches).toHaveLength(1);
    expect(searchMatches[0]?.id).toBe(created.id);
    expect(searchMatches[0]?.name).toBe("Remote Stored Database Password");

    // 4. Execute command injecting secret handle — resolves via remote /reveal endpoint and scrubs output
    let executedEnv: Record<string, string> = {};
    const cmdRuntime = new VaultRuntime({
      agentId,
      remoteApiUrl: "https://vault.internal.corp",
      agentToken: "agt_secret_token_123",
      agentDecryptionKey,
      httpFetcher: mockFetcher,
      commandRunner: async (_cmd, _args, env) => {
        executedEnv = env;
        return {
          exitCode: 0,
          stdout: `Exported DB_PASS=${env.DB_PASS}`,
          stderr: "",
        };
      },
    });
    const cmdServer = createVaultMcpServer(cmdRuntime);
    const cmdClient = new Client({ name: "cmd-client", version: "0.1.0" });
    const [cTrans, sTrans] = InMemoryTransport.createLinkedPair();
    await Promise.all([cmdServer.connect(sTrans), cmdClient.connect(cTrans)]);

    const runRes = await cmdClient.callTool({
      name: "vault_run_command",
      arguments: {
        command: "node",
        args: ["-e", "console.log(process.env.DB_PASS)"],
        env: {
          DB_PASS: created.handle,
        },
      },
    });

    const runOut = parseToolJson<{ exitCode: number; stdout: string }>(runRes);
    expect(runOut.exitCode).toBe(0);
    // Secret was decrypted locally and passed to child process environment
    expect(executedEnv.DB_PASS).toBeDefined();
    expect(executedEnv.DB_PASS).not.toBe(created.handle);
    // Output was scrubbed so raw secret does not leak into tool response or LLM context
    expect(runOut.stdout).toContain(`DB_PASS=[REDACTED:${created.id}]`);
  });

  it("acquires ephemeral lease and explicitly revokes it via vault_revoke_lease", async () => {
    const { client, vaultId, runtime } = await createConnectedTestPair();

    const genRes = await client.callTool({
      name: "vault_generate_and_store_secret",
      arguments: {
        vaultId,
        name: "Ephemeral API Key",
        byteLength: 32,
      },
    });
    expect(genRes.isError).toBeFalsy();
    const created = parseToolJson<{ id: string }>(genRes);

    const leaseRes = await client.callTool({
      name: "vault_lease_secret",
      arguments: {
        secretId: created.id,
        ttlSeconds: 60,
      },
    });
    expect(leaseRes.isError).toBeFalsy();
    const lease = parseToolJson<{ leaseId: string; handle: string; ttlSeconds: number }>(leaseRes);
    expect(lease.leaseId).toMatch(/^lease_[0-7][0-9a-hjkmnp-tv-z]{25}$/);
    expect(lease.handle).toBe(`{{vault:${lease.leaseId}}}`);

    // Verify lease is active in runtime
    expect(() => runtime.leaseManager.resolveLeaseBytes(lease.leaseId)).not.toThrow();

    // Explicitly revoke lease
    const revokeRes = await client.callTool({
      name: "vault_revoke_lease",
      arguments: {
        leaseId: lease.leaseId,
      },
    });
    expect(revokeRes.isError).toBeFalsy();
    const revoked = parseToolJson<{ success: boolean; leaseId: string }>(revokeRes);
    expect(revoked.success).toBe(true);
    expect(revoked.leaseId).toBe(lease.leaseId);

    // Verify lease buffer was zeroized and lease is no longer valid
    expect(() => runtime.leaseManager.resolveLeaseBytes(lease.leaseId)).toThrow(
      /expired or does not exist/,
    );

    // Revoking again returns success: false
    const revokeAgainRes = await client.callTool({
      name: "vault_revoke_lease",
      arguments: {
        leaseId: lease.leaseId,
      },
    });
    expect(revokeAgainRes.isError).toBeFalsy();
    expect(parseToolJson<{ success: boolean }>(revokeAgainRes).success).toBe(false);
  });

  it("enforces out-of-band confirmation workflow for vault_delete_secret and vault_confirm_action", async () => {
    let promptCount = 0;
    const { client, vaultId } = await createConnectedTestPair({
      scopes: [
        "secrets:create",
        "secrets:read",
        "secrets:reveal",
        "secrets:update",
        "secrets:delete",
        "agent:lease:acquire",
        "agent:exec:run",
        "agent:exec:http_proxy",
        "admin:audit:read",
      ],
      oobConfirmHandler: async () => {
        promptCount++;
        return false; // Simulate human operator not approving immediately interactively
      },
    });

    const genRes = await client.callTool({
      name: "vault_generate_and_store_secret",
      arguments: {
        vaultId,
        name: "Key to Delete",
        byteLength: 16,
      },
    });
    expect(genRes.isError).toBeFalsy();
    const created = parseToolJson<{ id: string }>(genRes);

    // 1. Initial delete attempt without confirmationToken returns pending_confirmation
    const deleteRes = await client.callTool({
      name: "vault_delete_secret",
      arguments: {
        secretId: created.id,
      },
    });
    expect(deleteRes.isError).toBeFalsy();
    const pending = parseToolJson<{
      status: string;
      confirmationToken: string;
      secretId: string;
      success: boolean;
      prompt: string;
    }>(deleteRes);

    expect(promptCount).toBe(1);
    expect(pending.status).toBe("pending_confirmation");
    expect(pending.success).toBe(false);
    expect(pending.confirmationToken).toMatch(/^conf_[0-9a-f]{32}$/);
    expect(pending.prompt).toContain("CAUTION");

    // 2. Reject pending action via vault_confirm_action
    const rejectRes = await client.callTool({
      name: "vault_confirm_action",
      arguments: {
        confirmationToken: pending.confirmationToken,
        approved: false,
      },
    });
    expect(rejectRes.isError).toBeFalsy();
    const rejected = parseToolJson<{ status: string; action: string }>(rejectRes);
    expect(rejected.status).toBe("cancelled");
    expect(rejected.action).toBe("delete_secret");

    // 3. New delete attempt generates a fresh confirmation token
    const deleteRes2 = await client.callTool({
      name: "vault_delete_secret",
      arguments: {
        secretId: created.id,
      },
    });
    expect(deleteRes2.isError).toBeFalsy();
    const pending2 = parseToolJson<{ confirmationToken: string }>(deleteRes2);

    // 4. Confirm deletion via vault_confirm_action with approved: true
    const confirmRes = await client.callTool({
      name: "vault_confirm_action",
      arguments: {
        confirmationToken: pending2.confirmationToken,
        approved: true,
      },
    });
    expect(confirmRes.isError).toBeFalsy();
    const confirmed = parseToolJson<{ status: string; success: boolean; secretId: string }>(
      confirmRes,
    );
    expect(confirmed.status).toBe("deleted");
    expect(confirmed.success).toBe(true);
    expect(confirmed.secretId).toBe(created.id);

    // 5. Verify secret is gone
    const searchRes = await client.callTool({
      name: "vault_search",
      arguments: { query: "Key to Delete" },
    });
    expect(searchRes.isError).toBeFalsy();
    expect(parseToolJson<unknown[]>(searchRes)).toHaveLength(0);
  });

  it("enforces out-of-band confirmation workflow for break-glass raw secret reveal", async () => {
    const { client, vaultId } = await createConnectedTestPair({
      allowRawContextReveal: true,
      oobConfirmHandler: async () => false, // Require OOB confirmation token
    });

    const genRes = await client.callTool({
      name: "vault_generate_and_store_secret",
      arguments: {
        vaultId,
        name: "Emergency API Key",
        byteLength: 16,
      },
    });
    expect(genRes.isError).toBeFalsy();
    const created = parseToolJson<{ id: string }>(genRes);

    // Attempt break-glass reveal without pre-approval
    const revealAttempt = await client.callTool({
      name: "vault_get_secret",
      arguments: {
        secretId: created.id,
        requestRawPlaintext: true,
        breakGlassReason: "Emergency outage investigation",
      },
    });

    expect(revealAttempt.isError).toBe(true);
    const content = revealAttempt.content as Array<{ type: string; text: string }>;
    const errMessage = content[0]?.text ?? "";

    expect(errMessage).toContain("OOB_APPROVAL_REQUIRED");
    const tokenMatch = errMessage.match(/conf_[0-9a-f]{32}/);
    expect(tokenMatch).not.toBeNull();
    const confirmationToken = tokenMatch![0];

    // Approve the break-glass action via vault_confirm_action
    const confirmRes = await client.callTool({
      name: "vault_confirm_action",
      arguments: {
        confirmationToken,
        approved: true,
      },
    });

    expect(confirmRes.isError).toBeFalsy();
    const revealed = parseToolJson<{
      id: string;
      plaintextValue: string;
      redacted: boolean;
    }>(confirmRes);

    expect(revealed.id).toBe(created.id);
    expect(revealed.redacted).toBe(false);
    expect(revealed.plaintextValue).toBeDefined();
    expect(revealed.plaintextValue.length).toBeGreaterThan(0);
  });

  it("red-teams prompt injection attacks by scrubbing raw, base64, and url-encoded secret echoes across stdout, stderr, and headers", async () => {
    let capturedEnv: Record<string, string> = {};
    const { client, vaultId } = await createConnectedTestPair({
      commandRunner: async (_cmd, _args, env) => {
        capturedEnv = env;
        const rawSecret = env.TARGET_SECRET || "";
        const b64Secret = Buffer.from(rawSecret, "utf-8").toString("base64");
        const urlSecret = encodeURIComponent(rawSecret);

        return {
          exitCode: 0,
          stdout: `Injected stdout raw: "${rawSecret}", base64: "${b64Secret}", url: "${urlSecret}"`,
          stderr: `Injected stderr raw: "${rawSecret}", base64: "${b64Secret}", url: "${urlSecret}"`,
        };
      },
    });

    const genRes = await client.callTool({
      name: "vault_generate_and_store_secret",
      arguments: {
        vaultId,
        name: "High Entropy Target Secret",
        byteLength: 24,
      },
    });
    const created = parseToolJson<{ id: string; handle: string }>(genRes);

    const runRes = await client.callTool({
      name: "vault_run_command",
      arguments: {
        command: "sh",
        args: ["-c", "echo $TARGET_SECRET"],
        env: {
          TARGET_SECRET: created.handle,
        },
      },
    });

    const output = parseToolJson<{ exitCode: number; stdout: string; stderr: string }>(runRes);
    const rawPlaintext = capturedEnv.TARGET_SECRET;
    expect(rawPlaintext).toBeDefined();
    expect(rawPlaintext!.length).toBeGreaterThan(10);

    // Verify raw secret does NOT appear in stdout or stderr
    expect(output.stdout).not.toContain(rawPlaintext);
    expect(output.stderr).not.toContain(rawPlaintext);

    // Verify Base64 and URL encoded variants are also redacted
    const b64 = Buffer.from(rawPlaintext!, "utf-8").toString("base64");
    const urlEnc = encodeURIComponent(rawPlaintext!);
    expect(output.stdout).not.toContain(b64);
    expect(output.stdout).not.toContain(urlEnc);
    expect(output.stderr).not.toContain(b64);
    expect(output.stderr).not.toContain(urlEnc);

    // Verify redaction placeholder format
    expect(output.stdout).toContain(`[REDACTED:${created.id}]`);
    expect(output.stderr).toContain(`[REDACTED:${created.id}]`);
  });

  describe("Slice 9: Workspace Secret Scanner, Absorption & Git Hooks", () => {
    it("scans content and workspace for unencrypted credentials via vault_scan_workspace", async () => {
      const { client } = await createConnectedTestPair();

      const mockOpenAi = ["sk", "proj", "TestingScannerOpenAiKey1234567890abcdef"].join("-");
      const mockAnthropic = ["sk", "ant", "api03", "TestingScannerClaudeKey1234567890"].join("-");
      const sampleCode = [
        `const openAi = "${mockOpenAi}";`,
        `const anthropic = "${mockAnthropic}";`,
        'const aws = "AKIAIOSFODNN7EXAMPLE";',
        'const safe = "{{vault:sec_01jk9876543210abcdefghij}}";',
      ].join("\n");

      const scanRes = await client.callTool({
        name: "vault_scan_workspace",
        arguments: {
          content: sampleCode,
          path: "src/test-config.ts",
        },
      });

      expect(scanRes.isError).toBeFalsy();
      const result = parseToolJson<{
        scannedFiles: number;
        findingsCount: number;
        clean: boolean;
        findings: Array<{
          ruleId: string;
          redactedValue: string;
          suggestedHandle: string;
        }>;
      }>(scanRes);

      expect(result.clean).toBe(false);
      expect(result.findingsCount).toBe(3);
      expect(result.findings.map((f) => f.ruleId)).toContain("openai-api-key");
      expect(result.findings.map((f) => f.ruleId)).toContain("anthropic-api-key");
      expect(result.findings.map((f) => f.ruleId)).toContain("aws-access-key-id");
      for (const f of result.findings) {
        expect(f.redactedValue).toContain("****");
        expect(f.suggestedHandle).toMatch(/^\{\{vault:sec_[0-9a-zA-Z]{26}\}\}$/);
      }
    });

    it("absorbs plaintext credentials into vault records and creates template via vault_absorb_credentials", async () => {
      const { client, vaultId } = await createConnectedTestPair();
      const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "mcp-absorb-test-"));
      const envPath = path.join(tempDir, ".env");

      try {
        const mockOpenAi = ["sk", "proj", "AbsorbMcpTestKey1234567890abcdef"].join("-");
        const mockGithub = ["ghp", "AbsorbMcpGithubToken1234567890abcdef"].join("_");
        fs.writeFileSync(
          envPath,
          ["# Service Keys", `OPENAI_API_KEY=${mockOpenAi}`, `GITHUB_TOKEN=${mockGithub}`].join(
            "\n",
          ),
        );

        // 1. Dry run
        const dryRes = await client.callTool({
          name: "vault_absorb_credentials",
          arguments: {
            filePath: envPath,
            dryRun: true,
            vaultId,
          },
        });
        expect(dryRes.isError).toBeFalsy();
        const dryResult = parseToolJson<{
          success: boolean;
          dryRun: boolean;
          absorbedCount: number;
          actions: Array<{ secretName: string; handle: string }>;
        }>(dryRes);
        expect(dryResult.dryRun).toBe(true);
        expect(dryResult.absorbedCount).toBe(2);

        // 2. Live absorb
        const liveRes = await client.callTool({
          name: "vault_absorb_credentials",
          arguments: {
            filePath: envPath,
            dryRun: false,
            vaultId,
          },
        });
        expect(liveRes.isError).toBeFalsy();
        const liveResult = parseToolJson<{
          success: boolean;
          dryRun: boolean;
          absorbedCount: number;
          actions: Array<{ secretName: string; secretId: string; handle: string }>;
        }>(liveRes);
        expect(liveResult.dryRun).toBe(false);
        expect(liveResult.absorbedCount).toBe(2);

        // Verify template file was generated
        const tplPath = `${envPath}.tpl`;
        expect(fs.existsSync(tplPath)).toBe(true);
        const tplContent = fs.readFileSync(tplPath, "utf8");
        expect(tplContent).toContain("OPENAI_API_KEY={{vault:sec_");
        expect(tplContent).toContain("GITHUB_TOKEN={{vault:sec_");

        // Verify newly absorbed secrets can be queried via vault_get_secret
        const firstSecId = liveResult.actions[0]!.secretId;
        const getRes = await client.callTool({
          name: "vault_get_secret",
          arguments: { secretId: firstSecId },
        });
        expect(getRes.isError).toBeFalsy();
        const getResult = parseToolJson<{ handle: string }>(getRes);
        expect(getResult.handle).toBe(`{{vault:${firstSecId}}}`);
      } finally {
        await fs.promises.rm(tempDir, { recursive: true, force: true });
      }
    });

    it("manages git pre-commit hooks via vault_install_pre_commit_hook", async () => {
      const { client } = await createConnectedTestPair();
      const mockGitRepo = await fs.promises.mkdtemp(path.join(os.tmpdir(), "mcp-hook-test-"));
      fs.mkdirSync(path.join(mockGitRepo, ".git", "hooks"), { recursive: true });

      try {
        // 1. Initial status
        const statusRes = await client.callTool({
          name: "vault_install_pre_commit_hook",
          arguments: {
            action: "status",
            workspaceDir: mockGitRepo,
          },
        });
        expect(statusRes.isError).toBeFalsy();
        expect(parseToolJson<{ installed: boolean }>(statusRes).installed).toBe(false);

        // 2. Install hook
        const installRes = await client.callTool({
          name: "vault_install_pre_commit_hook",
          arguments: {
            action: "install",
            workspaceDir: mockGitRepo,
          },
        });
        expect(installRes.isError).toBeFalsy();
        const installResult = parseToolJson<{ installed: boolean; isLlmVaultHook: boolean }>(
          installRes,
        );
        expect(installResult.installed).toBe(true);
        expect(installResult.isLlmVaultHook).toBe(true);

        // 3. Remove hook
        const removeRes = await client.callTool({
          name: "vault_install_pre_commit_hook",
          arguments: {
            action: "remove",
            workspaceDir: mockGitRepo,
          },
        });
        expect(removeRes.isError).toBeFalsy();
        expect(parseToolJson<{ installed: boolean }>(removeRes).installed).toBe(false);
      } finally {
        await fs.promises.rm(mockGitRepo, { recursive: true, force: true });
      }
    });
  });

  it("validates supported MCP transports and rejects deprecated SSE", () => {
    expect(assertSupportedTransport("stdio")).toBe("stdio");
    expect(assertSupportedTransport("streamable-http")).toBe("streamable-http");
    expect(() => assertSupportedTransport("sse")).toThrow(/deprecated/);
    expect(() => assertSupportedTransport("unknown")).toThrow(/Unsupported MCP transport/);
  });
});
