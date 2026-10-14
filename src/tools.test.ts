import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";

import {
  createVaultMcpServer,
  REGISTERED_TOOL_NAMES,
  VaultRuntime,
  type VaultRuntimeOptions,
} from "./tools.js";
import { assertSupportedTransport } from "./transports.js";

const encoder = new TextEncoder();

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

  it("validates supported MCP transports and rejects deprecated SSE", () => {
    expect(assertSupportedTransport("stdio")).toBe("stdio");
    expect(assertSupportedTransport("streamable-http")).toBe("streamable-http");
    expect(() => assertSupportedTransport("sse")).toThrow(/deprecated/);
    expect(() => assertSupportedTransport("unknown")).toThrow(/Unsupported MCP transport/);
  });
});
