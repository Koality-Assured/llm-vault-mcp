import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { createVaultMcpServer, VaultRuntime } from "./tools.js";
import {
  assertSupportedTransport,
  getDefaultSocketPath,
  prepareSocketPath,
  resolveSocketPath,
  secureSocketPermissions,
} from "./transports.js";

describe("MCP Transports & Socket Isolation (Slice 2)", () => {
  describe("assertSupportedTransport", () => {
    it("accepts stdio, streamable-http, and socket", () => {
      expect(assertSupportedTransport("stdio")).toBe("stdio");
      expect(assertSupportedTransport("streamable-http")).toBe("streamable-http");
      expect(assertSupportedTransport("socket")).toBe("socket");
    });

    it("rejects deprecated SSE transports with actionable migration message", () => {
      expect(() => assertSupportedTransport("sse")).toThrow(/deprecated/i);
      expect(() => assertSupportedTransport("http+sse")).toThrow(/deprecated/i);
      expect(() => assertSupportedTransport("http-sse")).toThrow(/deprecated/i);
    });

    it("rejects unknown transports", () => {
      expect(() => assertSupportedTransport("grpc")).toThrow(/unsupported/i);
      expect(() => assertSupportedTransport("websocket")).toThrow(/unsupported/i);
    });
  });

  describe("Socket Path Resolution & Permissions", () => {
    it("returns named pipe path on win32", () => {
      const p = getDefaultSocketPath("win32");
      expect(p).toBe("\\\\.\\pipe\\llm-vault-mcp");
    });

    it("returns ~/.llm-vault/mcp.sock on unix/darwin", () => {
      const p = getDefaultSocketPath("linux");
      expect(p).toContain(".llm-vault");
      expect(p.endsWith("mcp.sock")).toBe(true);
    });

    it("prioritizes explicit argument over env and default", () => {
      const explicit = resolveSocketPath("/tmp/custom.sock");
      expect(explicit).toBe("/tmp/custom.sock");
    });

    it("uses MCP_SOCKET_PATH environment variable if argument is omitted", () => {
      const prevEnv = process.env.MCP_SOCKET_PATH;
      try {
        process.env.MCP_SOCKET_PATH = "/tmp/env-socket.sock";
        expect(resolveSocketPath()).toBe("/tmp/env-socket.sock");
      } finally {
        if (prevEnv !== undefined) {
          process.env.MCP_SOCKET_PATH = prevEnv;
        } else {
          delete process.env.MCP_SOCKET_PATH;
        }
      }
    });

    it("prepareSocketPath and secureSocketPermissions safely handle win32 and unix", () => {
      expect(() => prepareSocketPath("\\\\.\\pipe\\test-pipe", "win32")).not.toThrow();
      expect(() => secureSocketPermissions("\\\\.\\pipe\\test-pipe", "win32")).not.toThrow();

      const tmpSocketDir = path.join(os.tmpdir(), `llm-vlt-test-${Date.now()}`);
      const tmpSocketFile = path.join(tmpSocketDir, "test.sock");
      try {
        prepareSocketPath(tmpSocketFile, "linux");
        expect(fs.existsSync(tmpSocketDir)).toBe(true);
        fs.writeFileSync(tmpSocketFile, "dummy");
        secureSocketPermissions(tmpSocketFile, "linux");
      } finally {
        try {
          fs.rmSync(tmpSocketDir, { recursive: true, force: true });
        } catch {
          // Ignore cleanup errors
        }
      }
    });
  });

  describe("End-to-End Socket Transport Integration", () => {
    let socketServer: net.Server;
    let testSocketPath: string;
    let client: Client;
    let clientSocket: net.Socket;

    beforeAll(async () => {
      const isWindows = process.platform === "win32";
      testSocketPath = isWindows
        ? `\\\\.\\pipe\\llm-vault-test-${Date.now()}`
        : path.join(os.tmpdir(), `llm-vlt-srv-${Date.now()}.sock`);

      prepareSocketPath(testSocketPath);

      const runtime = new VaultRuntime();
      await runtime.ensureDefaultVault();

      socketServer = net.createServer(async (socket) => {
        const serverTransport = new StdioServerTransport(socket, socket);
        const server = createVaultMcpServer(runtime);
        await server.connect(serverTransport);
        socket.on("close", () => {
          void server.close();
        });
      });

      await new Promise<void>((resolve, reject) => {
        socketServer.listen(testSocketPath, () => {
          secureSocketPermissions(testSocketPath);
          resolve();
        });
        socketServer.on("error", reject);
      });

      clientSocket = await new Promise<net.Socket>((resolve, reject) => {
        const s = net.connect(testSocketPath, () => resolve(s));
        s.on("error", reject);
      });

      const clientTransport = new StdioServerTransport(clientSocket, clientSocket);
      client = new Client({ name: "test-client", version: "1.0.0" }, { capabilities: {} });
      await client.connect(clientTransport);
    });

    afterAll(async () => {
      try {
        await client.close();
      } catch {
        void 0;
      }
      try {
        clientSocket.destroy();
      } catch {
        void 0;
      }
      await new Promise<void>((resolve) => {
        socketServer.close(() => {
          if (process.platform !== "win32") {
            try {
              fs.rmSync(testSocketPath, { force: true });
            } catch {
              void 0;
            }
          }
          resolve();
        });
      });
    });

    it("connects over socket and lists all zero-context MCP tools", async () => {
      const response = await client.listTools();
      const toolNames = response.tools.map((t) => t.name);

      expect(toolNames).toContain("vault_status");
      expect(toolNames).toContain("vault_search");
      expect(toolNames).toContain("vault_list_tags");
      expect(toolNames).toContain("vault_get_secret");
      expect(toolNames).toContain("vault_lease_secret");
      expect(toolNames).toContain("vault_run_command");
      expect(toolNames).toContain("vault_http_proxy");
      expect(toolNames).toContain("vault_generate_and_store_secret");
      expect(toolNames).toContain("vault_prompt_secret_oob");
      expect(toolNames).toContain("vault_admin_audit_logs");

      // Verify destructive administrative mutation tools are absent from MCP
      expect(toolNames).not.toContain("vault_admin_create_user");
      expect(toolNames).not.toContain("vault_admin_delete_user");
    });

    it("executes vault_status over the socket transport", async () => {
      const statusRes = await client.callTool({
        name: "vault_status",
        arguments: {},
      });
      expect(statusRes.isError).toBeFalsy();
      const content = statusRes.content as Array<{ type: string; text: string }>;
      const parsed = JSON.parse(content[0]!.text) as { status: string; keychainUnlocked: boolean };
      expect(parsed.status).toBe("ready");
      expect(parsed.keychainUnlocked).toBe(true);
    });
  });
});
