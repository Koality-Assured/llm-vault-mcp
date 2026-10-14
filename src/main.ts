import { createServer } from "node:http";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { createVaultMcpServer, VaultRuntime } from "./tools.js";
import { assertSupportedTransport } from "./transports.js";

export * from "./crypto.js";
export * from "./ids.js";
export * from "./lease-manager.js";
export * from "./scrubber.js";
export * from "./tools.js";
export * from "./transports.js";

async function runCli(): Promise<void> {
  const transportName = assertSupportedTransport(process.argv[2] ?? "stdio");
  const runtime = new VaultRuntime({
    deploymentMode: process.env.DEPLOYMENT_MODE === "enterprise" ? "enterprise" : "standalone",
  });
  await runtime.ensureDefaultVault();
  const server = createVaultMcpServer(runtime);

  if (transportName === "stdio") {
    await server.connect(new StdioServerTransport());
    return;
  }

  const token = process.env.MCP_TOKEN;
  if (!token) {
    process.stderr.write(
      "MCP_TOKEN environment variable must be set for streamable-http transport.\n",
    );
    process.exit(1);
  }

  const port = parseInt(process.env.PORT || "3000", 10);
  const host = process.env.HOST || "127.0.0.1";

  const transport = new StreamableHTTPServerTransport();

  const httpServer = createServer(async (req, res) => {
    const hostHeader = req.headers.host;
    const allowedHosts = [
      `localhost:${port}`,
      `127.0.0.1:${port}`,
      `[::1]:${port}`,
      host,
      `${host}:${port}`,
    ];
    if (hostHeader && !allowedHosts.includes(hostHeader)) {
      res.writeHead(403);
      res.end("Invalid Host header");
      return;
    }

    const origin = req.headers.origin;
    if (origin) {
      try {
        const originUrl = new URL(origin);
        if (!allowedHosts.includes(originUrl.host)) {
          res.writeHead(403);
          res.end("Invalid Origin");
          return;
        }
      } catch {
        res.writeHead(403);
        res.end("Invalid Origin");
        return;
      }
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${token}`) {
      res.writeHead(401);
      res.end("Unauthorized");
      return;
    }

    try {
      await transport.handleRequest(req, res);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500);
        res.end("Internal error");
      }
    }
  });

  await server.connect(transport as unknown as Transport);

  httpServer.listen(port, host, () => {
    process.stderr.write(`llm-vault-mcp listening on http://${host}:${port}\n`);
  });

  const shutdown = () => {
    runtime.leaseManager.disposeAll();
    httpServer.close(async () => {
      await transport.close();
      await server.close();
      process.exit(0);
    });
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

const isMainModule =
  process.argv[1] !== undefined &&
  (process.argv[1].endsWith("main.ts") || process.argv[1].endsWith("main.js"));

if (isMainModule) {
  runCli().catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Fatal error starting llm-vault-mcp: ${message}\n`);
    process.exit(1);
  });
}
