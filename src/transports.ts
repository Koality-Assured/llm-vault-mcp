import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** Transports this server is allowed to expose. HTTP+SSE is intentionally absent. */
export const SUPPORTED_TRANSPORTS = ["stdio", "streamable-http", "socket"] as const;

export type TransportName = (typeof SUPPORTED_TRANSPORTS)[number];

const DEPRECATED = new Set(["sse", "http+sse", "http-sse"]);

export function assertSupportedTransport(name: string): TransportName {
  if (DEPRECATED.has(name)) {
    throw new Error(
      `Transport "${name}" is deprecated. Use stdio locally or Streamable HTTP for remote access.`,
    );
  }
  if (name !== "stdio" && name !== "streamable-http" && name !== "socket") {
    throw new Error(`Unsupported MCP transport: ${name}`);
  }
  return name;
}

export function getDefaultSocketPath(platform: NodeJS.Platform = process.platform): string {
  if (platform === "win32") {
    return "\\\\.\\pipe\\llm-vault-mcp";
  }
  return path.join(os.homedir(), ".llm-vault", "mcp.sock");
}

export function resolveSocketPath(
  customPath?: string,
  platform: NodeJS.Platform = process.platform,
): string {
  if (customPath && customPath.trim().length > 0) {
    return customPath.trim();
  }
  if (process.env.MCP_SOCKET_PATH && process.env.MCP_SOCKET_PATH.trim().length > 0) {
    return process.env.MCP_SOCKET_PATH.trim();
  }
  return getDefaultSocketPath(platform);
}

export function prepareSocketPath(
  socketPath: string,
  platform: NodeJS.Platform = process.platform,
): void {
  if (platform === "win32") {
    // Windows named pipes do not exist on the filesystem and cannot be deleted or chmodded
    return;
  }
  const dir = path.dirname(socketPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.rmSync(socketPath, { force: true });
  } catch {
    // Ignore if file doesn't exist
  }
}

export function secureSocketPermissions(
  socketPath: string,
  platform: NodeJS.Platform = process.platform,
): void {
  if (platform === "win32") {
    return;
  }
  try {
    fs.chmodSync(socketPath, 0o600);
  } catch (err: unknown) {
    process.stderr.write(
      `Warning: could not set 0600 permissions on socket "${socketPath}": ${err instanceof Error ? err.message : String(err)}\n`,
    );
  }
}
