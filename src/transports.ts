/** Transports this server is allowed to expose. HTTP+SSE is intentionally absent. */
export const SUPPORTED_TRANSPORTS = ["stdio", "streamable-http"] as const;

export type TransportName = (typeof SUPPORTED_TRANSPORTS)[number];

const DEPRECATED = new Set(["sse", "http+sse", "http-sse"]);

export function assertSupportedTransport(name: string): TransportName {
  if (DEPRECATED.has(name)) {
    throw new Error(
      `Transport "${name}" is deprecated. Use stdio locally or Streamable HTTP for remote access.`,
    );
  }
  if (name !== "stdio" && name !== "streamable-http") {
    throw new Error(`Unsupported MCP transport: ${name}`);
  }
  return name;
}
