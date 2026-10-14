# llm-vault-mcp

Model Context Protocol (MCP) server for [`llm-vault`](https://github.com/Koality-Assured/llm-vault). It decrypts secret envelopes locally via the W3C Web Cryptography API (`crypto.subtle`) and injects credentials into child processes or outbound HTTP requests without exposing plaintext secret values to LLM context windows, chat transcripts, or model telemetry.

## Architecture & Security Model

- **Local Zero-Knowledge Decryption**: The MCP process loads the workstation's `AgentDecryptionKey` (from the OS keychain or runtime secret store), unwraps the vault's `AgentEncryptedVaultKey`, and decrypts `AES-256-GCM` payloads locally. Every encryption and decryption operation binds canonical Additional Authenticated Data (`AAD`):
  ```text
  UTF8("${tenantId}:${vaultId}:${secretId}:${version}:${keyVersion}")
  ```
- **Opaque Surrogate Handles**: Discovery and secret-resolution tools return type-prefixed ULID identifiers (`sec_<ulid>`) and template handles (`{{vault:sec_<ulid>}}`, `{{vault:lease_<ulid>}}`) rather than raw secret strings.
- **Multi-Encoding Output Scrubber**: When executing commands (`vault_run_command`, `vault_inject_env`) or proxying HTTP calls (`vault_http_proxy`), the server scans `stdout`, `stderr`, and response headers for raw UTF-8, Base64-encoded, and URL-encoded occurrences of active secrets and replaces matches with `[REDACTED:<id>]`.
- **Time-Bounded Ephemeral Leases**: `vault_lease_secret` holds decrypted `Uint8Array` secret bytes in process memory under a `lease_<ulid>` handle and overwrites the buffer with zeroes (`buf.fill(0)`) immediately upon TTL expiration.
- **Admin Plane Isolation**: User provisioning, role mutation, and identity provider configuration endpoints are omitted from the MCP surface so prompt-injected agents cannot escalate privileges. Only `vault_admin_audit_logs` (read-only query and hash-chain verification) is exposed for `ComplianceAuditor` tokens.

## MCP Toolset

| Tool                              | Purpose                                                                                                                                                                |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vault_status`                    | Report active vault connection, `agt_<ulid>` identity, keychain state, and permission scopes.                                                                          |
| `vault_search`                    | Search decrypted item metadata (`name`, `description`, `tags`, `folder_id`) and return safe item summaries.                                                            |
| `vault_list_tags`                 | List unique tags across accessible vaults.                                                                                                                             |
| `vault_get_secret`                | Return an opaque `{{vault:sec_<ulid>}}` handle and metadata summary. Blocks raw plaintext unless break-glass policy and out-of-band human approval are both satisfied. |
| `vault_lease_secret`              | Issue a time-bounded `lease_<ulid>` handle backed by an in-memory `Uint8Array` that auto-zeroizes on TTL expiry.                                                       |
| `vault_run_command`               | Spawn a subprocess with `{{vault:sec_...}}` or `lease_<ulid>` handles injected into environment variables, scrubbing `stdout` and `stderr` before returning.           |
| `vault_inject_env`                | Alias/companion execution tool that resolves secret handles into an execution environment map and scrubs command output.                                               |
| `vault_http_proxy`                | Execute an outbound HTTP request with secret handles resolved inside request headers and scrub echoed credentials from response headers and body.                      |
| `vault_generate_and_store_secret` | Generate a high-entropy secret inside the MCP server via `crypto.getRandomValues()`, encrypt it with `VaultKey` + canonical AAD, and return only `{ id, version }`.    |
| `vault_prompt_secret_oob`         | Prompt a human operator out-of-band to enter a third-party secret directly into client-side encryption without passing through chat context.                           |
| `vault_admin_audit_logs`          | Query append-only `aud_<ulid>` audit records and verify cryptographic hash-chain continuity (`prev_event_hash` -> `event_hash`).                                       |

## Requirements & Development

Requires **Node.js >= 22**.

```bash
npm install
npm run typecheck
npm run lint
npm test
npm run build
```

### Running the Server

Stdio transport (default for local coding agents such as Claude Desktop, Cursor, and Antigravity):

```bash
npx llm-vault-mcp stdio
```

Loopback Streamable HTTP transport (enforces `Host`/`Origin` validation and `MCP_TOKEN` bearer authentication):

```bash
MCP_TOKEN="your-ephemeral-token" PORT=3000 HOST=127.0.0.1 node dist/main.js streamable-http
```

## License

[MIT](./LICENSE)
