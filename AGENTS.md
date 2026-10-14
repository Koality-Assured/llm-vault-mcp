# Repository AGENTS

Repo-level agent entry point for `Koality-Assured/llm-vault-mcp` — the Model Context Protocol (MCP) server for `llm-vault` providing local W3C WebCrypto envelope decryption, opaque handle resolution, time-bounded secret leasing, and zero-context secret injection.

## Start Here

- Human-facing overview and tool reference: [`README.md`](./README.md)
- Security policy: [`SECURITY.md`](./SECURITY.md)
- Identifier & opaque handle parser (`sec_`, `vlt_`, `usr_`, `agt_`, `fld_`, `aud_`, `lease_`): [`src/ids.ts`](./src/ids.ts)
- Local W3C WebCrypto engine (AAD binding, agent key unwrap, blind indexes, zeroization): [`src/crypto.ts`](./src/crypto.ts)
- Zero-context output scrubber (`stdout`, `stderr`, HTTP headers across raw/base64/url encodings): [`src/scrubber.ts`](./src/scrubber.ts)
- Ephemeral lease manager (`lease_<ulid>` TTL tracking & memory zeroization): [`src/lease-manager.ts`](./src/lease-manager.ts)
- MCP tool contracts, schemas, and server registration: [`src/tools.ts`](./src/tools.ts)
- Transport & process entrypoint (`stdio` / `streamable-http` with DNS rebinding protection): [`src/main.ts`](./src/main.ts)

## Critical Invariants

1. **Zero-Context Default (`[C-2]`)**: `vault_get_secret` and `vault_lease_secret` MUST return opaque handles (`{{vault:sec_<ulid>}}` or `lease_<ulid>`) by default. Raw plaintext reveal requires both `allow_raw_context_reveal: true` on the active agent policy AND an explicit out-of-band (`oobApproved: true`) human confirmation.
2. **Local Envelope Decryption (`[C-1]`)**: Secrets are decrypted inside the MCP process via `globalThis.crypto.subtle` (`AES-256-GCM`) using the local `AgentDecryptionKey` and canonical Additional Authenticated Data (`${tenantId}:${vaultId}:${secretId}:${version}:${keyVersion}`).
3. **Output Scrubbing (`[C-2]`)**: `vault_run_command`, `vault_inject_env`, and `vault_http_proxy` MUST scrub exact UTF-8, Base64, and URL-encoded matches of active secrets from outputs and echoed headers, replacing them with `[REDACTED:<id>]`.
4. **Admin Plane Separation (`[H-4]`)**: Never add user creation, role assignment, or IdP mutation tools to `llm-vault-mcp`. Only read-only `vault_admin_audit_logs` is permitted for `ComplianceAuditor`-scoped tokens.
5. **Memory Zeroization (`[M-1]`, `[M-3]`)**: Always zeroize `Uint8Array` secret buffers (`zeroizeBuffer`) upon lease expiration or execution completion.

## Session-End Verification Gates

Before declaring any change complete, verify all checks pass cleanly:

```bash
npm run typecheck
npm run lint
npm test
npm run build
npm run format:check
```
