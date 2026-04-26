---
name: mcp-server-security-scan
description: Defensive security scan for Model Context Protocol (MCP) servers built with the official @modelcontextprotocol/sdk or mcp Python SDK. Detects tools exposing filesystem/shell with user-controlled paths, HTTP/SSE transports without authentication, unvalidated tool arguments, sensitive data leaking via resource URIs, and unbounded tool output that floods context. Invoke when the user asks to "review", "audit", or "scan" an MCP server implementation.
---

# MCP Server Security Scan

Defensive scan for MCP servers (`@modelcontextprotocol/sdk` Node, `mcp` Python). Reports findings using the [shared scoring schema](../../../SCORING.md).

## Scope

- Files importing `@modelcontextprotocol/sdk/*` or `mcp` (Python)
- Tool / resource / prompt registrations (`server.tool`, `@server.list_tools`, etc.)
- Transport setup (`StdioServerTransport`, `SSEServerTransport`, `StreamableHTTPServerTransport`)

## Threat model recap

MCP tools execute on the **server's** trust boundary but are invoked at the LLM's discretion based on a user's conversation. Treat tool arguments as **fully attacker-controlled**: a user can craft chat input or upload a document that causes the model to call your tool with adversarial arguments (indirect prompt injection).

## Rules

| ID | Severity | Detection | Fix |
|----|----------|-----------|-----|
| MCP-FS-001 | critical | Tool accepts `path` / `filename` argument and reads/writes the filesystem with no containment check (no `path.resolve` + `startsWith(BASE)`) | Resolve under a fixed base dir; reject if outside |
| MCP-FS-002 | high | Tool uses `fs.readFile`/`fs.writeFile` on a user-supplied path with no allowlist of base directories | Configure allowlist via env; refuse otherwise |
| MCP-EXEC-001 | critical | Tool runs `child_process.exec` / `subprocess.run(shell=True)` with command built from arguments | Use spawn with arg array; allowlist commands; reject metacharacters |
| MCP-NET-001 | high | Tool performs HTTP fetch with arbitrary user URL (SSRF: localhost, RFC1918, link-local, AWS metadata 169.254.169.254) | Resolve hostname; block private/link-local/loopback; allowlist if possible |
| MCP-AUTH-001 | critical | HTTP/SSE transport bound to non-loopback interface without authentication middleware (any process on the network can call tools) | Require bearer token / mTLS; bind to loopback unless intentional |
| MCP-AUTH-002 | high | Streamable HTTP transport without `Origin`/`Host` validation (DNS rebinding from a victim's browser to localhost MCP) | Validate `Origin`; require non-browser auth header |
| MCP-VALID-001 | high | Tool registered without input schema (`inputSchema` / zod / Pydantic) | Define and enforce schema; reject unknown fields |
| MCP-VALID-002 | medium | Tool schema uses `additionalProperties: true` or `z.any()` / `Dict[str, Any]` for arguments | Tighten schema |
| MCP-RES-001 | high | Resource URI scheme allows arbitrary paths (`file:///{anything}`) without containment | Resolve under a base dir; refuse parent traversal |
| MCP-RES-002 | medium | Resource list includes secrets (`.env`, key files, `~/.aws`) | Apply ignore list comparable to a `.gitignore`-style filter |
| MCP-OUT-001 | medium | Tool returns unbounded output (full file, full table) that can flood the model's context window — DoS / cost amplification | Cap output size; truncate with explicit notice |
| MCP-OUT-002 | high | Tool output forwards untrusted content (e.g., webpage fetched by tool) without marking provenance | Tag output with `source`/`trust` metadata so the calling agent can apply data-vs-instruction framing |
| MCP-LOG-001 | medium | Tool arguments / results logged to disk or remote sink without redaction | Log tool name and run id; redact bodies |
| MCP-PROMPT-001 | medium | Server-defined prompts include literal credentials or per-tenant data | Parameterize via prompt arguments; never bake secrets in |
| MCP-VER-001 | low | Server advertises capabilities it does not implement (e.g., declares `tools` but registers none) | Match advertised capabilities to implementation |

## Wrong vs. right

### MCP-FS-001 (path traversal)

```ts
// ❌ ../../etc/passwd
server.tool('read_doc', { path: z.string() }, async ({ path }) => {
  const text = await fs.readFile(path, 'utf8');
  return { content: [{ type: 'text', text }] };
});
```

```ts
// ✅ Containment + allowlist
const BASE = path.resolve(process.env.MCP_DOC_ROOT!);
server.tool(
  'read_doc',
  { path: z.string() },
  async ({ path: rel }) => {
    const target = path.resolve(BASE, rel);
    if (!target.startsWith(BASE + path.sep)) throw new Error('forbidden');
    const text = await fs.readFile(target, 'utf8');
    return { content: [{ type: 'text', text }] };
  },
);
```

### MCP-AUTH-001 (HTTP transport without auth)

```ts
// ❌ Network-reachable, no auth
const transport = new StreamableHTTPServerTransport({ port: 8080 });
await server.connect(transport);
```

```ts
// ✅ Auth + Origin check + loopback default
const transport = new StreamableHTTPServerTransport({
  host: '127.0.0.1',
  port: 8080,
  requestHook: (req) => {
    if (req.headers.authorization !== `Bearer ${process.env.MCP_TOKEN}`) {
      throw new Error('unauthorized');
    }
    const origin = req.headers.origin;
    if (origin && !ALLOWED_ORIGINS.has(origin)) throw new Error('bad origin');
  },
});
```

### MCP-NET-001 (SSRF)

```python
# ❌ Tool fetches anything
@server.tool()
async def fetch(url: str) -> str:
    async with httpx.AsyncClient() as c:
        return (await c.get(url)).text
```

```python
# ✅ DNS resolved + private-range blocked
import ipaddress, socket

BLOCKED = [ipaddress.ip_network(n) for n in
    ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
     "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]

def safe_host(host: str) -> bool:
    for _, _, _, _, sa in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(sa[0])
        if any(ip in n for n in BLOCKED):
            return False
    return True

@server.tool()
async def fetch(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not safe_host(parsed.hostname):
        raise ValueError("forbidden")
    ...
```

## References

- MCP specification: https://modelcontextprotocol.io/specification
- MCP TypeScript SDK: https://github.com/modelcontextprotocol/typescript-sdk
- MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk
- OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
