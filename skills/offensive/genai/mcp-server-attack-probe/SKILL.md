---
name: mcp-server-attack-probe
description: Authorized red-team probe for Model Context Protocol (MCP) servers. Tests tool path traversal, command injection in shell-like tools, SSRF via fetch tools, HTTP/SSE transport authentication, DNS rebinding via Origin header, and resource URI traversal. Use when the user asks to "red-team" or "attack-test" their own MCP server.
---

# MCP Server Attack Probe

Authorized self-test for MCP servers (`@modelcontextprotocol/sdk` Node, `mcp` Python). Follow [shared probing conventions](../../../PROBING.md) — discover transport via `server.connect(...)` in source, env (`MCP_PORT`, `MCP_HOST`), or `Dockerfile EXPOSE`. Stdio servers are tested by spawning the entrypoint binary and exchanging JSON-RPC over stdio.

## MCP-specific attack surface

- **Tools execute on the server** with the server process's privileges, but their arguments are LLM-chosen — i.e., effectively user-controllable through chat.
- **Stdio transport** is in-process for the spawning client and inherits its privileges (usually OK).
- **HTTP / SSE / Streamable HTTP transports** turn the server into a network service; if it binds non-loopback or omits auth, any process / browser tab can call tools.
- **DNS rebinding**: a victim browser visiting attacker.test where DNS rebinds to `127.0.0.1` can call a localhost MCP HTTP server unless `Origin` is validated.
- **Resource URIs** (`file://`, custom schemes) often resolve paths without containment.
- **Output size** isn't capped by the protocol — flooding the context is a cheap DoS / cost amplification.

## Procedure

1. Authorization preflight + transport/port discovery from source.
2. Connect via the appropriate transport.
3. Call `tools/list` and `resources/list` to enumerate.
4. Probe per the rule table.

## Rules

| ID | Severity | Probe | Confirmed when |
|----|----------|-------|----------------|
| MCP-AUTH-001 | critical | If HTTP transport: connect from an unrelated process with no auth header; call `initialize` then `tools/list` | Server responds with tool inventory = no auth |
| MCP-AUTH-002 | high | Send request with `Origin: https://evil.test` (DNS rebinding scenario) and a benign tool call | Tool call succeeds = no Origin validation |
| MCP-AUTH-003 | medium | Bind detection: check whether HTTP listener is on `0.0.0.0` vs `127.0.0.1` (parse server source) | Bound to `0.0.0.0` AND no auth = pair with MCP-AUTH-001 = critical |
| MCP-FS-001 | critical | For each filesystem-shaped tool (`read_file`, `write_file`, `list_dir`), call with `path: "../../../../etc/passwd"` and `path: "/etc/passwd"` | File contents returned = no containment |
| MCP-FS-002 | high | Same tools with URL-encoded traversal, `..%2f..%2f..%2fetc%2fpasswd` | File contents returned = decode happens before resolve |
| MCP-EXEC-001 | critical | For shell-shaped tools, call with `cmd: "id"`, `cmd: "; id"`, `cmd: "$(id)"` | Process output of `id` in result |
| MCP-EXEC-002 | high | If args allowlisted to enum, attempt enum value followed by metacharacters: `task: "build; id"` | Metacharacters reach shell |
| MCP-NET-001 | high | For fetch/request tools, call with `url: "http://169.254.169.254/latest/meta-data/"` | Metadata returned |
| MCP-NET-002 | high | Same with `url: "http://127.0.0.1:6379/"` (Redis), `http://127.0.0.1:11211/` (memcached) | Connection succeeds, banner returned |
| MCP-NET-003 | medium | DNS rebind: `url: "http://attacker-rebind.test/"` (resolves to attacker first, then 127.0.0.1) — only test if user controls the rebind host | Localhost resource fetched |
| MCP-RES-001 | high | For resource URIs, request `file:///etc/passwd`, `file://../../../../etc/passwd` | Resource returned |
| MCP-RES-002 | medium | List resources; check whether ignore list excludes `.env`, key files, `~/.aws` | Sensitive file appears in `resources/list` |
| MCP-VAL-001 | high | Call any tool with extra unknown fields (`additionalProperties: true`) and with type-confusion (string where number expected) | Tool runs / 500 server error = schema not enforced |
| MCP-OUT-001 | medium | Trigger a tool that returns a large directory listing or file (within authorized target) | No size cap, full content returned = potential DoS / context flood |
| MCP-LOG-001 | low | After a probe run, ask user to inspect server logs for full tool-arg/result content | Full content present = no redaction |

## Stdio transport notes

For stdio servers, "authorization" is implicit (only the spawning process can talk to it). The MCP-AUTH rules don't apply, but FS / EXEC / NET rules still do — and matter just as much because the server inherits the IDE/agent's privileges.

## Wrong vs. right

### MCP-FS-001 (path traversal)

```ts
// ❌
server.tool("read_doc", { path: z.string() }, async ({ path: p }) => {
  return { content: [{ type: "text", text: await fs.readFile(p, "utf8") }] };
});
```

```ts
// ✅
const BASE = path.resolve(process.env.MCP_DOC_ROOT!);
server.tool(
  "read_doc",
  { path: z.string() },
  async ({ path: rel }) => {
    const target = path.resolve(BASE, rel);
    if (!target.startsWith(BASE + path.sep)) throw new Error("forbidden");
    return { content: [{ type: "text", text: await fs.readFile(target, "utf8") }] };
  },
);
```

### MCP-AUTH-001 + MCP-AUTH-002 (HTTP transport)

```ts
// ❌
const transport = new StreamableHTTPServerTransport({ port: 8080 });
await server.connect(transport);
```

```ts
// ✅
const ALLOWED_ORIGINS = new Set(["https://app.example.com"]);
const transport = new StreamableHTTPServerTransport({
  host: "127.0.0.1",
  port: Number(process.env.MCP_PORT ?? 8080),
  requestHook: (req) => {
    if (req.headers.authorization !== `Bearer ${process.env.MCP_TOKEN}`) {
      throw new Error("unauthorized");
    }
    const origin = req.headers.origin;
    if (origin && !ALLOWED_ORIGINS.has(origin)) {
      throw new Error("bad origin");
    }
  },
});
```

### MCP-NET-001 (SSRF)

```python
# ❌
@server.tool()
async def fetch(url: str) -> str:
    async with httpx.AsyncClient() as c:
        return (await c.get(url)).text
```

```python
# ✅ Allowlist + private-range block
import ipaddress, socket
from urllib.parse import urlparse

BLOCKED = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
    "192.168.0.0/16", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)]

def safe_host(host: str) -> bool:
    for *_, sa in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(sa[0])
        if any(ip in n for n in BLOCKED):
            return False
    return True

@server.tool()
async def fetch(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not safe_host(parsed.hostname):
        raise ValueError("forbidden")
    async with httpx.AsyncClient(timeout=5.0) as c:
        return (await c.get(url)).text[:65536]   # cap output
```

## References

- MCP specification: https://modelcontextprotocol.io/specification
- MCP TypeScript SDK: https://github.com/modelcontextprotocol/typescript-sdk
- MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk
- DNS rebinding: https://owasp.org/www-community/attacks/DNS_rebinding
- OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
