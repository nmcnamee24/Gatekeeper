# Gatekeeper MCP server

Single-user, single-iPhone service with authenticated Streamable HTTP MCP,
a separate device API, persistent SQLite state, and optional APNs notifications.
Requires Node 24.4+ for built-in SQLite.

```sh
npm ci
npm test
npm run init
npm start
```

`init` creates a private `.env` with independent agent and device credentials;
it refuses to overwrite an existing configuration and never prints secrets.
See [.env.example](.env.example), the [root setup guide](../README.md), and
[Railway deployment](../docs/railway.md).

The agent connects to `/mcp` using `MUSE_TOKEN`. The phone uses `/device/*` with
`DEVICE_TOKEN`. Host validation and browser-origin rejection remain active.
Health checks reveal only service availability, not phone or request state.

Tools: `gatekeeper_status`, `gatekeeper_approve`, and `gatekeeper_end_access`.
The `gatekeeper-role` prompt and `gatekeeper://policy` resource provide agent
instructions. The server validates input and timing; the agent judges purpose.

An approval is not an unlock. Redemption is transactional and single-use. A
network or scheduling failure can consume the pass without opening apps. Early
revocation preserves cooldown. There is no refund/reset tool. APNs wakes the
phone but carries no authority to unlock; foreground sync is the fallback.

Run one replica on persistent storage. Keep SQLite files and environment values
outside version control. Request purposes and device reports are retained;
automatic retention, rate limiting, multi-user isolation, and OAuth are not
implemented. See [SECURITY.md](../SECURITY.md).
