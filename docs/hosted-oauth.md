# Hosted agent connections

`HostedOAuth({store,billing,publicOrigin,encryptionKey})` implements the consumer
agent connection flow. Initialize it after the hosted store migration with
`await oauth.init()`, then mount `oauth.router()` at the application root. This
router includes both the OAuth endpoints and `/mcp`; do not mount a second MCP
transport. `encryptionKey` must be a durable 32-byte Buffer or base64 value. Back
it up with the database. Losing or changing the key invalidates pending browser
completion payloads. The constructor accepts HTTPS origins and local HTTP
loopback origins, without paths, queries or credentials.

The issuer and resource are exactly `${publicOrigin}/mcp`. Authoritative
metadata is available at `/.well-known/oauth-authorization-server/mcp` and
`/.well-known/oauth-protected-resource/mcp`, with an authorization-server root
alias for client compatibility. The unauthenticated MCP challenge supplies the
path-specific resource metadata URL in `WWW-Authenticate`; browser clients can
read that challenge before registering.

## Registration and consent

The installed MCP SDK provides `/register`, `/authorize`, `/token` and `/revoke`
HTTP protocol handling and rate limits. Gatekeeper's provider persists the
actual state in PostgreSQL. DCR accepts named public clients with
`token_endpoint_auth_method: "none"`, authorization code/refresh grants and code
responses. Redirect URIs must be HTTPS or HTTP loopback (`127.0.0.1`, `localhost`,
`[::1]`), without fragments or embedded credentials. Authorization matches a
registered redirect exactly, with only loopback port relaxation. Code redemption
must use the exact URI from that authorization request, including its selected
port. Client metadata URLs and URL-form client IDs are never fetched. This
implementation supports DCR rather than Client ID Metadata Documents.

Only these permissions are supported:

| Scope | Authority |
| --- | --- |
| `gatekeeper:status` | Read policy, device list, pending passes, cooldown and historical phone reports |
| `gatekeeper:approve` | Issue a bounded one-use pass for an explicitly selected account-owned device |
| `gatekeeper:end` | Request an early end for an explicitly selected account-owned device |

A registration's declared scopes bound the authorization request. Omitted
requested scopes default to status only. The browser shows the client-supplied
name, callback origin and requested permissions, with untrusted text escaped.
It explains that the client name has not been verified. The user opens
`gatekeeper://connect-agent?request=<UUID>` in Gatekeeper and reviews consent
while signed in. On a different device, the page displays the request UUID for
entry in the phone app. The account API supplies:

- `request(requestId)` → `{id,clientName,redirectURI,scopes,status,expiresAt}`.
- `decide(userId,requestId,approve)` → `{redirectURL,requiresOriginalBrowser:true}`.
- `connections(userId)` → array of `{id,clientName,scopes,createdAt}`.
- `disconnect(userId,connectionId)` → `{revoked:true}`.

The root HTTP application must protect these native APIs with **account** bearer
authentication. The OAuth router does not create public consent decision routes.
A pending request binds to the authenticated account that makes the first
decision; conflicting decisions and cross-account retries are rejected. A
same-account identical retry returns the same encrypted completion, without
minting another code.

Keep the initiating browser open. It posts its separate random browser secret
in the JSON body of `/oauth/requests/<UUID>/poll`, and redirects only after
receiving the approved or denied callback. Polling does not use account tokens,
cookies or secrets in the query string. Cross-origin polling is rejected. The
native app must honor `requiresOriginalBrowser: true` and must not navigate the
callback itself; a desktop `localhost` callback must run on that desktop.
Approved callbacks contain a single-use code, state (when supplied), and `iss`.
Denied callbacks contain `access_denied`, state and `iss`. Conflicting reserved
OAuth response parameters supplied in a registered callback are removed.

## Credential and account boundaries

Authorization requires PKCE S256 and the exact resource indicator. PKCE is
checked inside the locked code exchange transaction. Requests expire in ten
minutes; approved codes expire five minutes after the decision and are consumed
once. Codes and poll secrets are SHA-256 hashed at rest. The callback containing
the code is AES-256-GCM encrypted at rest so another HTTP replica can complete
the original browser flow without storing plaintext codes.

Agent access and refresh tokens are opaque random values, stored only as hashes
in dedicated OAuth tables. Access expires within one hour, capped at the original
family deadline; refresh has an
absolute thirty-day lifetime from the initial exchange. Refresh rotates both
credentials and retires the old access token. Reusing a consumed refresh token
revokes the connection and every token in that family, even during concurrent
refresh requests. A wrong client, resource or scope escalation does not consume
a valid refresh token. Refresh may narrow scopes but cannot widen them.

Every token read binds its connection to the exact issuer/resource. Native
connection listing, disconnect and token revocation also include issuer/resource
and account boundaries. Account deletion cascades consent requests, connections
and token rows. Public client registration metadata is unowned and remains.
Disconnect revokes all family credentials and prevents pending codes from being
exchanged. It does not assert that a phone has changed its shielding state.

Code exchange, refresh, revocation and disconnect lock the account row before
child rows, matching account deletion. Ownership discovered without locks is
re-read in that transaction. Call `oauth.prune()` at startup and hourly: expired
requests (including encrypted callback/state/redirect data) are deleted after a
one-hour grace. Token rows are deleted only after both access expiry and the
absolute refresh expiry plus one hour. Consumed refresh hashes remain for the
whole live family lifetime so cleanup preserves replay revocation. Connection
metadata remains available while consent is active; account deletion erases it.

## Hosted MCP behavior

The stateless Streamable HTTP transport constructs a request-local MCP server;
HTTP replicas require no shared in-memory MCP sessions. MCP accepts only the
OAuth provider's dedicated agent credentials. Account credentials, phone device
credentials, and legacy store-created agent sessions are rejected. Tools are
listed according to the granted scopes, with HTTP 403 challenges for attempts to
call known tools outside those permissions. Write actions recheck token
revocation inside the same account transaction that changes grants. Disconnect
and refresh-family replay take that account lock too, so a revocation committed
before the write acquires it prevents the mutation. Billing reads during
approval use that transaction's client. Authenticated browser origins are bound to the
registered client callback origins. Host checks protect against DNS rebinding.
Unexpected backend failures return a generic error.

`gatekeeper_status` accepts an optional device ID and returns the account's
non-revoked device list so an agent can choose the phone. It includes the last
report timestamp/age and `phoneReportFresh` (at most thirty seconds old), while
`phoneStateConfirmed` remains false: a historical report cannot establish the
phone's current state. The policy resource and role prompt require status scope.
`gatekeeper_approve` requires UUID request/device IDs, a concrete purpose, an exit
plan and 1–15 whole minutes. It checks billing and awaits the store's durable
approval transaction. Status and early end remain available without paid access.
An approval is `awaiting_phone`; server approval and push queuing never imply
that apps unlocked. Device redemption and local timers retain authority.

## Verification and remaining acceptance

Run from `connector/` with an actual PostgreSQL test database:

```sh
TEST_DATABASE_URL=postgresql://gatekeeper@127.0.0.1:55439/gatekeeper_test node --test test/hosted/oauth.test.js test/hosted/hosted-mcp.test.js
```

Tests use unique schemas, real HTTP requests, the SDK OAuth handlers, and a real
SDK Streamable HTTP client. They cover DCR/metadata, account versus device versus
agent roles, native consent, escaped HTML, protected browser polling, PKCE,
redirect/resource/client binding, code expiry/replay, concurrent consent/code/
refresh exchanges, account deletion lock races, atomic disconnect/write races,
retention with preserved refresh replay markers, refresh-family replay revocation, scope boundaries, issuer
separation, device ownership, paid approval checks, disconnect and deletion.
They do not establish Apple sign-in, production client compatibility, actual
phone deep-link behavior or shielding/relocking on a physical device. Before
release, verify a real external client can complete the browser/phone/desktop
loopback flow, refresh and disconnect against the production HTTPS origin.
Browser UI and phone deep-link acceptance must be tested on the target devices.

Protocol references: [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
and [RFC 8252 native loopback redirects](https://www.rfc-editor.org/rfc/rfc8252).
