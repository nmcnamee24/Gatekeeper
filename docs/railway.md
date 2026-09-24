# Deploy Gatekeeper on Railway

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/A-K_7u)

The template configures the source root, public HTTP port, health check,
persistent volume, and independent generated credentials. Review the settings
and Railway cost estimate, then deploy. Retrieve your generated credentials from
the service variables and pair your app and agent. APNs is optional and requires
your own Apple credentials. The share page and configuration have been checked;
a fresh cloud deployment from this template has not yet been acceptance-tested.

## Manual deployment

1. Create a Railway service from `nmcnamee24/Gatekeeper` (or your fork).
2. Set its **Root Directory** to `/connector`. Use `/connector/railway.json`
   as the configuration-file path if Railway does not detect it automatically.
   The included Dockerfile installs locked dependencies on Node 24.
3. Attach a persistent volume at `/app/data`. Keep one replica.
4. Enable public networking with a generated HTTPS domain; route it to port 8787.
5. Set these service variables before deploying:

| Variable | Value |
| --- | --- |
| `PUBLIC_ORIGIN` | `https://${{RAILWAY_PUBLIC_DOMAIN}}`, or your exact HTTPS origin |
| `HOST` | `0.0.0.0` |
| `PORT` | `8787` |
| `DATA_PATH` | `/app/data/gatekeeper.sqlite` |
| `MUSE_TOKEN` | Independent random secret, at least 32 characters |
| `DEVICE_TOKEN` | A different independent random secret, at least 32 characters |
| `RAILWAY_RUN_UID` | `0` if required for Railway volume write permissions |

Generate credentials locally with `npm run init` and transfer them through
Railway's private variable editor. Do not put values in this README, issue
comments, shell history, or screenshots. Do not copy another deployment's keys.
The `.env.example` deliberately leaves them empty so it cannot start with a
shared default credential.

6. Deploy and confirm `/health` returns `{"status":"ok"}` over HTTPS. The
   Railway healthcheck hostname is accepted only for `GET /health`; it cannot
   bypass authentication on the MCP or device API.
7. Set the same origin and keys in your private local `.env`, then run
   `node --env-file=.env scripts/check-service.js` from `connector/` to verify
   authenticated MCP discovery and status without issuing an approval.
8. Pair the app with `DEVICE_TOKEN`; configure the agent with `MUSE_TOKEN`.

Optional APNs variables are documented in the root README. Without them,
foreground sync works but no server-initiated push is sent.

Do not delete/recreate the volume during updates: it contains cooldown and grant
history. A volume-backed redeploy may briefly interrupt service. Do not enable
request body or Authorization-header logging in a proxy.

## Template configuration

A shareable template must use the public GitHub source, `/connector` root,
public HTTP networking, and a fresh `/app/data` volume. Configure **each** token
with `${{secret(64, "abcdef0123456789")}}` so deployments receive independent
credentials. Leave APNs credentials unset. Never generate a public template
containing values copied from a personal deployment.

References: [Railway templates](https://docs.railway.com/templates/create),
[health checks](https://docs.railway.com/deployments/healthchecks), and
[volumes](https://docs.railway.com/volumes).
