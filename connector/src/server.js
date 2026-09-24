import express from 'express';
import { timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { createMcpServer } from './mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { PolicyError } from './store.js';

export function createApp({ store, museToken, deviceToken, publicOrigin, push }) {
  for (const token of [museToken, deviceToken]) {
    if (typeof token !== 'string' || token.length < 32) throw new Error('Two separate tokens of at least 32 characters are required.');
  }
  if (museToken === deviceToken) throw new Error('Muse and device tokens must differ.');
  const origin = new URL(publicOrigin);
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('X-Content-Type-Options', 'nosniff');
    // The upstream TLS proxy must preserve Host. No browser origins are needed by this service.
    const railwayHealthcheck = req.method === 'GET' && req.path === '/health' && req.headers.host === 'healthcheck.railway.app';
    if ((!railwayHealthcheck && ![origin.host, '127.0.0.1:8787', 'localhost:8787'].includes(req.headers.host)) || req.headers.origin) return res.sendStatus(403);
    next();
  });
  function authenticate(token) {
    return (req, res, next) => {
      const header = req.headers.authorization ?? '';
      const expected = Buffer.from(`Bearer ${token}`);
      const supplied = Buffer.from(header);
      if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return res.sendStatus(401);
      next();
    };
  }
  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.use('/mcp', authenticate(museToken));
  app.use('/device', authenticate(deviceToken));
  app.use(express.json({ limit: '16kb' }));
  app.post('/mcp', async (req, res) => {
    const server = createMcpServer(store, push);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => { void transport.close(); void server.close(); });
    try { await server.connect(transport); await transport.handleRequest(req, res, req.body); }
    catch { if (!res.headersSent) res.status(500).json({ error: 'MCP request failed' }); }
  });
  app.all('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').end());
  app.post('/device/push', (req, res) => {
    const input = z.object({ token: z.string().regex(/^[a-f0-9]{64,256}$/), environment: z.enum(['sandbox', 'production']) }).strict().safeParse(req.body);
    if (!input.success) return res.status(400).json({ error: 'Invalid push registration' });
    if (!push) return res.status(503).json({ error: 'Push delivery unavailable' });
    res.json(push.register(input.data.token, input.data.environment));
  });
  app.get('/device/state', (_req, res) => res.json(store.deviceState()));
  app.post('/device/redeem', (req, res, next) => {
    const input = z.object({ grantId: z.string().uuid() }).strict().safeParse(req.body);
    if (!input.success) return res.status(400).json({ error: 'Invalid grant ID' });
    try { res.json(store.redeem(input.data.grantId)); } catch (error) { next(error); }
  });
  app.post('/device/report', (req, res) => {
    const input = z.object({ state: z.enum(['shielded', 'window_open', 'permission_missing', 'selection_missing']),
      grantId: z.string().uuid().nullable().optional(), localExpiry: z.string().datetime().nullable().optional() }).strict().safeParse(req.body);
    if (!input.success) return res.status(400).json({ error: 'Invalid device report' });
    res.json(store.report(input.data));
  });
  app.use((error, _req, res, _next) => {
    if (error instanceof PolicyError) return res.status(409).json({ error: error.message });
    if (error instanceof SyntaxError || error.type === 'entity.too.large') return res.status(400).json({ error: 'Invalid request body' });
    res.status(500).json({ error: 'Request failed' });
  });
  return app;
}
