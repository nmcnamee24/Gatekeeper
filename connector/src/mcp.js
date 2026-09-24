import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ROLE } from './policy.js';
import { PolicyError } from './store.js';

export function createMcpServer(store, push) {
  function result(value) { return { content: [{ type: 'text', text: JSON.stringify(value) }] }; }
  const safe = fn => async args => {
    try { return result(fn(args)); }
    catch (error) {
      if (!(error instanceof PolicyError)) throw error;
      return { isError: true, content: [{ type: 'text', text: error.message }] };
    }
  };
    const server = new McpServer({ name: 'gatekeeper', version: '0.2.0' }, { instructions: ROLE });
    server.registerTool('gatekeeper_status', {
      description: 'Read fixed policy, cooldown, pending pass, and the timestamped last phone report. Check before considering approval.',
      inputSchema: {}, annotations: { readOnlyHint: true, openWorldHint: false }
    }, safe(() => ({ ...store.status(), push: push?.status() ?? { configured: false, deviceRegistered: false } })));
    server.registerTool('gatekeeper_approve', {
      description: 'After judging a concrete purpose and exit plan acceptable, issue a one-use 16-minute pass. Queues a background wake-up; this does not confirm unlocking. Check a fresh matching phone report. Keep openAppURL as fallback. Reuse requestId only to retry the identical approval.',
      inputSchema: { requestId: z.string().uuid(), purpose: z.string().trim().min(8).max(500), exitPlan: z.string().trim().min(8).max(500) },
      annotations: { readOnlyHint: false, idempotentHint: true, openWorldHint: false }
    }, safe(args => {
      const approval = store.approve(args);
      const delivery = approval.status === 'awaiting_phone' ? push?.enqueue(approval.grantId, 'approve', Date.parse(approval.redeemBy)) : null;
      return { ...approval, push: delivery ?? { configured: false }, instruction: 'Background delivery requested if configured. Only a fresh matching phone report confirms access. Use the notification Start access action or openAppURL if delayed.' };
    }));
    server.registerTool('gatekeeper_end_access', {
      description: 'Revoke outstanding passes and request an early end. The phone applies this on next push or foreground sync; never claim immediate remote blocking.',
      inputSchema: {}, annotations: { readOnlyHint: false, idempotentHint: true, openWorldHint: false }
    }, safe(() => {
      const result = store.endAccess();
      push?.enqueue(`revoke-${Date.now()}`, 'revoke');
      return result;
    }));
    server.registerResource('gatekeeper-policy', 'gatekeeper://policy', { mimeType: 'text/plain' }, async uri => ({ contents: [{ uri: uri.href, text: ROLE }] }));
    server.registerPrompt('gatekeeper-role', { description: 'The role Muse should remember when acting as Gatekeeper.' }, async () => ({ messages: [{ role: 'user', content: { type: 'text', text: ROLE } }] }));
    return server;
}
