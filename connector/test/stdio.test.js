import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
test('stdio discovers the same tools without disclosing or requiring HTTP tokens', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'gatekeeper-stdio-'));
  const client = new Client({ name: 'stdio-check', version: '1' });
  try {
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [resolve('src/stdio.js')], env: { DATA_PATH: join(dir, 'db.sqlite') }, stderr: 'pipe' }));
    assert.deepEqual((await client.listTools()).tools.map(t => t.name), ['gatekeeper_status', 'gatekeeper_approve', 'gatekeeper_end_access']);
    const state = JSON.parse((await client.callTool({ name: 'gatekeeper_status', arguments: {} })).content[0].text);
    assert.equal(state.lastDeviceReport, null);
    assert.equal(state.pendingPass, null);
    const policy = await client.readResource({ uri: 'gatekeeper://policy' });
    assert.match(policy.contents[0].text, /concrete task/);
  } finally { await client.close(); rmSync(dir, { recursive: true, force: true }); }
});
