import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
const client = new Client({ name: 'gatekeeper-service-check', version: '1' });
try {
  await client.connect(new StreamableHTTPClientTransport(new URL(`${process.env.PUBLIC_ORIGIN}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${process.env.MUSE_TOKEN}` } } }));
  const tools = (await client.listTools()).tools.map(t => t.name);
  const status = JSON.parse((await client.callTool({ name: 'gatekeeper_status', arguments: {} })).content[0].text);
  console.log(JSON.stringify({ connected: true, tools, phoneHasReported: status.lastDeviceReport !== null, pendingPass: status.pendingPass !== null }));
} finally { await client.close(); }
