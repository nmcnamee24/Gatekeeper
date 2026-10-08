import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {randomBytes,createHash,randomUUID} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {database,account} from './helpers.js';
import {HostedOAuth} from '../../src/hosted/oauth.js';
import {createHostedApp} from '../../src/hosted/app.js';
const verifier='z'.repeat(64),challenge=createHash('sha256').update(verifier).digest('base64url');
async function service(t,scopes=['gatekeeper:status','gatekeeper:approve','gatekeeper:end']) {
 const {pool,store}=await database(t),a=await account(store,'mcp-a'),b=await account(store,'mcp-b');
 const server=createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin=`http://127.0.0.1:${server.address().port}`;
 const billing={requireAccess:async()=>{},entitlement:async()=>({active:true,betaAccess:true}),products:()=>({productIds:[],betaAccess:true})};
 const oauth=new HostedOAuth({store,billing,publicOrigin:origin,encryptionKey:randomBytes(32)});await oauth.init();
 server.on('request',createHostedApp({store,identity:{},billing,conversation:{},coach:{configured:true},publicOrigin:origin,oauth}));
 t.after(()=>{server.closeAllConnections();server.close();});
 const client=await oauth.registerClient({client_name:'MCP tests',token_endpoint_auth_method:'none',redirect_uris:['http://127.0.0.1:8000/cb']});
 let html;
 await oauth.authorize(client,{redirectUri:client.redirect_uris[0],resource:new URL(origin+'/mcp'),scopes,codeChallenge:challenge,state:'test'}, {set(){return this;},type(){return this;},send(value){html=value;}});
 const id=/data-request="([^"]+)"/.exec(html)[1],decision=await oauth.decide(a.user.id,id,true),code=new URL(decision.redirectURL).searchParams.get('code');
 const token=await oauth.exchangeAuthorizationCode(client,code,verifier,client.redirect_uris[0],new URL(origin+'/mcp'));
 const call=(body,bearer=token.access_token)=>fetch(origin+'/mcp',{method:'POST',headers:{Authorization:'Bearer '+bearer,'Content-Type':'application/json',Accept:'application/json, text/event-stream'},body:JSON.stringify(body)});
 return {pool,store,oauth,origin,a,b,billing,token,call};
}
async function sdk(t,s){const client=new Client({name:'real-sdk-tests',version:'1.0'});await client.connect(new StreamableHTTPClientTransport(new URL(s.origin+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+s.token.access_token}}}));t.after(()=>client.close());return client;}
const result=r=>JSON.parse(r.content[0].text);

test('real SDK client discovers hosted tools and fresh phone report while readonly scope cannot approve',async t=>{
 const s=await service(t,['gatekeeper:status']),client=await sdk(t,s);
 assert.deepEqual((await client.listTools()).tools.map(tool=>tool.name),['gatekeeper_status']);
 await s.store.report(s.a.user.id,s.a.device.id,{state:'shielded'});
 const status=result(await client.callTool({name:'gatekeeper_status',arguments:{deviceId:s.a.device.id}}));
 assert.equal(status.lastDeviceReport.state,'shielded');assert.equal(status.phoneReportFresh,true);
 assert.equal(status.phoneStateConfirmed,false);
 assert.deepEqual(status.devices.map(device=>device.id),[s.a.device.id]);
 assert.equal((await s.call({jsonrpc:'2.0',id:10,method:'tools/call',params:{name:'gatekeeper_approve',arguments:{}}})).status,403);
 assert.equal((await client.readResource({uri:'gatekeeper://policy'})).contents.length,1);
});

test('account/device/store-agent credentials cannot authenticate hosted MCP and discovery advertises resource',async t=>{
 const s=await service(t);const ordinaryAgent=await s.store.createSession(s.a.user.id,{kind:'agent',scopes:['gatekeeper:status']});
 for(const token of [s.a.session.accountToken,s.a.device.token,ordinaryAgent.accountToken,'invalid']) {
  const response=await s.call({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'unauthorized',version:'1'}}},token);
  assert.equal(response.status,401);assert.ok(response.headers.get('www-authenticate').includes('/.well-known/oauth-protected-resource/mcp'));
 }
});

test('agent approve is user/device bound, awaits durable store and paid access; end/status stay available',async t=>{
 const s=await service(t),client=await sdk(t,s);
 const args={requestId:randomUUID(),deviceId:s.a.device.id,purpose:'Reply to a specific message',exitPlan:'Close the app after my reply',durationMinutes:4};
 const cross=await client.callTool({name:'gatekeeper_approve',arguments:{...args,deviceId:s.b.device.id}});assert.equal(cross.isError,true);
 assert.equal((await s.pool.query('SELECT count(*) FROM gk_grants')).rows[0].count,'0');
 s.billing.requireAccess=async()=>{throw Object.assign(new Error('Paid access unavailable'),{status:402,code:'subscription_required'});};
 assert.equal((await client.callTool({name:'gatekeeper_approve',arguments:args})).isError,true);
 assert.equal(result(await client.callTool({name:'gatekeeper_status',arguments:{deviceId:s.a.device.id}})).pendingPass,null);
 assert.equal(result(await client.callTool({name:'gatekeeper_end_access',arguments:{deviceId:s.a.device.id}})).status,'end_requested');
 s.billing.requireAccess=async()=>{};
 const approval=result(await client.callTool({name:'gatekeeper_approve',arguments:args}));assert.ok(approval.grantId);assert.equal(approval.status,'awaiting_phone');assert.equal(approval.phoneStateConfirmed,false);
 const row=(await s.pool.query('SELECT * FROM gk_grants WHERE id=$1',[approval.grantId])).rows[0];assert.equal(row.user_id,s.a.user.id);assert.equal(row.device_id,s.a.device.id);assert.equal(row.window_seconds,240);
 const status=result(await client.callTool({name:'gatekeeper_status',arguments:{deviceId:s.a.device.id}}));assert.equal(status.pendingPass.grantId,approval.grantId);
 const connection=(await s.oauth.connections(s.a.user.id))[0];await s.oauth.disconnect(s.a.user.id,connection.id);
 assert.equal((await s.call({jsonrpc:'2.0',id:12,method:'tools/list'})).status,401);
});

test('MCP blocks unsafe browser origins and host rebinding before consuming an agent action',async t=>{
 const s=await service(t),client=await sdk(t,s);
 const response=await fetch(s.origin+'/mcp',{method:'POST',headers:{Origin:'https://attacker.example',Authorization:'Bearer '+s.token.access_token,'Content-Type':'application/json',Accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:2,method:'tools/list'})});
 assert.equal(response.status,403);
 const valid=await client.listTools();assert.equal(valid.tools.length,3);
});

test('browser-based clients can read the unauthenticated MCP OAuth discovery challenge',async t=>{
 const s=await service(t);
 const response=await fetch(s.origin+'/mcp',{method:'POST',headers:{Origin:'https://agent.example','Content-Type':'application/json',Accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});
 assert.equal(response.status,401);
 assert.equal(response.headers.get('Access-Control-Allow-Origin'),'https://agent.example');
 assert.ok(response.headers.get('Access-Control-Expose-Headers').includes('WWW-Authenticate'));
});

test('unexpected backend failures do not disclose internal configuration to an agent',async t=>{
 const s=await service(t,['gatekeeper:status']),client=await sdk(t,s);
 s.store.status=async()=>{throw new Error('database password=private-setting');};
 const failed=await client.callTool({name:'gatekeeper_status',arguments:{}});
 assert.equal(failed.isError,true);
 assert.equal(failed.content[0].text.includes('private-setting'),false);
});

async function waitForAccountContention(pool,blockerPid){
 for(let attempt=0;attempt<200;attempt++){
  if((await pool.query("SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%gk_users%FOR UPDATE%'",[blockerPid])).rows.length)return;
  await new Promise(resolve=>setTimeout(resolve,10));
 }
 throw new Error('MCP mutation never reached the held account lock');
}
for(const tool of ['gatekeeper_approve','gatekeeper_end_access'])test('disconnect committed before account lock prevents '+tool+' mutation',async t=>{
 const s=await service(t),client=await sdk(t,s);
 const args={requestId:randomUUID(),deviceId:s.a.device.id,purpose:'Reply to a specific message',exitPlan:'Close the app after my reply',durationMinutes:3};
 let existing;
 if(tool==='gatekeeper_end_access')existing=await s.store.approve(s.a.user.id,args);
 const connection=(await s.oauth.connections(s.a.user.id))[0],blocker=await s.pool.connect();
 let operation;
 try {
  await blocker.query('BEGIN');await blocker.query('SELECT id FROM gk_users WHERE id=$1 FOR UPDATE',[s.a.user.id]);
  operation=client.callTool({name:tool,arguments:tool==='gatekeeper_approve'?args:{deviceId:s.a.device.id}});
  await waitForAccountContention(s.pool,blocker.processID);
  // Commit the same durable connection/family revocation while owning the account lock.
  await blocker.query('UPDATE gk_oauth_connections SET revoked_at=now() WHERE id=$1 AND user_id=$2',[connection.id,s.a.user.id]);
  await blocker.query('UPDATE gk_oauth_tokens SET revoked_at=now() WHERE connection_id=$1',[connection.id]);
  await blocker.query('COMMIT');
  const failed=await operation;assert.equal(failed.isError,true);
  if(existing){
   assert.equal((await s.pool.query('SELECT revoked_at FROM gk_grants WHERE id=$1',[existing.grantId])).rows[0].revoked_at,null);
   assert.equal((await s.pool.query("SELECT count(*) FROM gk_push_jobs WHERE event='end'")).rows[0].count,'0');
  }else assert.equal((await s.pool.query('SELECT count(*) FROM gk_grants')).rows[0].count,'0');
 }finally{await blocker.query('ROLLBACK');blocker.release();if(operation)await operation.catch(()=>{});}
});
