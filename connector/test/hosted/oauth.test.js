import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {randomBytes,createHash,randomUUID} from 'node:crypto';
import {database,account} from './helpers.js';
import {HostedOAuth} from '../../src/hosted/oauth.js';
import {createHostedApp} from '../../src/hosted/app.js';
const verifier='a'.repeat(64);
const challenge=createHash('sha256').update(verifier).digest('base64url');

export async function service(t) {
 const {pool,store}=await database(t),a=await account(store,'oauth-a'),b=await account(store,'oauth-b');
 const server=createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const origin=`http://127.0.0.1:${server.address().port}`;
 const billing={requireAccess:async()=>{},entitlement:async()=>({active:true,betaAccess:true}),products:()=>({productIds:[],betaAccess:true})};
 const oauth=new HostedOAuth({store,billing,publicOrigin:origin,encryptionKey:randomBytes(32)});await oauth.init();
 server.on('request',createHostedApp({store,identity:{},billing,conversation:{},coach:{configured:true},publicOrigin:origin,oauth}));
 t.after(()=>{server.closeAllConnections();server.close();});
 const call=(path,body,token,method)=>fetch(origin+path,{method:method??(body?'POST':'GET'),redirect:'manual',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:body?JSON.stringify(body):undefined});
 return {pool,store,oauth,a,b,billing,origin,call};
}
export async function register(s,overrides={}) {
 const response=await s.call('/register',{client_name:'Test agent',redirect_uris:['http://127.0.0.1:8123/callback'],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code'],scope:'gatekeeper:status gatekeeper:approve gatekeeper:end',...overrides});
 assert.equal(response.status,201);return response.json();
}
export async function consent(s,client,overrides={}) {
 const redirectURI=overrides.redirectURI??client.redirect_uris[0];
 const params=new URLSearchParams({client_id:client.client_id,redirect_uri:redirectURI,response_type:'code',code_challenge:challenge,code_challenge_method:'S256',resource:s.origin+'/mcp',scope:'gatekeeper:status gatekeeper:approve gatekeeper:end',state:'client-state',...overrides});
 params.delete('redirectURI');
 const response=await s.call('/authorize?'+params);assert.equal(response.status,200);
 const html=await response.text();
 const requestId=/data-request="([^"]+)"/.exec(html)?.[1];
 const pollSecret=/data-poll-secret="([^"]+)"/.exec(html)?.[1];
 assert.ok(requestId);assert.ok(pollSecret);return {requestId,pollSecret,html,redirectURI};
}
export async function tokens(s,client,c,overrides={}) {
 const decision=await s.oauth.decide(s.a.user.id,c.requestId,true);
 const code=new URL(decision.redirectURL).searchParams.get('code');
 const response=await s.call('/token',{grant_type:'authorization_code',client_id:client.client_id,code,code_verifier:verifier,redirect_uri:c.redirectURI,resource:s.origin+'/mcp',...overrides});
 assert.equal(response.status,200);return {token:await response.json(),code,decision};
}

test('DCR public clients, exact metadata issuer/resource and safe redirect registration',async t=>{
 const s=await service(t);const client=await register(s);
 assert.equal(client.client_secret,undefined);
 const metadata=await (await s.call('/.well-known/oauth-authorization-server/mcp')).json();
 assert.equal(metadata.issuer,s.origin+'/mcp');assert.deepEqual(metadata.token_endpoint_auth_methods_supported,['none']);
 const resource=await (await s.call('/.well-known/oauth-protected-resource/mcp')).json();
 assert.equal(resource.resource,s.origin+'/mcp');assert.deepEqual(resource.authorization_servers,[s.origin+'/mcp']);
 for(const value of [
  {redirect_uris:['http://example.com/callback']},{redirect_uris:['https://example.com/callback#fragment']},
  {redirect_uris:['https://user:password@example.com/callback']},{token_endpoint_auth_method:'client_secret_post'},
  {scope:'gatekeeper:status admin'},{redirect_uris:['javascript:alert(1)']},
 ]) assert.equal((await s.call('/register',{client_name:'Unsafe',redirect_uris:['https://example.com/callback'],token_endpoint_auth_method:'none',...value})).status,400);
 assert.equal((await s.call('/authorize?'+new URLSearchParams({client_id:client.client_id,redirect_uri:'https://attacker.com'}))).status,400);
});

test('account-authenticated native consent binds code to user, PKCE and initiating browser',async t=>{
 const s=await service(t),client=await register(s,{client_name:'<script>alert(1)</script>'});
 const c=await consent(s,client,{redirectURI:'http://127.0.0.1:9222/callback'});
 assert.equal(c.html.includes('<script>alert(1)</script>'),false);assert.ok(c.html.includes('&lt;script&gt;'));
 assert.equal((await s.call('/v1/agents/requests/'+c.requestId)).status,401);
 assert.equal((await s.call('/v1/agents/requests/'+c.requestId,null,s.a.device.token)).status,401);
 const request=await (await s.call('/v1/agents/requests/'+c.requestId,null,s.a.session.accountToken)).json();
 assert.equal(request.redirectURI,c.redirectURI);
 assert.equal((await s.call('/oauth/requests/'+c.requestId+'/poll',{pollSecret:'bad'})).status,403);
 const decisionResponse=await s.call('/v1/agents/requests/'+c.requestId+'/decision',{approve:true},s.a.session.accountToken);
 assert.equal(decisionResponse.status,200);const decision=await decisionResponse.json();assert.equal(decision.requiresOriginalBrowser,true);
 const redirect=new URL(decision.redirectURL);assert.equal(redirect.host,'127.0.0.1:9222');assert.equal(redirect.searchParams.get('state'),'client-state');assert.equal(redirect.searchParams.get('iss'),s.origin+'/mcp');
 const polled=await (await s.call('/oauth/requests/'+c.requestId+'/poll',{pollSecret:c.pollSecret})).json();assert.equal(polled.redirectURL,decision.redirectURL);
 const code=redirect.searchParams.get('code');
 for(const changes of [{code_verifier:'b'.repeat(64)},{redirect_uri:'http://127.0.0.1:9223/callback'},{resource:s.origin+'/other'}]) {
  const response=await s.call('/token',{grant_type:'authorization_code',client_id:client.client_id,code,code_verifier:verifier,redirect_uri:c.redirectURI,resource:s.origin+'/mcp',...changes});assert.equal(response.status,400);
 }
 const token=await s.call('/token',{grant_type:'authorization_code',client_id:client.client_id,code,code_verifier:verifier,redirect_uri:c.redirectURI,resource:s.origin+'/mcp'});assert.equal(token.status,200);
 const value=await token.json(),auth=await s.oauth.verifyAccessToken(value.access_token);assert.equal(auth.extra.userId,s.a.user.id);
 const rows=(await s.pool.query('SELECT * FROM gk_oauth_requests')).rows;assert.equal(JSON.stringify(rows).includes(code),false);assert.equal(JSON.stringify(rows).includes(c.pollSecret),false);
 assert.equal((await s.call('/v1/account',null,value.access_token)).status,401);
 assert.equal((await s.call('/device/state',null,value.access_token)).status,401);
});

test('single-use authorization exchange and client ownership serialize across workers',async t=>{
 const s=await service(t),client=await register(s),other=await register(s),c=await consent(s,client);
 const decision=await s.oauth.decide(s.a.user.id,c.requestId,true),code=new URL(decision.redirectURL).searchParams.get('code');
 const request={grant_type:'authorization_code',client_id:client.client_id,code,code_verifier:verifier,redirect_uri:c.redirectURI,resource:s.origin+'/mcp'};
 assert.equal((await s.call('/token',{...request,client_id:other.client_id})).status,400);
 const parallel=await Promise.all([s.call('/token',request),s.call('/token',request)]);
 assert.deepEqual(parallel.map(r=>r.status).sort(),[200,400]);
 assert.equal((await s.pool.query('SELECT count(*) FROM gk_oauth_connections')).rows[0].count,'1');
});

test('refresh rotates, rejects wrong client/resource/escalation, and replay revokes the entire family',async t=>{
 const s=await service(t),client=await register(s),other=await register(s),c=await consent(s,client,{scope:'gatekeeper:status'});
 const {token}=await tokens(s,client,c);
 const request={grant_type:'refresh_token',client_id:client.client_id,refresh_token:token.refresh_token,resource:s.origin+'/mcp'};
 for(const change of [{client_id:other.client_id},{resource:s.origin+'/wrong'},{scope:'gatekeeper:approve'}]) assert.equal((await s.call('/token',{...request,...change})).status,400);
 const renewed=await s.call('/token',request);assert.equal(renewed.status,200);const next=await renewed.json();
 assert.notEqual(next.access_token,token.access_token);assert.notEqual(next.refresh_token,token.refresh_token);
 await assert.rejects(s.oauth.verifyAccessToken(token.access_token));
 assert.equal((await s.call('/token',request)).status,400);
 await assert.rejects(s.oauth.verifyAccessToken(next.access_token));
 assert.equal((await s.call('/token',{...request,refresh_token:next.refresh_token})).status,400);
});

test('disconnect belongs to the account, revokes all tokens and account deletion cascades',async t=>{
 const s=await service(t),client=await register(s),c=await consent(s,client),{token}=await tokens(s,client,c);
 const connections=await s.oauth.connections(s.a.user.id);assert.equal(connections.length,1);assert.equal((await s.oauth.connections(s.b.user.id)).length,0);
 await assert.rejects(s.oauth.disconnect(s.b.user.id,connections[0].id));
 assert.equal((await s.oauth.verifyAccessToken(token.access_token)).extra.userId,s.a.user.id);
 await s.oauth.disconnect(s.a.user.id,connections[0].id);await assert.rejects(s.oauth.verifyAccessToken(token.access_token));
 await s.store.deleteAccount(s.a.user.id);
 for(const table of ['gk_oauth_connections','gk_oauth_tokens']) assert.equal((await s.pool.query('SELECT count(*) FROM '+table)).rows[0].count,'0');
});

test('denial returns state-bound access_denied and pending requests expire',async t=>{
 const s=await service(t),client=await register(s),c=await consent(s,client);
 const denial=await s.oauth.decide(s.a.user.id,c.requestId,false);
 assert.equal(new URL(denial.redirectURL).searchParams.get('error'),'access_denied');
 assert.equal(new URL(denial.redirectURL).searchParams.get('state'),'client-state');
 await assert.rejects(s.oauth.decide(s.b.user.id,c.requestId,true));
 const expired=await consent(s,client);await s.pool.query('UPDATE gk_oauth_requests SET expires_at=now()-interval \'1 second\' WHERE id=$1',[expired.requestId]);
 await assert.rejects(s.oauth.decide(s.a.user.id,expired.requestId,true));
 assert.equal((await s.call('/oauth/requests/'+expired.requestId+'/poll',{pollSecret:expired.pollSecret})).status,410);
});

test('authorization responses remove conflicting response parameters supplied in registered callback query',async t=>{
 const s=await service(t),client=await register(s,{redirect_uris:['http://127.0.0.1:8123/callback?code=untrusted&error=untrusted&state=untrusted&iss=untrusted']});
 const denied=await consent(s,client);const denial=new URL((await s.oauth.decide(s.a.user.id,denied.requestId,false)).redirectURL);
 assert.equal(denial.searchParams.get('code'),null);
 assert.equal(denial.searchParams.get('error'),'access_denied');
 const approved=await consent(s,client);const success=new URL((await s.oauth.decide(s.a.user.id,approved.requestId,true)).redirectURL);
 assert.equal(success.searchParams.get('error'),null);assert.ok(success.searchParams.get('code'));assert.equal(success.searchParams.get('state'),'client-state');
});

test('code expiry, missing resource and concurrent consent cannot create cross-account credentials',async t=>{
 const s=await service(t),client=await register(s),c=await consent(s,client);
 const decisions=await Promise.allSettled([s.oauth.decide(s.a.user.id,c.requestId,true),s.oauth.decide(s.b.user.id,c.requestId,true)]);
 assert.equal(decisions.filter(result=>result.status==='fulfilled').length,1);
 const decision=decisions.find(result=>result.status==='fulfilled').value,code=new URL(decision.redirectURL).searchParams.get('code');
 const request={grant_type:'authorization_code',client_id:client.client_id,code,code_verifier:verifier,redirect_uri:c.redirectURI};
 assert.equal((await s.call('/token',request)).status,400);
 await s.pool.query('UPDATE gk_oauth_requests SET code_expires_at=now()-interval \'1 second\' WHERE id=$1',[c.requestId]);
 assert.equal((await s.call('/token',{...request,resource:s.origin+'/mcp'})).status,400);
 assert.equal((await s.pool.query('SELECT count(*) FROM gk_oauth_tokens')).rows[0].count,'0');
});

test('parallel refresh uses the family lock and reuse invalidates the winning credential',async t=>{
 const s=await service(t),client=await register(s),c=await consent(s,client),{token}=await tokens(s,client,c);
 const request={grant_type:'refresh_token',client_id:client.client_id,refresh_token:token.refresh_token,resource:s.origin+'/mcp'};
 const responses=await Promise.all([s.call('/token',request),s.call('/token',request)]);
 assert.deepEqual(responses.map(response=>response.status).sort(),[200,400]);
 const winner=await responses.find(response=>response.status===200).json();
 await assert.rejects(s.oauth.verifyAccessToken(winner.access_token));
});

test('other issuer cannot list, disconnect or revoke this issuer connection in a shared database',async t=>{
 const s=await service(t),client=await register(s),c=await consent(s,client),{token}=await tokens(s,client,c);
 const other=new HostedOAuth({store:s.store,billing:s.billing,publicOrigin:'https://other.example',encryptionKey:randomBytes(32)});
 const connection=(await s.oauth.connections(s.a.user.id))[0];
 assert.equal((await other.connections(s.a.user.id)).length,0);
 await assert.rejects(other.request(c.requestId));
 await assert.rejects(other.disconnect(s.a.user.id,connection.id));
 await other.revokeToken(client,{token:token.access_token});
 assert.equal((await s.oauth.verifyAccessToken(token.access_token)).extra.userId,s.a.user.id);
});

async function waitForWorkerLock(pool,applicationName) {
 for(let attempt=0;attempt<200;attempt++) {
  if((await pool.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'",[applicationName])).rows.length)return;
  await new Promise(resolve=>setTimeout(resolve,10));
 }
 throw new Error('OAuth worker never reached the concurrent account lock');
}

for(const grantType of ['authorization_code','refresh_token'])test('account deletion does not deadlock '+grantType+' exchange',async t=>{
 const s=await service(t),client=await register(s),c=await consent(s,client);
 const decision=await s.oauth.decide(s.a.user.id,c.requestId,true),code=new URL(decision.redirectURL).searchParams.get('code');
 const initial=grantType==='refresh_token'?await s.oauth.exchangeAuthorizationCode(client,code,verifier,c.redirectURI,new URL(s.origin+'/mcp')):null;
 const [{default:pg},{HostedStore}]=await Promise.all([import('pg'),import('../../src/hosted/store.js')]);
 const applicationName='oauth_delete_'+randomUUID(),workerPool=new pg.Pool({...s.pool.options,application_name:applicationName});t.after(()=>workerPool.end());
 const worker=new HostedOAuth({store:new HostedStore(workerPool),billing:s.billing,publicOrigin:s.origin,encryptionKey:randomBytes(32)});
 const deleter=await s.pool.connect();
 try {
  await deleter.query('BEGIN');await deleter.query('SELECT id FROM gk_users WHERE id=$1 FOR UPDATE',[s.a.user.id]);
  const operation=(grantType==='authorization_code'?worker.exchangeAuthorizationCode(client,code,verifier,c.redirectURI,new URL(s.origin+'/mcp')):worker.exchangeRefreshToken(client,initial.refresh_token,undefined,new URL(s.origin+'/mcp'))).then(value=>({value}),error=>({error}));
  await waitForWorkerLock(s.pool,applicationName);
  await deleter.query('DELETE FROM gk_users WHERE id=$1',[s.a.user.id]);await deleter.query('COMMIT');
  const outcome=await operation;assert.ok(outcome.error);assert.equal(outcome.error.errorCode,'invalid_grant');
  assert.equal((await s.pool.query('SELECT count(*) FROM gk_oauth_tokens')).rows[0].count,'0');
 }finally{await deleter.query('ROLLBACK');deleter.release();}
});

test('prune removes expired consent secrets and tokens while preserving replay markers and active connection metadata',async t=>{
 const s=await service(t),client=await register(s),c=await consent(s,client),{token}=await tokens(s,client,c);
 const refresh={grant_type:'refresh_token',client_id:client.client_id,refresh_token:token.refresh_token,resource:s.origin+'/mcp'};
 assert.equal((await s.call('/token',refresh)).status,200);
 await s.pool.query("UPDATE gk_oauth_requests SET expires_at=now()-interval '2 hours' WHERE id=$1",[c.requestId]);
 const oldToken=randomUUID();
 const oldHash=createHash('sha256').update(token.refresh_token).digest('hex');
 await s.pool.query('INSERT INTO gk_oauth_tokens(id,user_id,connection_id,access_hash,refresh_hash,scopes,expires_at,refresh_expires_at,created_at) SELECT $1,user_id,connection_id,$2,$3,scopes,now()-interval \'3 days\',now()-interval \'2 days\',now()-interval \'32 days\' FROM gk_oauth_tokens WHERE refresh_hash=$4',[oldToken,'a'.repeat(64),'b'.repeat(64),oldHash]);
 const counts=await s.oauth.prune();
 assert.equal(counts.requestsDeleted,1);assert.equal(counts.tokensDeleted,1);
 assert.equal((await s.pool.query('SELECT * FROM gk_oauth_tokens WHERE id=$1',[oldToken])).rowCount,0);
 assert.equal((await s.pool.query('SELECT * FROM gk_oauth_tokens WHERE refresh_hash=$1',[oldHash])).rowCount,1);
 assert.equal((await s.oauth.connections(s.a.user.id)).length,1);
 assert.equal((await s.call('/token',refresh)).status,400); // Replay still revokes the current family.
 assert.equal((await s.oauth.connections(s.a.user.id)).length,0);
});

test('last refresh caps access expiry at the original absolute family deadline',async t=>{
 const s=await service(t),client=await register(s),c=await consent(s,client),{token}=await tokens(s,client,c);
 const deadline=new Date(Date.now()+30000),refreshHash=createHash('sha256').update(token.refresh_token).digest('hex');
 await s.pool.query('UPDATE gk_oauth_tokens SET refresh_expires_at=$1 WHERE refresh_hash=$2',[deadline,refreshHash]);
 const response=await s.call('/token',{grant_type:'refresh_token',client_id:client.client_id,refresh_token:token.refresh_token,resource:s.origin+'/mcp'});
 assert.equal(response.status,200);const renewed=await response.json();assert.ok(renewed.expires_in>0&&renewed.expires_in<=30);
 const accessHash=createHash('sha256').update(renewed.access_token).digest('hex');
 assert.equal((await s.pool.query('SELECT expires_at FROM gk_oauth_tokens WHERE access_hash=$1',[accessHash])).rows[0].expires_at.toISOString(),deadline.toISOString());
 s.store.clock=()=>deadline.getTime();
 await assert.rejects(s.oauth.verifyAccessToken(renewed.access_token));
});

test('known revoked Apple authorization blocks consent, code, refresh and existing agent access',async t=>{
 const s=await service(t),client=await register(s),first=await consent(s,client),{token}=await tokens(s,client,first);
 const exchange=await consent(s,client),decision=await s.oauth.decide(s.a.user.id,exchange.requestId,true),code=new URL(decision.redirectURL).searchParams.get('code');
 const pending=await consent(s,client);
 await s.pool.query('UPDATE gk_users SET apple_authorization_revoked_at=now() WHERE id=$1',[s.a.user.id]);
 await assert.rejects(s.oauth.verifyAccessToken(token.access_token));
 await assert.rejects(s.oauth.exchangeAuthorizationCode(client,code,verifier,exchange.redirectURI,new URL(s.origin+'/mcp')));
 await assert.rejects(s.oauth.exchangeRefreshToken(client,token.refresh_token,undefined,new URL(s.origin+'/mcp')));
 await assert.rejects(s.oauth.decide(s.a.user.id,pending.requestId,true),{code:'apple_authorization_revoked'});
 assert.equal((await s.pool.query('SELECT count(*) FROM gk_oauth_connections')).rows[0].count,'2');
});

test('consent authenticated before Apple revocation cannot create connection after waiting for user lock',async t=>{
 const s=await service(t),client=await register(s),pending=await consent(s,client),blocker=await s.pool.connect();
 let request;
 try {
  await blocker.query('BEGIN');await blocker.query('SELECT id FROM gk_users WHERE id=$1 FOR UPDATE',[s.a.user.id]);
  request=s.call('/v1/agents/requests/'+pending.requestId+'/decision',{approve:true},s.a.session.accountToken);
  let waiting=false;
  for(let attempt=0;attempt<200;attempt++){
   if((await s.pool.query("SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%gk_users%FOR UPDATE%'",[blocker.processID])).rows.length){waiting=true;break;}
   await new Promise(resolve=>setTimeout(resolve,10));
  }
  assert.equal(waiting,true);
  await blocker.query('UPDATE gk_users SET apple_authorization_revoked_at=now() WHERE id=$1',[s.a.user.id]);await blocker.query('COMMIT');
  const response=await request;assert.equal(response.status,401);assert.equal((await response.json()).code,'apple_authorization_revoked');
  assert.equal((await s.pool.query('SELECT count(*) FROM gk_oauth_connections')).rows[0].count,'0');
  assert.equal((await s.pool.query('SELECT status FROM gk_oauth_requests WHERE id=$1',[pending.requestId])).rows[0].status,'pending');
 }finally{await blocker.query('ROLLBACK');blocker.release();if(request)await request.catch(()=>{});}
});
