import express from 'express';
import {randomBytes,randomUUID,createHash,createCipheriv,createDecipheriv,timingSafeEqual} from 'node:crypto';
import {mcpAuthRouter,createOAuthMetadata} from '@modelcontextprotocol/sdk/server/auth/router.js';
import {redirectUriMatches} from '@modelcontextprotocol/sdk/server/auth/handlers/authorize.js';
import {InvalidClientMetadataError,InvalidGrantError,InvalidRequestError,InvalidScopeError,InvalidTargetError,InvalidTokenError} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import {HostedError} from './errors.js';
import {createHostedMcpRouter} from './hosted-mcp.js';

export const AGENT_SCOPES = Object.freeze(['gatekeeper:status','gatekeeper:approve','gatekeeper:end']);
const loopback = host => ['127.0.0.1','localhost','[::1]'].includes(host);
const hash = value => createHash('sha256').update(value).digest('hex');
const credential = () => randomBytes(32).toString('base64url');
const escape = value => String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const uuid = value => typeof value==='string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value);
const safeToken = value => typeof value==='string' && /^[a-zA-Z0-9_-]{43}$/.test(value);
function redirectUrl(value) {
 let url;
 try {url=new URL(value);} catch {throw new InvalidClientMetadataError('Invalid redirect URI');}
 if(value.length>2048||url.hash||url.username||url.password||!(url.protocol==='https:'||(url.protocol==='http:'&&loopback(url.hostname)))) throw new InvalidClientMetadataError('Redirect URI must be HTTPS or HTTP loopback, without credentials or fragments');
 return url;
}
function validateScopes(scopes,allowed=AGENT_SCOPES) {
 if(!Array.isArray(scopes)||!scopes.length||scopes.length>AGENT_SCOPES.length||scopes.some(scope=>!allowed.includes(scope)))throw new InvalidScopeError('Unsupported or unconsented scope');
 return [...new Set(scopes)];
}

export class HostedOAuth {
 constructor({store,billing,publicOrigin,encryptionKey}) {
  const origin=new URL(publicOrigin);
  if(origin.pathname!=='/'||origin.search||origin.hash||origin.username||origin.password||!(origin.protocol==='https:'||(origin.protocol==='http:'&&loopback(origin.hostname))))throw new Error('OAuth publicOrigin must be an HTTPS origin or local HTTP loopback origin');
  const key=Buffer.isBuffer(encryptionKey)?encryptionKey:typeof encryptionKey==='string'?Buffer.from(encryptionKey,'base64'):null;
  if(!key||key.length!==32)throw new Error('OAuth requires a durable 32-byte encryptionKey');
  this.store=store;this.pool=store.pool;this.billing=billing;this.publicOrigin=origin.origin;this.resource=this.publicOrigin+'/mcp';this.encryptionKey=key;
  this.skipLocalPkceValidation=true; // SDK forwards the verifier; THIS provider validates it under the code row lock.
  this.clientsStore={getClient:id=>this.getClient(id),registerClient:metadata=>this.registerClient(metadata)};
 }
 now(){return this.store.clock?.()??Date.now();}
 encrypt(value){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.encryptionKey,iv);const encrypted=Buffer.concat([cipher.update(JSON.stringify(value),'utf8'),cipher.final()]);return Buffer.concat([iv,cipher.getAuthTag(),encrypted]).toString('base64');}
 decrypt(value){const raw=Buffer.from(value,'base64'),cipher=createDecipheriv('aes-256-gcm',this.encryptionKey,raw.subarray(0,12));cipher.setAuthTag(raw.subarray(12,28));return JSON.parse(Buffer.concat([cipher.update(raw.subarray(28)),cipher.final()]).toString('utf8'));}
 async transaction(fn){const client=await this.pool.connect();try{await client.query('BEGIN');const value=await fn(client);await client.query('COMMIT');return value;}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}}
 async init(){await this.transaction(async client=>{
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended('gatekeeper-oauth-migrations:'||current_schema(),0))");
  await client.query(`
   CREATE TABLE IF NOT EXISTS gk_oauth_clients(client_id text PRIMARY KEY,metadata jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
   CREATE TABLE IF NOT EXISTS gk_oauth_connections(
    id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES gk_oauth_clients(client_id),scopes text[] NOT NULL,
    issuer text NOT NULL,resource text NOT NULL,created_at timestamptz NOT NULL,revoked_at timestamptz);
   CREATE INDEX IF NOT EXISTS gk_oauth_connections_user ON gk_oauth_connections(user_id);
   CREATE TABLE IF NOT EXISTS gk_oauth_requests(
    id uuid PRIMARY KEY,client_id text NOT NULL REFERENCES gk_oauth_clients(client_id),
    user_id uuid REFERENCES gk_users(id) ON DELETE CASCADE,connection_id uuid REFERENCES gk_oauth_connections(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,scopes text[] NOT NULL,state text,code_challenge text NOT NULL,
    issuer text NOT NULL,resource text NOT NULL,poll_hash text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK(status IN('pending','approved','denied')),
    completion_ciphertext text,code_hash text UNIQUE,code_expires_at timestamptz,code_consumed_at timestamptz,
    expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL);
   CREATE TABLE IF NOT EXISTS gk_oauth_tokens(
    id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
    connection_id uuid NOT NULL REFERENCES gk_oauth_connections(id) ON DELETE CASCADE,
    access_hash text UNIQUE NOT NULL,refresh_hash text UNIQUE NOT NULL,scopes text[] NOT NULL,
    expires_at timestamptz NOT NULL,refresh_expires_at timestamptz NOT NULL,refresh_used_at timestamptz,
    revoked_at timestamptz,created_at timestamptz NOT NULL);
   CREATE INDEX IF NOT EXISTS gk_oauth_tokens_connection ON gk_oauth_tokens(connection_id);
   CREATE INDEX IF NOT EXISTS gk_oauth_requests_expiry ON gk_oauth_requests(issuer,expires_at);
   CREATE INDEX IF NOT EXISTS gk_oauth_tokens_expiry ON gk_oauth_tokens(refresh_expires_at,expires_at);
  `);
 });}
 async getClient(clientId){if(!uuid(clientId))return undefined;return (await this.pool.query('SELECT metadata FROM gk_oauth_clients WHERE client_id=$1',[clientId])).rows[0]?.metadata;}
 async registerClient(metadata){
  if(metadata.token_endpoint_auth_method!=='none'||metadata.client_secret||!Array.isArray(metadata.redirect_uris)||!metadata.redirect_uris.length||metadata.redirect_uris.length>8||typeof metadata.client_name!=='string'||!metadata.client_name.trim()||metadata.client_name.length>200)throw new InvalidClientMetadataError('Only named public clients with registered redirect URIs are supported');
  metadata.redirect_uris.forEach(redirectUrl);
  if((metadata.grant_types??[]).some(value=>!['authorization_code','refresh_token'].includes(value))||(metadata.response_types??[]).some(value=>value!=='code'))throw new InvalidClientMetadataError('Only authorization code with refresh is supported');
  const scopes=metadata.scope?validateScopes(metadata.scope.split(' ')):AGENT_SCOPES;
  // Do not fetch or embed logo/client metadata URLs. A DCR name is unverified.
  const client={client_id:randomUUID(),client_id_issued_at:Math.floor(this.now()/1000),client_name:metadata.client_name.trim(),redirect_uris:[...new Set(metadata.redirect_uris)],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code'],scope:scopes.join(' ')};
  await this.pool.query('INSERT INTO gk_oauth_clients(client_id,metadata) VALUES($1,$2)',[client.client_id,client]);return client;
 }
 requireResource(resource){if(resource?.href!==this.resource)throw new InvalidTargetError('resource must be the Rook MCP resource');}
 async authorize(client,params,res){
  this.requireResource(params.resource);
  redirectUrl(params.redirectUri);
  if(!client.redirect_uris.some(uri=>redirectUriMatches(params.redirectUri,uri)))throw new InvalidRequestError('Unregistered redirect URI');
  if(!/^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge)||params.state?.length>2048)throw new InvalidRequestError('Invalid PKCE S256 challenge or state');
  const scopes=validateScopes(params.scopes?.length?params.scopes:['gatekeeper:status'],client.scope.split(' '));
  const id=randomUUID(),pollSecret=credential(),now=this.now();
  await this.pool.query('DELETE FROM gk_oauth_requests WHERE user_id IS NULL AND expires_at<$1',[new Date(now)]);
  await this.pool.query(`INSERT INTO gk_oauth_requests(id,client_id,redirect_uri,scopes,state,code_challenge,issuer,resource,poll_hash,expires_at,created_at)
   VALUES($1,$2,$3,$4,$5,$6,$7,$7,$8,$9,$10)`,[id,client.client_id,params.redirectUri,scopes,params.state??null,params.codeChallenge,this.resource,hash(pollSecret),new Date(now+600000),new Date(now)]);
  const nonce=credential();
  res.set({'Content-Security-Policy':`default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`,'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'});
  res.type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect an agent — Rook</title><style nonce="${nonce}">body{font:17px system-ui;max-width:36rem;margin:4rem auto;padding:1.5rem;line-height:1.6}a{color:#214e43}code{overflow-wrap:anywhere}</style><main data-request="${id}" data-poll-secret="${pollSecret}"><h1>Connect ${escape(client.client_name)}</h1><p>This client name is supplied by the agent and has not been verified. Check the callback and requested permissions in Rook.</p><p>Callback: <code>${escape(new URL(params.redirectUri).origin)}</code></p><ul>${scopes.map(scope=>`<li>${escape(scope)}</li>`).join('')}</ul><p><a href="gatekeeper://connect-agent?request=${id}">Approve in Rook</a></p><p>If this browser is on your computer, open Rook on your phone and enter this request ID: <code>${id}</code>.</p><p id="status">Waiting for your decision. Keep this browser open.</p></main><script nonce="${nonce}">const node=document.querySelector('main');async function poll(){try{const r=await fetch('/oauth/requests/'+node.dataset.request+'/poll',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pollSecret:node.dataset.pollSecret})});if(!r.ok){document.getElementById('status').textContent='This request has expired. Start the connection again.';return;}const value=await r.json();if(value.redirectURL){location.assign(value.redirectURL);return;}}catch{}setTimeout(poll,2000);}poll();</script></html>`);
 }
 async request(requestId){
  if(!uuid(requestId))throw new HostedError('Request was not found.','not_found',404);
  const row=(await this.pool.query('SELECT r.*,c.metadata FROM gk_oauth_requests r JOIN gk_oauth_clients c USING(client_id) WHERE r.id=$1 AND r.expires_at>$2 AND r.issuer=$3 AND r.resource=$3',[requestId,new Date(this.now()),this.resource])).rows[0];
  if(!row)throw new HostedError('Request has expired.','request_expired',410);
  return {id:row.id,clientName:row.metadata.client_name,redirectURI:row.redirect_uri,scopes:row.scopes,status:row.status,expiresAt:row.expires_at.toISOString()};
 }
 async decide(userId,requestId,approve){
  if(!uuid(requestId)||typeof approve!=='boolean')throw new HostedError('Invalid consent decision.');
  return this.store.withUserLock(userId,async(client,user)=>{
   if(user.apple_authorization_revoked_at)throw new HostedError('Apple authorization is no longer valid. Sign in again.','apple_authorization_revoked',401);
   const row=(await client.query('SELECT * FROM gk_oauth_requests WHERE id=$1 FOR UPDATE',[requestId])).rows[0];
   if(!row||row.expires_at.getTime()<=this.now()||row.issuer!==this.resource||row.resource!==this.resource)throw new HostedError('Request has expired.','request_expired',410);
   if(row.status!=='pending'){
    if(row.user_id!==userId||((row.status==='approved')!==approve))throw new HostedError('Request was already decided.','request_decided',409);
    return {...this.decrypt(row.completion_ciphertext),requiresOriginalBrowser:true};
   }
   const redirect=new URL(row.redirect_uri);
   for(const reserved of ['code','error','error_description','error_uri','state','iss'])redirect.searchParams.delete(reserved);
   if(row.state!==null)redirect.searchParams.set('state',row.state);redirect.searchParams.set('iss',this.resource);
   let connectionId=null,codeHash=null;
   if(approve){
    const code=credential();codeHash=hash(code);connectionId=randomUUID();redirect.searchParams.set('code',code);
    await client.query('INSERT INTO gk_oauth_connections(id,user_id,client_id,scopes,issuer,resource,created_at) VALUES($1,$2,$3,$4,$5,$5,$6)',[connectionId,userId,row.client_id,row.scopes,this.resource,new Date(this.now())]);
   }else redirect.searchParams.set('error','access_denied');
   const completion={redirectURL:redirect.href};
   await client.query(`UPDATE gk_oauth_requests SET user_id=$1,connection_id=$2,status=$3,code_hash=$4,code_expires_at=$5,completion_ciphertext=$6 WHERE id=$7`,[userId,connectionId,approve?'approved':'denied',codeHash,approve?new Date(this.now()+300000):null,this.encrypt(completion),requestId]);
   return {...completion,requiresOriginalBrowser:true};
  });
 }
 async poll(requestId,pollSecret){
  if(!uuid(requestId)||!safeToken(pollSecret))throw new HostedError('Invalid browser completion credential.','poll_forbidden',403);
  const row=(await this.pool.query('SELECT * FROM gk_oauth_requests WHERE id=$1',[requestId])).rows[0];
  if(!row||!timingSafeEqual(Buffer.from(hash(pollSecret)),Buffer.from(row.poll_hash)))throw new HostedError('Invalid browser completion credential.','poll_forbidden',403);
  if(row.expires_at.getTime()<=this.now()||row.issuer!==this.resource)throw new HostedError('Request has expired.','request_expired',410);
  return row.status==='pending'?{status:'pending'}:{status:row.status,...this.decrypt(row.completion_ciphertext)};
 }
 async challengeForAuthorizationCode(client,code){
  if(!safeToken(code))throw new InvalidGrantError('Invalid authorization code');
  const row=(await this.pool.query('SELECT code_challenge FROM gk_oauth_requests WHERE code_hash=$1 AND client_id=$2 AND code_consumed_at IS NULL AND code_expires_at>$3',[hash(code),client.client_id,new Date(this.now())])).rows[0];
  if(!row)throw new InvalidGrantError('Invalid authorization code');return row.code_challenge;
 }
 async issueTokens(client,connection,scopes,refreshExpiry=new Date(this.now()+30*86400000)){
  const now=this.now(),access=credential(),refresh=credential(),expires=new Date(Math.min(now+3600000,refreshExpiry.getTime()));
  await client.query('INSERT INTO gk_oauth_tokens(id,user_id,connection_id,access_hash,refresh_hash,scopes,expires_at,refresh_expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[randomUUID(),connection.user_id,connection.id,hash(access),hash(refresh),scopes,expires,refreshExpiry,new Date(this.now())]);
  return {access_token:access,token_type:'Bearer',expires_in:Math.max(0,Math.floor((expires.getTime()-now)/1000)),refresh_token:refresh,scope:scopes.join(' ')};
 }
 async exchangeAuthorizationCode(client,code,codeVerifier,redirectURI,resource){
  this.requireResource(resource);
  if(!safeToken(code)||typeof codeVerifier!=='string'||!/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier))throw new InvalidGrantError('Invalid authorization code or verifier');
  const owner=(await this.pool.query('SELECT user_id FROM gk_oauth_requests WHERE code_hash=$1',[hash(code)])).rows[0]?.user_id;
  if(!owner)throw new InvalidGrantError('Invalid authorization code');
  return this.transaction(async tx=>{
   const user=(await tx.query('SELECT id,apple_authorization_revoked_at FROM gk_users WHERE id=$1 FOR UPDATE',[owner])).rows[0];
   if(!user||user.apple_authorization_revoked_at)throw new InvalidGrantError('Account authorization is no longer valid');
   const row=(await tx.query('SELECT * FROM gk_oauth_requests WHERE code_hash=$1 FOR UPDATE',[hash(code)])).rows[0];
   if(!row||row.user_id!==owner||row.client_id!==client.client_id||row.status!=='approved'||row.code_consumed_at||row.code_expires_at.getTime()<=this.now()||row.redirect_uri!==redirectURI||row.resource!==this.resource||row.issuer!==this.resource||createHash('sha256').update(codeVerifier).digest('base64url')!==row.code_challenge)throw new InvalidGrantError('Invalid, expired or already used authorization code');
   const connection=(await tx.query('SELECT * FROM gk_oauth_connections WHERE id=$1 AND revoked_at IS NULL FOR UPDATE',[row.connection_id])).rows[0];
   if(!connection||connection.user_id!==owner||connection.client_id!==client.client_id||connection.issuer!==this.resource||connection.resource!==this.resource)throw new InvalidGrantError('Connection was revoked');
   await tx.query('UPDATE gk_oauth_requests SET code_consumed_at=$1 WHERE id=$2',[new Date(this.now()),row.id]);
   return this.issueTokens(tx,connection,row.scopes);
  });
 }
 async exchangeRefreshToken(client,refresh,scopes,resource){
  this.requireResource(resource);if(!safeToken(refresh))throw new InvalidGrantError('Invalid refresh token');
  const found=(await this.pool.query('SELECT user_id,connection_id FROM gk_oauth_tokens WHERE refresh_hash=$1',[hash(refresh)])).rows[0];
  if(!found)throw new InvalidGrantError('Invalid refresh token');
  // Revocation on replay must COMMIT, so throw only after the transaction returns.
  const result=await this.transaction(async tx=>{
   const user=(await tx.query('SELECT id,apple_authorization_revoked_at FROM gk_users WHERE id=$1 FOR UPDATE',[found.user_id])).rows[0];
   if(!user||user.apple_authorization_revoked_at)return null;
   const connection=(await tx.query('SELECT * FROM gk_oauth_connections WHERE id=$1 FOR UPDATE',[found.connection_id])).rows[0];
   if(!connection||connection.user_id!==found.user_id||connection.client_id!==client.client_id||connection.issuer!==this.resource||connection.resource!==this.resource)return null;
   const row=(await tx.query('SELECT * FROM gk_oauth_tokens WHERE refresh_hash=$1 FOR UPDATE',[hash(refresh)])).rows[0];
   if(connection.revoked_at||!row||row.user_id!==found.user_id||row.connection_id!==found.connection_id)return null;
   if(row.refresh_used_at){await tx.query('UPDATE gk_oauth_connections SET revoked_at=$1 WHERE id=$2',[new Date(this.now()),connection.id]);await tx.query('UPDATE gk_oauth_tokens SET revoked_at=$1 WHERE connection_id=$2',[new Date(this.now()),connection.id]);return null;}
   if(row.revoked_at||row.refresh_expires_at.getTime()<=this.now())return null;
   const granted=validateScopes(scopes??row.scopes,row.scopes);
   await tx.query('UPDATE gk_oauth_tokens SET refresh_used_at=$1,revoked_at=$1 WHERE id=$2',[new Date(this.now()),row.id]);
   return this.issueTokens(tx,connection,granted,row.refresh_expires_at);
  });
  if(!result)throw new InvalidGrantError('Invalid, expired or replayed refresh token');return result;
 }
 async verifyAccessToken(token,executor=this.pool){
  if(!safeToken(token))throw new InvalidTokenError('Invalid agent token');
  const row=(await executor.query(`SELECT t.*,c.client_id,c.issuer,c.resource,c.revoked_at AS connection_revoked_at,u.apple_authorization_revoked_at FROM gk_oauth_tokens t JOIN gk_oauth_connections c ON c.id=t.connection_id JOIN gk_users u ON u.id=t.user_id WHERE t.access_hash=$1`,[hash(token)])).rows[0];
  if(!row||row.apple_authorization_revoked_at||row.revoked_at||row.connection_revoked_at||row.expires_at.getTime()<=this.now()||row.issuer!==this.resource||row.resource!==this.resource)throw new InvalidTokenError('Invalid, expired or revoked agent token');
  return {token,clientId:row.client_id,scopes:row.scopes,expiresAt:Math.floor(row.expires_at.getTime()/1000),resource:new URL(this.resource),extra:{userId:row.user_id,connectionId:row.connection_id}};
 }
 async connections(userId){return (await this.pool.query('SELECT c.*,cl.metadata FROM gk_oauth_connections c JOIN gk_oauth_clients cl USING(client_id) WHERE user_id=$1 AND revoked_at IS NULL AND issuer=$2 AND resource=$2 ORDER BY created_at DESC',[userId,this.resource])).rows.map(row=>({id:row.id,clientName:row.metadata.client_name,scopes:row.scopes,createdAt:row.created_at.toISOString()}));}
 async disconnect(userId,connectionId){return this.store.withUserLock(userId,async tx=>{
  const row=(await tx.query('UPDATE gk_oauth_connections SET revoked_at=$1 WHERE id=$2 AND user_id=$3 AND issuer=$4 AND resource=$4 RETURNING id',[new Date(this.now()),connectionId,userId,this.resource])).rows[0];
  if(!row)throw new HostedError('Connection was not found.','not_found',404);
  await tx.query('UPDATE gk_oauth_tokens SET revoked_at=$1 WHERE connection_id=$2',[new Date(this.now()),connectionId]);return {revoked:true};
 });}
 async revokeToken(client,{token}){
  if(!safeToken(token))return;
  const found=(await this.pool.query('SELECT t.user_id FROM gk_oauth_tokens t JOIN gk_oauth_connections c ON c.id=t.connection_id WHERE c.client_id=$1 AND c.issuer=$3 AND c.resource=$3 AND (access_hash=$2 OR refresh_hash=$2)',[client.client_id,hash(token),this.resource])).rows[0];
  if(!found)return;
  await this.transaction(async tx=>{
   if(!(await tx.query('SELECT id FROM gk_users WHERE id=$1 FOR UPDATE',[found.user_id])).rows.length)return;
   const row=(await tx.query('SELECT connection_id FROM gk_oauth_tokens t JOIN gk_oauth_connections c ON c.id=t.connection_id WHERE c.client_id=$1 AND c.issuer=$3 AND c.resource=$3 AND (access_hash=$2 OR refresh_hash=$2)',[client.client_id,hash(token),this.resource])).rows[0];
   if(!row)return;
   await tx.query('UPDATE gk_oauth_connections SET revoked_at=$1 WHERE id=$2',[new Date(this.now()),row.connection_id]);await tx.query('UPDATE gk_oauth_tokens SET revoked_at=$1 WHERE connection_id=$2',[new Date(this.now()),row.connection_id]);
  });
 }
 async prune(){
  const now=new Date(this.now()),grace=new Date(this.now()-3600000);
  return this.transaction(async tx=>{
   const requests=await tx.query('DELETE FROM gk_oauth_requests WHERE issuer=$1 AND resource=$1 AND expires_at<$2',[this.resource,grace]);
   // Used refresh hashes remain until their ORIGINAL absolute refresh deadline,
   // so pruning cannot erase the replay detector for a still-live family.
   const tokens=await tx.query(`DELETE FROM gk_oauth_tokens t USING gk_oauth_connections c
    WHERE t.connection_id=c.id AND c.issuer=$1 AND c.resource=$1
      AND t.refresh_expires_at<$2 AND t.expires_at<$3`,[this.resource,grace,now]);
   return {requestsDeleted:requests.rowCount,tokensDeleted:tokens.rowCount};
  });
 }
 router(){
  const router=express.Router(),options={provider:this,issuerUrl:new URL(this.resource),baseUrl:new URL(this.publicOrigin),resourceServerUrl:new URL(this.resource),resourceName:'Rook',scopesSupported:AGENT_SCOPES};
  // SDK metadata advertises client_secret_post generically; our provider supports public clients only.
  const metadata={...createOAuthMetadata(options),token_endpoint_auth_methods_supported:['none'],revocation_endpoint_auth_methods_supported:['none'],authorization_response_iss_parameter_supported:true};
  router.get(['/.well-known/oauth-authorization-server','/.well-known/oauth-authorization-server/mcp'],(_req,res)=>res.set('Access-Control-Allow-Origin','*').json(metadata));
  router.use(mcpAuthRouter(options));
  router.post('/oauth/requests/:id/poll',express.json({limit:'2kb'}),async(req,res,next)=>{
   try{if(req.headers.origin&&req.headers.origin!==this.publicOrigin)throw new HostedError('Browser origin is not allowed.','poll_forbidden',403);res.set('Cache-Control','no-store').json(await this.poll(req.params.id,req.body?.pollSecret));}catch(error){next(error);}
  });
  router.use(createHostedMcpRouter({store:this.store,billing:this.billing,oauth:this,publicOrigin:this.publicOrigin}));
  return router;
 }
}
