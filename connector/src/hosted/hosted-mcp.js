import express from 'express';
import {z} from 'zod';
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {requireBearerAuth} from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import {POLICY,ROLE} from '../policy.js';

const TOOL_SCOPES={gatekeeper_status:'gatekeeper:status',gatekeeper_approve:'gatekeeper:approve',gatekeeper_end_access:'gatekeeper:end'};
const instructions=`${ROLE}\nThis hosted connection can operate only on its consenting Gatekeeper account. Select a device explicitly when approving or ending access. Report server approval as pending until a fresh matching phone report acknowledges it. A historical report never proves the phone's current state.`;
const result=value=>({content:[{type:'text',text:JSON.stringify(value)}]});

export function createHostedMcpServer({store,billing,oauth,auth}) {
 const server=new McpServer({name:'rook',version:'1.0.0'},{instructions});
 const safe=(scope,fn)=>async args=>{
  try{
   // Re-read token revocation for each action, including when several requests race.
   const current=await oauth.verifyAccessToken(auth.token);
   if(!current.scopes.includes(scope))throw Object.assign(new Error('This connection does not have the required permission.'),{code:'insufficient_scope'});
   return result(await fn(current.extra.userId,args));
  }catch(error){
   const clientError=(error.status>=400&&error.status<500)||typeof error.errorCode==='string';
   return {isError:true,content:[{type:'text',text:JSON.stringify({error:clientError?error.message:'Service temporarily unavailable.',code:clientError?(error.code??error.errorCode??'request_failed'):'service_unavailable'})}]};
  }
 };
 const write=(scope,fn)=>(userId,args)=>store.withUserLock(userId,async(client,user)=>{
  // Disconnect, refresh replay, deletion and writes all serialize on this user row.
  const current=await oauth.verifyAccessToken(auth.token,client);
  if(current.extra.userId!==user.id||!current.scopes.includes(scope))throw Object.assign(new Error('This connection lacks the required permission.'),{code:'insufficient_scope',status:403});
  return fn(client,user,args);
 });
 if(auth.scopes.includes('gatekeeper:status')){
  server.registerTool('gatekeeper_status',{
   description:'Read policy, cooldown, pending access and timestamped last phone report for your account. Reports are historical; always inspect age before describing device state.',
   inputSchema:{deviceId:z.string().uuid().optional()},annotations:{readOnlyHint:true,openWorldHint:false}
  },safe('gatekeeper:status',async(userId,{deviceId})=>{
   const status=await store.status(userId,deviceId);
   const devices=(await store.listDevices(userId)).filter(device=>!device.revokedAt);
   return {...status,devices,selectedDeviceId:deviceId??null,phoneReportFresh:Boolean(status.lastDeviceReport&&status.lastDeviceReport.ageSeconds<=30),phoneStateConfirmed:false};
  }));
  server.registerResource('gatekeeper-policy','gatekeeper://policy',{mimeType:'text/plain'},safeResource(oauth,auth));
  server.registerPrompt('gatekeeper-role',{description:'Gatekeeper account and approval rules.'},async()=>{
   const current=await oauth.verifyAccessToken(auth.token);if(!current.scopes.includes('gatekeeper:status'))throw new Error('Insufficient scope');
   return {messages:[{role:'user',content:{type:'text',text:instructions}}]};
  });
 }
 if(auth.scopes.includes('gatekeeper:approve'))server.registerTool('gatekeeper_approve',{
  description:'Issue a one-use 1–15 minute pass for an explicit device after judging a concrete purpose and exit plan. This queues delivery and does not confirm phone access. Reuse requestId only for an identical retry.',
  inputSchema:{requestId:z.string().uuid(),deviceId:z.string().uuid(),purpose:z.string().trim().min(8).max(500),exitPlan:z.string().trim().min(8).max(500),durationMinutes:z.number().int().min(POLICY.minDurationMinutes).max(POLICY.maxDurationMinutes)},
  annotations:{readOnlyHint:false,idempotentHint:true,openWorldHint:false}
 },safe('gatekeeper:approve',write('gatekeeper:approve',async(client,user,args)=>{
  await billing.requireAccess(user.id,client);
  const approval=await store.approveInTransaction(client,user,args);
  return {...approval,phoneStateConfirmed:false,instruction:'Approval awaits this phone redeeming the pass. Only a fresh matching phone report acknowledges access; background delivery is not confirmation.'};
 })));
 if(auth.scopes.includes('gatekeeper:end'))server.registerTool('gatekeeper_end_access',{
  description:'Request an early end on the selected device. An offline phone continues its existing local timer until it applies the request; cooldown persists.',
  inputSchema:{deviceId:z.string().uuid()},annotations:{readOnlyHint:false,idempotentHint:true,openWorldHint:false}
 },safe('gatekeeper:end',write('gatekeeper:end',(client,user,{deviceId})=>store.endAccessInTransaction(client,user,deviceId))));
 return server;
}
function safeResource(oauth,auth){return async uri=>{const current=await oauth.verifyAccessToken(auth.token);if(!current.scopes.includes('gatekeeper:status'))throw new Error('Insufficient scope');return {contents:[{uri:uri.href,text:instructions}]};};}

export function createHostedMcpRouter({store,billing,oauth,publicOrigin}) {
 const router=express.Router(),origin=new URL(publicOrigin),metadata=origin.origin+'/.well-known/oauth-protected-resource/mcp';
 // Discovery challenges contain no account data and must be readable before registration.
 // Authenticated requests below additionally bind browser origin to the token's client.
 router.use('/mcp',(req,res,next)=>{
  if(req.headers.origin)res.set({'Access-Control-Allow-Origin':req.headers.origin,'Vary':'Origin','Access-Control-Expose-Headers':'WWW-Authenticate, MCP-Protocol-Version'});
  next();
 });
 router.options('/mcp',(req,res)=>{
  if(req.headers.origin)res.set({'Access-Control-Allow-Origin':req.headers.origin,'Vary':'Origin','Access-Control-Allow-Methods':'POST, GET, DELETE, OPTIONS','Access-Control-Allow-Headers':'Authorization, Content-Type, Accept, MCP-Protocol-Version, Last-Event-ID','Access-Control-Expose-Headers':'WWW-Authenticate, MCP-Protocol-Version'});
  res.sendStatus(204);
 });
 router.use('/mcp',requireBearerAuth({verifier:oauth,expectedResource:oauth.resource,resourceMetadataUrl:metadata}));
 router.use('/mcp',async(req,res,next)=>{
  try{
   if(req.headers.host!==origin.host)return res.sendStatus(403);
   if(req.headers.origin){
    const client=await oauth.getClient(req.auth.clientId);
    if(req.headers.origin!==origin.origin&&!client?.redirect_uris.some(uri=>new URL(uri).origin===req.headers.origin))return res.sendStatus(403);
    res.set({'Access-Control-Allow-Origin':req.headers.origin,'Vary':'Origin','Access-Control-Expose-Headers':'WWW-Authenticate, MCP-Protocol-Version'});
   }
   const bodies=Array.isArray(req.body)?req.body:[req.body];
   for(const body of bodies){
    const required=body?.method==='tools/call'?TOOL_SCOPES[body.params?.name]:['resources/read','prompts/get'].includes(body?.method)?'gatekeeper:status':undefined;
    if(required&&!req.auth.scopes.includes(required))return res.set('WWW-Authenticate',`Bearer error="insufficient_scope", scope="${required}", resource_metadata="${metadata}"`).status(403).json({error:'insufficient_scope',error_description:'The connection lacks the required permission.'});
   }
   next();
  }catch(error){next(error);}
 });
 router.post('/mcp',async(req,res,next)=>{
  const server=createHostedMcpServer({store,billing,oauth,auth:req.auth});
  const transport=new StreamableHTTPServerTransport({sessionIdGenerator:undefined,enableJsonResponse:true,enableDnsRebindingProtection:true,allowedHosts:[origin.host]});
  res.on('close',()=>{void server.close().catch(()=>{});void transport.close().catch(()=>{});});
  try{await server.connect(transport);await transport.handleRequest(req,res,req.body);}catch(error){if(!res.headersSent)next(error);}
 });
 router.all('/mcp',(_req,res)=>res.set('Allow','POST, OPTIONS').status(405).json({error:'method_not_allowed'}));
 return router;
}
