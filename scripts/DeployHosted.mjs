import {spawn,spawnSync} from 'node:child_process';
import {mkdtemp,cp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const value=name=>{const i=process.argv.indexOf(name);return i<0?undefined:process.argv[i+1];};
const project=value('--project'),service=value('--service'),environment=value('--environment');
if(![project,service,environment].every(x=>/^[a-f0-9-]{36}$/i.test(x??'')))throw new Error('Provide explicit --project, --service, and --environment UUIDs.');
const check=spawnSync('railway',['status','--json'],{encoding:'utf8'});
if(check.status!==0)throw new Error('Cannot inspect Railway link.');
const status=JSON.parse(check.stdout);
if(status.id!==project||!status.services.edges.some(x=>x.node.id===service)||!status.environments.edges.some(x=>x.node.id===environment))throw new Error('Railway link or target does not match. Link the intended hosted project first.');
const source=new URL('../connector/',import.meta.url),stage=await mkdtemp(join(tmpdir(),'rook-hosted-deploy-'));
try{
 for(const path of ['src','config','package.json','package-lock.json'])await cp(new URL(path,source),join(stage,path),{recursive:true});
 await cp(new URL('Dockerfile.hosted',source),join(stage,'Dockerfile'));
 console.log('Uploading only hosted source and pinned public certificates to the verified service.');
 const child=spawn('railway',['up','--detach','--path-as-root',stage,'--service',service,'--environment',environment],{stdio:'inherit'});
 const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('exit',resolve);});
 if(code!==0)throw new Error('Hosted upload failed.');
 console.log('Upload accepted. Check deployment status and live /ready before claiming release readiness.');
}finally{await rm(stage,{recursive:true,force:true});}
