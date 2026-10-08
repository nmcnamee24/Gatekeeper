import {readFile,writeFile} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
const destination=new URL('../connector/.env.hosted',import.meta.url);
const template=await readFile(new URL('../connector/.env.hosted.example',import.meta.url),'utf8');
const text=template.replace(/^CREDENTIAL_ENCRYPTION_KEY=.*$/m,'CREDENTIAL_ENCRYPTION_KEY='+randomBytes(32).toString('base64'))
 .replace(/^PURCHASE_BINDING_KEY=.*$/m,'PURCHASE_BINDING_KEY='+randomBytes(32).toString('base64'));
try{await writeFile(destination,text,{mode:0o600,flag:'wx'});console.log('Created private connector/.env.hosted. Configure Apple and AI credentials there; never commit it.');}
catch(error){if(error.code==='EEXIST'){console.log('Existing private configuration preserved.');}else throw error;}
