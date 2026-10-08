import pg from 'pg';
import { randomUUID } from 'node:crypto';
import { HostedStore } from '../../src/hosted/store.js';
export async function database(t) {
 const url=process.env.TEST_DATABASE_URL;
 if(!url) throw new Error('TEST_DATABASE_URL must point to real PostgreSQL for hosted tests');
 const admin=new pg.Pool({connectionString:url});
 const schema=`root_${randomUUID().replaceAll('-','')}`;
 await admin.query(`CREATE SCHEMA ${schema}`);
 const pool=new pg.Pool({connectionString:url,options:`-c search_path=${schema}`});
 const store=new HostedStore(pool); await store.migrate();
 t.after(async()=>{await pool.end();await admin.query(`DROP SCHEMA ${schema} CASCADE`);await admin.end();});
 return {pool,store};
}
export async function account(store,name='owner') {
 const user=await store.upsertUser({appleSub:`test-${name}-${randomUUID()}`});
 const device=await store.registerDevice(user.id,{installationId:randomUUID(),name:'iPhone'});
 const session=await store.createSession(user.id,{deviceId:device.id});
 return {user,device,session};
}
