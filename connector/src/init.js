import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
// Exclusive creation avoids invalidating a paired phone by accidentally rotating credentials.
writeFileSync('.env', `PUBLIC_ORIGIN=http://127.0.0.1:8787\nHOST=127.0.0.1\nPORT=8787\nDATA_PATH=./data/gatekeeper.sqlite\nMUSE_TOKEN=${randomBytes(32).toString('hex')}\nDEVICE_TOKEN=${randomBytes(32).toString('hex')}\n`, { flag: 'wx', mode: 0o600 });
console.log('Created private .env. Configure a public HTTPS origin before connecting the iPhone or remote Muse. Store credentials in secure connector configuration, never in chat or memory.');
