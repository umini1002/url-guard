import {cpSync,mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=fileURLToPath(new URL('..',import.meta.url));
const value=(process.env.API_BASE_URL||'').trim().replace(/\/+$/,'');
if(!value)throw new Error('Set the repository Actions variable API_BASE_URL to the deployed Python server origin.');
let api;
try{api=new URL(value);}catch{throw new Error('API_BASE_URL must be an absolute HTTPS origin');}
if(api.protocol!=='https:' || api.username || api.password || api.pathname!=='/' || api.search || api.hash)
  throw new Error('API_BASE_URL must be an HTTPS origin without credentials, paths or query strings');
const output=path.join(root,'_site');mkdirSync(output,{recursive:true});
cpSync(path.join(root,'public'),output,{recursive:true});
writeFileSync(path.join(output,'config.js'),'globalThis.URL_GUARD_CONFIG = '+JSON.stringify({apiBase:api.origin})+';\n');
writeFileSync(path.join(output,'.nojekyll'),'');
for(const name of ['index.html','app.js','style.css','samples.json','config.js'])readFileSync(path.join(output,name));
console.log('GitHub Pages files prepared; Python API: '+api.origin);
