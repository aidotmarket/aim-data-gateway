// Real local workerd + SQLite DO storage; no remote bindings or cloud calls.
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { generateKeyPairSync, sign } from "node:crypto";
import assert from "node:assert/strict";
import { mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
const {privateKey, publicKey} = generateKeyPairSync("ed25519");
const publicRaw = publicKey.export({type:"spki",format:"der"}).subarray(-32).toString("base64");
const folder = resolve("artifacts/ledger-state"); await mkdir(resolve("artifacts"),{recursive:true}); await rm(folder,{recursive:true,force:true});
function instance() { return new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:folder, workers:[{name:"ledger-test",
  modules:[{type:"ESModule",path:resolve("ledger/test-worker.mjs")},{type:"ESModule",path:resolve("ledger/ledger.mjs")}], modulesRoot:process.cwd(),
  compatibilityDate:"2026-10-04",
  durableObjects:{LEDGER:{className:"Ledger",useSQLite:true}},
  bindings:{SPIKE_SPEC_PUBLIC_KEY_B64:publicRaw,LISTING_ID:"synthetic-listing",LISTING_VERSION_ID:"synthetic-v1"}
}]})); }
function spec(n, overrides={}) { return {
 listing_id:"synthetic-listing",listing_version_id:"synthetic-v1",nonce:`nonce-${n}`,owner_authorization_id:`auth-${n}`,
 accepted_at_utc:new Date().toISOString(),issued_at_utc:new Date().toISOString(),
 event:{mode:"scan",bucket:"synthetic",objects:[{key:"spike/file.csv",etag:'"fixture"',format:"csv"}]},...overrides
}; }
function envelope(s) { const payload=Buffer.from(JSON.stringify(s)); return {payload_b64:payload.toString("base64"),signature_b64:sign(null,payload,privateKey).toString("base64")}; }
async function post(mf, body) { return mf.dispatchFetch("http://local/",{method:"POST",body:JSON.stringify(body)}); }
async function refused(mf,s,why) { const r=await post(mf,envelope(s));assert.equal(r.status,409);assert.match((await r.json()).error,new RegExp(why)); }
let mf=instance();
try {
 assert.equal((await post(mf,envelope(spec(1)))).status,200);
 await refused(mf,spec(1),"replay");
 await refused(mf,spec(2,{owner_authorization_id:"auth-1"}),"replay");
 await refused(mf,spec(2,{nonce:"nonce-1"}),"replay");
 const duplicate=envelope(spec(2));const statuses=(await Promise.all([post(mf,duplicate),post(mf,duplicate)])).map(r=>r.status).sort();assert.deepEqual(statuses,[200,409]);
 await refused(mf,spec(100,{listing_version_id:"other"}),"wrong_version");
 await refused(mf,spec(101,{issued_at_utc:new Date(Date.now()-25*3600000).toISOString()}),"expired_spec");
 await refused(mf,spec(102,{owner_authorization_id:""}),"missing_binding");
 const bad=envelope(spec(103));bad.signature_b64=Buffer.alloc(64).toString("base64");assert.equal((await post(mf,bad)).status,409);
 for(let i=3;i<=10;i++) assert.equal((await post(mf,envelope(spec(i)))).status,200);
 await refused(mf,spec(11),"daily_limit");
 await mf.dispose();mf=instance();
 await refused(mf,spec(1),"replay");await refused(mf,spec(11),"daily_limit");
 console.log("PASS: signature, bindings, expiry, nonce/auth replay, concurrent duplicate, tenth/eleventh, cold restart");
} finally { await mf.dispose(); }
