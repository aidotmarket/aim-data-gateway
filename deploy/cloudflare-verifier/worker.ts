import { Container, type OutboundHandlerContext } from "@cloudflare/containers";
export { ContainerProxy } from "@cloudflare/containers";
import { Ledger, LEASE_GRACE, refuse, type Admission, type Job, type Member } from "./state";
import { b64, unb64, utf8, random, sha, canonical, encrypt, decrypt, equalSecret, bounded, now } from "./crypto";

type Env = Omit<RuntimeEnv,"VERIFIER"> & { VERIFIER: DurableObjectNamespace<CloudflareVerifier>; REGISTRATION_TOKEN: string; RUN_NOW_SECRET: string };

type Identity = {mode: "bundle" | "source_tree_lockfile"; sha256: string};
type Config = {connection_id:string;bucket:string;prefix:string;jurisdiction:string;keys:string[];release_id:string;scanner_version:string;binary_sha256:string;worker_identity:Identity;registration_token?:string};
type Secret = {Private:string;Commitment:number[];Runner:string;Receipt:string;Version:string;Digest:string;Connection:string;Release:string;Worker:Identity;Registration:string;Nonce:string;Ack:string;Pins:unknown[]};
type Prepared = {job:Job;snapshot:string;objects:Member[];rotation?:boolean;secret?:Secret};

export function config(env: Env): Config {
  const c:Config=JSON.parse(env.DEPLOYMENT_CONFIG);
  if (!/^[0-9a-f-]{36}$/.test(c.connection_id) || !c.bucket || c.jurisdiction!=="default" || !Array.isArray(c.keys) || c.keys.length===0 || c.keys.length>17033 || utf8.encode(canonical(c)).length>1048576 || c.keys.some(k=>!k || k.includes("\0") || !k.startsWith(c.prefix)) || new Set(c.keys).size!==c.keys.length || !/^[a-f0-9]{64}$/.test(c.binary_sha256) || !/^[a-f0-9]{64}$/.test(c.worker_identity.sha256) || !["bundle","source_tree_lockfile"].includes(c.worker_identity.mode)) refuse();
  return c;
}
async function signingKey(secret: Secret): Promise<CryptoKey> {
  // Go stores the raw Ed25519 private key (seed || public); PKCS8 wraps the seed.
  const seed=unb64(secret.Private.replaceAll("+","-").replaceAll("/","_"));
  if(seed.length!==64)refuse();
  const der=new Uint8Array(48);der.set([48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32]);der.set(seed.slice(0,32),16);
  return crypto.subtle.importKey("pkcs8",der,{name:"Ed25519"},false,["sign"]);
}
async function marketplace(c: Config,s: Secret,path: string,body: string,limit: number): Promise<string> {
  if(!/^\/api\/v1\/verification-runners\/[a-f0-9-]{36}\/(work|report)$/.test(path))refuse();
  const claims={runner_id:s.Runner,kind:"cloudflare",connection_id:c.connection_id,release_id:c.release_id,scanner_version:c.scanner_version,binary_sha256:c.binary_sha256,worker_identity:c.worker_identity,method:"POST",path,nonce:random(),iat:now(),body_sha256:await sha(body)};
  const token=b64(utf8.encode(canonical({alg:"EdDSA",typ:"aim-verification-request+jwt",kid:s.Receipt})))+"."+b64(utf8.encode(canonical(claims)));
  const jws=token+"."+b64(new Uint8Array(await crypto.subtle.sign("Ed25519",await signingKey(s),utf8.encode(token))));
  if(jws.length>4096)refuse();
  const response=await fetch("https://api.ai.market"+path,{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+jws},body,redirect:"manual",signal:AbortSignal.timeout(30000)});
  if(response.status!==200)refuse();return bounded(response,limit);
}
async function capability(wrap: string, payload: object): Promise<string> {
  const text=b64(utf8.encode(canonical(payload)));
  const key=await crypto.subtle.importKey("raw",unb64(wrap),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return text+"."+b64(new Uint8Array(await crypto.subtle.sign("HMAC",key,utf8.encode("bridge-v1."+text))));
}

export class CloudflareVerifier extends Container<Env> {
  defaultPort=8080;
  sleepAfter="20m";
  enableInternet=true;
  readonly ledger:Ledger;
  static outboundByHost={
    "r2-bridge.internal": async (request:Request, env:Env, ctx:OutboundHandlerContext) => {
      const u=new URL(request.url);
      if(u.protocol!=="http:" || u.hostname!=="r2-bridge.internal" || (u.port && u.port!=="80"))return new Response("verification_refused",{status:403});
      // ctx.containerId is supplied by ContainerProxy, never public input.
      return env.VERIFIER.get(env.VERIFIER.idFromString(ctx.containerId)).fetch(request);
    },
  };
  constructor(ctx:DurableObjectState<{}>,env:Env) {
    super(ctx,env);this.ledger=new Ledger(ctx.storage);
  }
  async fetch(request:Request):Promise<Response> {
    // This entrypoint is reachable only from the private outbound handler.
    try {return await this.bridge(request);}catch{return new Response("verification_refused",{status:403});}
  }
  async bridge(request:Request):Promise<Response> {
    const u=new URL(request.url);
    if(u.protocol!=="http:" || u.hostname!=="r2-bridge.internal" || u.search || !["HEAD","GET"].includes(request.method) || !/^\/member\/(0|[1-9][0-9]*)$/.test(u.pathname))refuse();
    const c=config(this.env),r=this.ledger.active(),wrap=this.ledger.get("wrap"),saved=this.ledger.get("capability");
    const token=request.headers.get("Authorization")?.replace(/^Bearer /,"");
    if(!r || r.state!=="accepted" || !wrap || !saved || !token || token.length>4096 || !(await equalSecret(token,saved)))refuse();
    const parts=token.split(".");if(parts.length!==2)refuse();
    const p=JSON.parse(new TextDecoder().decode(unb64(parts[0])));
    if(await capability(wrap,p)!==token || p.connection!==c.connection_id || p.spec!==r.hash || p.id!==this.ctx.id.toString() || p.start!==r.start || now()>p.exp || now()>r.start+780)refuse();
    const index=Number(u.pathname.slice(8)),m=r.objects[index];
    if(!m || !c.keys.includes(m.Key) || !m.Key.startsWith(c.prefix))refuse();
    let range:{offset:number;length:number}|undefined;
    const header=request.headers.get("Range");
    if(header){
      const match=/^bytes=(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$/.exec(header);
      if(!match || request.method!=="GET")refuse();
      const offset=Number(match[1]),end=Number(match[2]);
      if(!Number.isSafeInteger(offset) || !Number.isSafeInteger(end) || end<offset || end>=m.Size)refuse();
      range={offset,length:end-offset+1};
    }
    if(request.method==="HEAD") {
      const head=await this.env.SOURCE.head(m.Key);
      if(!head || head.etag!==m.ETag || head.size!==m.Size)refuse();
      return new Response(null,{headers:{"X-Object-Size":String(head.size),"X-Object-Etag":head.etag,"Cache-Control":"no-store"}});
    }
    const object=await this.env.SOURCE.get(m.Key,{onlyIf:{etagMatches:m.ETag},...(range?{range}:{})});
    if(!object || object.etag!==m.ETag || object.size!==m.Size || !("body" in object) || !object.body)refuse();
    const headers=new Headers({"X-Object-Size":String(object.size),"X-Object-Etag":object.etag,"Cache-Control":"no-store"});
    if(range){
      const got=object.range;
      if(!got || !("offset" in got) || !("length" in got) || got.offset!==range.offset || got.length!==range.length)refuse();
      headers.set("X-Range-Offset",String(range.offset));headers.set("X-Range-Length",String(range.length));
    }else if(object.range && (!("offset" in object.range) || !("length" in object.range) || object.range.offset!==0 || object.range.length!==m.Size))refuse();
    return new Response(object.body,{status:range?206:200,headers});
  }
  async enqueue():Promise<void> {
    config(this.env);
    if(this.ledger.wake(now())){
      try {await this.schedule(1,"pollTask");}
      catch(e){this.ledger.release();throw e;}
    }
  }
  async save(secret:Secret,c:Config):Promise<void> {
    const wrap=this.ledger.get("wrap")??refuse();
    const cipher=await encrypt(wrap,c.connection_id,secret);
    this.ctx.storage.transactionSync(()=>{this.ledger.put("secret",cipher);this.ledger.put("bootstrap","saved");});
  }
  async load(c:Config):Promise<Secret> {
    const wrap=this.ledger.get("wrap"),cipher=this.ledger.get("secret");if(!wrap || !cipher)refuse();
    const s=await decrypt<Secret>(wrap,c.connection_id,cipher);
    if(s.Connection!==c.connection_id || s.Version!==c.scanner_version || s.Release!==c.release_id || s.Digest!==c.binary_sha256 || canonical(s.Worker)!==canonical(c.worker_identity))refuse();return s;
  }
  async compute<T>(path:string,c:Config,secret?:Secret,extra:object={}):Promise<T> {
    const response=await this.containerFetch("http://localhost"+path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({config:c,...(secret?{secret}:{}),...extra}),signal:AbortSignal.timeout(890000)});
    if(response.status!==200)refuse();return JSON.parse(await bounded(response,18<<20));
  }
  async recover(c:Config,s:Secret):Promise<void> {
    let r=this.ledger.active();if(!r)return;
    if(now()>r.pickup+1920){this.ledger.settle(r,"expired",now());return;}
    if(r.state!=="committed"){
      if(now()<=r.start+LEASE_GRACE)refuse();
      if(r.variant==="probe"){this.ledger.settle(r,"interrupted",now());return;}
      const terminal=await this.compute<{body:string}>("/terminal",c,s,{token:r.token,pickup:r.pickup});
      this.ledger.commit(r,terminal.body,await sha(terminal.body),now());r=this.ledger.active()??refuse();
    }
    const out=this.ledger.body(r);
    if(await sha(out.body)!==out.hash || now()>r.pickup+1920)refuse();
    const raw=await marketplace(c,s,"/api/v1/verification-runners/"+s.Runner+"/report",out.body,4096);
    const ack=JSON.parse(raw);
    if(canonical(ack)!==raw || Object.keys(ack).sort().join(" ")!=="iid status" || ack.iid!==r.iid || ack.status!=="stored")refuse();
    this.ledger.settle(r,"reported",now());
    console.log(JSON.stringify({event:"reported",hash:r.hash}));
  }
  async pollTask():Promise<void> {
    const start=now();
    if(!this.ledger.claim(start)){
      // SDK 0.3.7 deletes this one-shot schedule on normal return. Preserve
      // recovery with a new schedule beyond the running task's lease grace.
      await this.schedule(Math.max(1,Number(this.ledger.get("lease"))+LEASE_GRACE+1-start),"pollTask");
      return;
    }
    try {
      const c=config(this.env);
      if(!this.ledger.get("bootstrap")){
        if(!this.ledger.firstStart(random(),now()))refuse();
        const sec=await this.compute<Secret>("/create",{...c,registration_token:this.env.REGISTRATION_TOKEN});await this.save(sec,c);
      }
      let sec=await this.load(c);
      if(!sec.Runner){sec=await this.compute<Secret>("/register",c,sec);await this.save(sec,c);}
      // No poll can precede committed-outbox recovery, including empty wakes.
      await this.recover(c,sec);
      const pickup=now();
      const raw=await marketplace(c,sec,"/api/v1/verification-runners/"+sec.Runner+"/work","{}",64<<10);
      const response=JSON.parse(raw);
      if(canonical(response)!==raw || Object.keys(response).join()!=="work_jws" || !(response.work_jws===null || typeof response.work_jws==="string"))refuse();
      this.ledger.put("last_poll",String(now()));
      if(response.work_jws===null)return;
      const token:string=response.work_jws,hash=await sha(token);
      this.ledger.event("received",hash,now());
      console.log(JSON.stringify({event:"received",hash}));
      // Exact replay is recognized before snapshot fetch or compute restart.
      const replay=this.ctx.storage.sql.exec<{record:string}>("SELECT record FROM admissions WHERE json_extract(record,'$.token')=?",token).toArray()[0];
      if(replay)return;
      const prepared=await this.compute<Prepared>("/prepare",c,sec,{token});
      if(prepared.rotation && prepared.secret){await this.save(prepared.secret,c);return;}
      const admitted=this.ledger.admit(prepared.job,prepared.snapshot,prepared.objects,now(),pickup,start);
      if(!admitted)return;
      console.log(JSON.stringify({event:"accepted",hash:admitted.hash}));
      const cap=await capability(this.ledger.get("wrap")??refuse(),{connection:c.connection_id,spec:admitted.hash,start:admitted.start,exp:admitted.start+780,id:this.ctx.id.toString(),nonce:random()});
      this.ledger.put("capability",cap);
      const result=await this.compute<{body:string}>("/execute",c,sec,{token,snapshot:prepared.snapshot,capability:cap,start,pickup});
      this.ledger.commit(admitted,result.body,await sha(result.body),now());
      console.log(JSON.stringify({event:"committed",hash:admitted.hash}));
      await this.recover(c,sec);
    } catch {
      this.ledger.event("refused","",now());
      console.log(JSON.stringify({event:"refused"}));
      // A subsequent schedule retries recovery, never an admitted traversal.
      await this.schedule(60,"pollTask");
    } finally {
      this.ledger.release();this.ledger.prune(now());
      await this.stop();
    }
  }
}

export default {
  async fetch(request:Request,env:Env):Promise<Response> {
    const u=new URL(request.url),headers={"Cache-Control":"no-store","Referrer-Policy":"no-referrer","Content-Security-Policy":"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"};
    if(u.pathname==="/operator" && request.method==="GET" && !u.search){
      return new Response(`<!doctype html><meta charset="utf-8"><title>Verifier control</title><h1>Run a check</h1><p>Enter your seller control secret. Scheduled checks are a best-effort backstop.</p><input id="secret" type="password" autocomplete="off"><button id="run">Run now</button><p id="result"></p><script>document.getElementById('run').onclick=async()=>{const input=document.getElementById('secret');const secret=input.value;input.value='';const r=await fetch('/operator/run-now',{method:'POST',headers:{Authorization:'Bearer '+secret,'Content-Type':'application/json'},body:'{}'});document.getElementById('result').textContent=r.status===202?'Check scheduled':'Check refused';};</script>`,{headers:{...headers,"Content-Type":"text/html; charset=utf-8"}});
    }
    if(u.pathname!=="/operator/run-now" || request.method!=="POST" || u.search)return new Response("Not found",{status:404,headers});
    if(!env.RUN_NOW_SECRET || !/^[A-Za-z0-9_-]{43}$/.test(env.RUN_NOW_SECRET) || !(await equalSecret(request.headers.get("Authorization")??"","Bearer "+env.RUN_NOW_SECRET)))return new Response("Unauthorized",{status:401,headers});
    try {
      if(await bounded(new Response(request.body),3)!=="{}")refuse();
      const c=config(env);await env.VERIFIER.getByName(c.connection_id).enqueue();
      return new Response(null,{status:202,headers});
    }catch{return new Response("verification_refused",{status:400,headers});}
  },
  async scheduled(_controller:ScheduledController,env:Env):Promise<void> {
    const c=config(env);await env.VERIFIER.getByName(c.connection_id).enqueue();
  },
} satisfies ExportedHandler<Env>;
