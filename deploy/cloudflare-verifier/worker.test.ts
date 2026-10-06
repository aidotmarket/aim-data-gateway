import { env, runInDurableObject } from "cloudflare:test";
import { beforeAll, afterAll, describe, it, expect, vi } from "vitest";
import worker, { CloudflareVerifier } from "./worker.ts";
import { Ledger, type Job } from "./state";
import { encrypt, decrypt, random, sha, now, canonical } from "./crypto";

beforeAll(()=>{vi.stubGlobal("fetch",()=>{throw new Error("network disabled in tests");});});
afterAll(()=>{vi.unstubAllGlobals();});
const at=1791290000;
const config={connection_id:"11111111-1111-1111-1111-111111111111",bucket:"synthetic",prefix:"p/",jurisdiction:"default",keys:["p/data.csv"],release_id:"cloudflare-verifier-v0.1.0",scanner_version:"0.1.0",binary_sha256:"b".repeat(64),worker_identity:{mode:"bundle",sha256:"c".repeat(64)}};
function job(n:number):Job {return {Token:"authentic-signed-test-"+n,Envelope:{iid:"iid-"+n,spec_hash:"a".repeat(64),variant:"scan"},Payload:{spec_id:"spec-"+n,nonce:"nonce-"+n,owner_authorization_id:"authorization-"+n,listing_id:"listing",expires_at_utc:new Date((at+86400)*1000).toISOString(),accepted_at_utc:new Date(at*1000).toISOString()}};}
function storage(name:string,fn:(ledger:Ledger,state:DurableObjectState)=>unknown){
  return runInDurableObject(env.STORAGE.getByName(name),async(_instance,state)=>fn(new Ledger(state.storage),state));
}
describe("SQLite consent and custody",()=>{
  it("serializes duplicate admissions and increments only once",async()=>{
    const accepted=await Promise.all(Array.from({length:20},()=>storage("race",l=>!!l.admit(job(1),"signed",[],at,at,at))));
    expect(accepted.filter(Boolean)).toHaveLength(1);
    await storage("race",l=>{
      expect(l.storage.sql.exec("SELECT n FROM daily").one().n).toBe(1);
      expect(()=>l.admit({...job(1),Token:"changed"},"signed",[],at,at,at)).toThrow();
      expect(()=>l.admit({...job(2),Payload:{...job(2).Payload,nonce:"nonce-1"}},"signed",[],at,at,at)).toThrow();
      expect(l.storage.sql.exec("SELECT COUNT(*) n FROM admissions").one().n).toBe(1);
    });
  });
  it("accepts the tenth and refuses the eleventh across versions",async()=>storage("daily",l=>{
    for(let n=1;n<=10;n++){const r=l.admit(job(n),"signed",[],at,at,at)!;l.settle(r,"reported",at);}
    expect(()=>l.admit(job(11),"signed",[],at,at,at)).toThrow();
    expect(l.storage.sql.exec("SELECT n FROM daily").one().n).toBe(10);
    expect(l.admit(job(11),"signed",[],at+86400,at+86400,at+86400)).toBeDefined();
  }));
  it("does not reset clock, quota or consent on reconstructed storage",async()=>storage("clock",(l,s)=>{
    l.observe(at);new Ledger(s.storage).observe(at-300);
    expect(()=>new Ledger(s.storage).observe(at-301)).toThrow();
    const r=l.admit(job(1),"signed",[],at,at,at)!;
    expect(new Ledger(s.storage).admit(job(1),"signed",[],at,at,at)).toBeUndefined();
    expect(new Ledger(s.storage).active()?.token).toBe(r.token);
  }));
  it("persists exact outbox chunks atomically; incomplete descriptor refuses",async()=>storage("outbox",async(l,s)=>{
    const r=l.admit(job(1),"signed",[],at,at,at)!;
    const body="x".repeat(300000);l.commit(r,body,await sha(body),at);
    expect(new Ledger(s.storage).body(r).body).toBe(body);
    expect(l.storage.sql.exec("SELECT COUNT(*) n FROM chunks").one().n).toBe(3);
    l.storage.sql.exec("DELETE FROM chunks WHERE n=1");expect(()=>l.body(r)).toThrow();
    l.prune(at+31*86400);expect(l.active()?.id).toBe(r.id);
  }));
  it("wrap is created once; lost state cannot regenerate custody",async()=>storage("wrap",async l=>{
    const wrap=random();expect(l.firstStart(wrap,at)).toBe(true);
    expect(()=>l.firstStart(random(),at)).toThrow();
    l.put("secret",await encrypt(wrap,"connection",{key:"synthetic"}));
    expect(l.firstStart(random(),at)).toBe(false);expect(l.get("wrap")).toBe(wrap);
    l.storage.sql.exec("DELETE FROM meta WHERE k='wrap'");expect(()=>l.firstStart(random(),at)).toThrow();
  }));
  it("AES-GCM binds connection and detects tamper with fresh IV",async()=>{
    const k=random(),a=await encrypt(k,"connection",{key:"synthetic"}),b=await encrypt(k,"connection",{key:"synthetic"});
    expect(a).not.toBe(b);expect(await decrypt(k,"connection",a)).toEqual({key:"synthetic"});
    await expect(decrypt(k,"other",a)).rejects.toThrow();
    const tampered=JSON.parse(a);tampered.cipher="00"+tampered.cipher.slice(2);
    await expect(decrypt(k,"connection",JSON.stringify(tampered))).rejects.toThrow();
  });
  it("coalesces cron/operator/task retries and observes the recovery lease",async()=>storage("wake",l=>{
    expect(l.wake(at)).toBe(true);expect(l.wake(at+1)).toBe(false);
    expect(l.claim(at)).toBe(true);expect(l.claim(at+900)).toBe(false);
    expect(l.claim(at+1020)).toBe(false);expect(l.claim(at+1021)).toBe(true);
    l.release();expect(l.wake(at+1081)).toBe(true);
  }));
});
describe("seller control and private bridge",()=>{
  it("authenticates seller only, accepts exactly {}, never forwards operator payload",async()=>{
    const enqueue=vi.fn().mockResolvedValue(undefined);
    const e={DEPLOYMENT_CONFIG:JSON.stringify(config),RUN_NOW_SECRET:"s".repeat(43),VERIFIER:{getByName:()=>({enqueue})}};
    const req=(body:string,auth="Bearer "+e.RUN_NOW_SECRET)=>new Request("https://seller.invalid/operator/run-now",{method:"POST",headers:{Authorization:auth},body});
    expect((await worker.fetch(req("{}","wrong"),e)).status).toBe(401);
    expect((await worker.fetch(req('{"spec":"evil"}'),e)).status).toBe(400);
    expect((await worker.fetch(req("{} "),e)).status).toBe(400);
    expect((await worker.fetch(req("{}"),e)).status).toBe(202);expect(enqueue).toHaveBeenCalledTimes(1);
    expect((await worker.fetch(new Request("https://seller.invalid/member/0"),e)).status).toBe(404);
    const html=await (await worker.fetch(new Request("https://seller.invalid/operator"),e)).text();
    expect(html).not.toContain(e.RUN_NOW_SECRET);expect(html).not.toMatch(/localStorage|sessionStorage/);
  });
  it("never overrides alarm and keeps internet enabled with private host interception",()=>{
    expect(CloudflareVerifier.prototype.hasOwnProperty("alarm")).toBe(false);
    expect(Object.keys(CloudflareVerifier.outboundByHost)).toEqual(["r2-bridge.internal"]);
  });
  it("pins all HEAD/full/range reads and refuses list/write/nonmembers/expired capabilities",async()=>{
    const object=await env.SOURCE.put("p/data.csv","x\n1\n");
    await storage("bridge",async(l,s)=>{
      const t=now(),j=job(1);j.Payload.accepted_at_utc=new Date(t*1000).toISOString();j.Payload.expires_at_utc=new Date((t+86400)*1000).toISOString();
      const r=l.admit(j,"signed",[{Key:"p/data.csv",ETag:object.etag,Size:4,Format:"csv"}],t,t,t)!;
      const wrap=random();l.put("wrap",wrap);
      const payload={connection:config.connection_id,spec:r.hash,start:t,exp:t+780,id:s.id.toString(),nonce:random()};
      const text=btoa(canonical(payload)).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
      const key=await crypto.subtle.importKey("raw",Uint8Array.from(atob(wrap.replaceAll("-","+").replaceAll("_","/")),c=>c.charCodeAt(0)),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
      const sig=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode("bridge-v1."+text)));
      const token=text+"."+btoa(String.fromCharCode(...sig)).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");l.put("capability",token);
      const fake={ledger:l,ctx:s,env:{SOURCE:env.SOURCE,DEPLOYMENT_CONFIG:JSON.stringify(config)}};
      const bridge=(path="/member/0",method="GET",extra={})=>CloudflareVerifier.prototype.bridge.call(fake,new Request("http://r2-bridge.internal"+path,{method,headers:{Authorization:"Bearer "+token,...extra}}));
      expect((await bridge("/member/0","HEAD")).headers.get("X-Object-Etag")).toBe(object.etag);
      expect(await (await bridge()).text()).toBe("x\n1\n");
      expect(await (await bridge("/member/0","GET",{Range:"bytes=1-2"})).text()).toBe("\n1");
      for(const method of ["POST","PUT","DELETE","OPTIONS"])await expect(bridge("/member/0",method)).rejects.toThrow();
      for(const path of ["/list","/member/1","/member/00","/member/0?key=other","/member/p%2Fdata.csv"])await expect(bridge(path)).rejects.toThrow();
      await expect(bridge("/member/0","GET",{Range:"bytes=0-4"})).rejects.toThrow();
      await env.SOURCE.put("p/data.csv","changed");await expect(bridge()).rejects.toThrow();
      l.update({...r,start:t-781},t);await expect(bridge()).rejects.toThrow();
    });
  });
});

async function testSecret(){
  const pair=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
  const pkcs8=new Uint8Array(await crypto.subtle.exportKey("pkcs8",pair.privateKey));
  const pub=new Uint8Array(await crypto.subtle.exportKey("raw",pair.publicKey));
  const raw=new Uint8Array(64);raw.set(pkcs8.slice(-32));raw.set(pub,32);
  return {Private:btoa(String.fromCharCode(...raw)),Connection:config.connection_id,Version:config.scanner_version,Release:config.release_id,Digest:config.binary_sha256,Worker:config.worker_identity,Runner:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",Receipt:"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",Commitment:[],Registration:"",Nonce:"",Ack:"saved",Pins:[],pub};
}
async function authClaims(request:Request,publicKey:Uint8Array){
  const token=request.headers.get("Authorization")!.slice(7),parts=token.split(".");
  const decode=(s:string)=>Uint8Array.from(atob(s.replaceAll("-","+").replaceAll("_","/")),c=>c.charCodeAt(0));
  const key=await crypto.subtle.importKey("raw",publicKey,"Ed25519",false,["verify"]);
  expect(await crypto.subtle.verify("Ed25519",key,decode(parts[2]),new TextEncoder().encode(parts[0]+"."+parts[1]))).toBe(true);
  return JSON.parse(new TextDecoder().decode(decode(parts[1])));
}
describe("scheduled recovery without external network",()=>{
  it("resends lost-ack committed outbox before poll, identical bytes with new HTTP nonce",async()=>storage("recover",async(l,state)=>{
    const t=now(),j=job(1);j.Payload.accepted_at_utc=new Date((t-900)*1000).toISOString();j.Payload.expires_at_utc=new Date((t+3600)*1000).toISOString();
    const r=l.admit(j,"saved snapshot",[],t-900,t-900,t-900)!;
    const body=canonical({approved_control_only:true});l.commit(r,body,await sha(body),t-900);
    l.put("bootstrap","saved");const sec=await testSecret();
    const requests:{path:string;body:string;nonce:string}[]=[];
    let lost=true;
    vi.stubGlobal("fetch",async(url:string,init:RequestInit)=>{
      const request=new Request(url,init),claims=await authClaims(request,sec.pub),raw=await request.text();
      expect(claims.body_sha256).toBe(await sha(raw));expect(claims.worker_identity).toEqual(config.worker_identity);expect(claims.kind).toBe("cloudflare");
      requests.push({path:new URL(url).pathname,body:raw,nonce:claims.nonce});
      if(url.endsWith("/report")){if(lost){lost=false;throw new Error("lost ack");}return new Response(canonical({iid:r.iid,status:"stored"}));}
      return new Response('{"work_jws":null}');
    });
    const compute=vi.fn().mockRejectedValue(new Error("must not restart compute"));
    const fake={ledger:l,ctx:state,env:{DEPLOYMENT_CONFIG:JSON.stringify(config)},load:async()=>sec,compute,recover:CloudflareVerifier.prototype.recover,stop:vi.fn().mockResolvedValue(undefined),schedule:vi.fn().mockResolvedValue(undefined)};
    try {
      await CloudflareVerifier.prototype.pollTask.call(fake);
      expect(l.active()?.state).toBe("committed");expect(requests).toHaveLength(1);
      fake.ledger=new Ledger(state.storage);
      await CloudflareVerifier.prototype.pollTask.call(fake);
      expect(requests.map(r=>r.path.split("/").at(-1))).toEqual(["report","report","work"]);
      expect(requests[0].body).toBe(requests[1].body);expect(requests[0].nonce).not.toBe(requests[1].nonce);
      expect(compute).not.toHaveBeenCalled();expect(l.active()).toBeUndefined();expect(l.record(r.id)?.state).toBe("reported");
    }finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled in tests");});}
  }));
  it("interrupted work at 15 minutes waits, then produces terminal recovery once; never re-executes",async()=>storage("interruption",async(l,state)=>{
    const t=now(),j=job(1);j.Payload.accepted_at_utc=new Date((t-900)*1000).toISOString();j.Payload.expires_at_utc=new Date((t+3600)*1000).toISOString();
    let r=l.admit(j,"saved",[],t-900,t-900,t-900)!;
    const sec=await testSecret();
    const compute=vi.fn().mockResolvedValue({body:canonical({terminal_error_code:"scanner_failure"})});
    const fake={ledger:l,ctx:state,env:{DEPLOYMENT_CONFIG:JSON.stringify(config)},compute};
    await expect(CloudflareVerifier.prototype.recover.call(fake,config,sec)).rejects.toThrow();expect(compute).not.toHaveBeenCalled();
    r={...r,start:t-1021};l.update(r,t);
    let sent=0;vi.stubGlobal("fetch",async()=>{sent++;return new Response(canonical({iid:r.iid,status:"stored"}));});
    try {
      await CloudflareVerifier.prototype.recover.call(fake,config,sec);
      expect(compute.mock.calls[0][0]).toBe("/terminal");expect(compute).toHaveBeenCalledTimes(1);expect(sent).toBe(1);
      await CloudflareVerifier.prototype.recover.call(fake,config,sec);expect(sent).toBe(1);
    }finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled in tests");});}
  }));
  it("late outbox settles expired without HTTP and missing audit table refuses before admission",async()=>storage("late",async(l,state)=>{
    const t=now(),j=job(1);j.Payload.accepted_at_utc=new Date((t-1921)*1000).toISOString();j.Payload.expires_at_utc=new Date((t+1)*1000).toISOString();
    const r=l.admit(j,"saved",[],t-1921,t-1921,t-1921)!;
    l.commit(r,"{}",await sha("{}"),t-1921);
    await CloudflareVerifier.prototype.recover.call({ledger:l},config,await testSecret());expect(l.record(r.id)?.state).toBe("expired");
    state.storage.sql.exec("DROP TABLE events");expect(()=>new Ledger(state.storage)).toThrow();
  }));
  it("cron and operator enqueue share durable coalescing through schedule",async()=>storage("coalesced",async(l,state)=>{
    const schedule=vi.fn().mockResolvedValue(undefined),fake={ledger:l,ctx:state,env:{DEPLOYMENT_CONFIG:JSON.stringify(config)},schedule};
    await Promise.all([CloudflareVerifier.prototype.enqueue.call(fake),CloudflareVerifier.prototype.enqueue.call(fake)]);
    expect(schedule).toHaveBeenCalledTimes(1);expect(schedule).toHaveBeenCalledWith(1,"pollTask");
  }));
});
