import deploymentVector from "../../contract/vectors/verification/deployment_config/unicode.json";
import { env, runInDurableObject } from "cloudflare:test";
import { beforeAll, afterAll, describe, it, expect, vi } from "vitest";
import worker, { CloudflareVerifier, identity } from "./worker.ts";
import { Container } from "@cloudflare/containers";
import { Ledger, RETENTION, type Job } from "./state";
import { encrypt, decrypt, random, sha, now, canonical, deploymentConfigCanonical, b64, utf8 } from "./crypto";

beforeAll(()=>{vi.stubGlobal("fetch",()=>{throw new Error("network disabled in tests");});});
afterAll(()=>{vi.unstubAllGlobals();});
const at=1791290000;
const config={connection_id:"11111111-1111-1111-1111-111111111111",bucket:"synthetic",prefix:"p/",jurisdiction:"default",keys:["p/data.csv"],release_id:"cloudflare-verifier-v0.1.0",scanner_version:"0.1.0",binary_sha256:"b".repeat(64),worker_identity:{mode:"bundle",sha256:"c".repeat(64)}};
const shipped={release_id:config.release_id,scanner_version:config.scanner_version,binary_sha256:config.binary_sha256,worker_identity:config.worker_identity,jurisdiction:"default"};
const routing=(stub:unknown)=>({idFromName:vi.fn((name:string)=>{expect(name).toBe("aim-verifier");return "fixed";}),get:vi.fn((id:string)=>{expect(id).toBe("fixed");return stub;})});
function job(n:number):Job {return {Token:"authentic-signed-test-"+n,Envelope:{iid:"iid-"+n,spec_hash:"a".repeat(64),variant:"scan"},Payload:{spec_id:"spec-"+n,nonce:"nonce-"+n,owner_authorization_id:"authorization-"+n,listing_id:"listing",expires_at_utc:new Date((at+86400)*1000).toISOString(),accepted_at_utc:new Date(at*1000).toISOString()}};}
function storage(name:string,fn:(ledger:Ledger,state:DurableObjectState)=>unknown){
  return runInDurableObject(env.STORAGE.getByName(name),async(_instance,state)=>{
    const l=new Ledger(state.storage);
    if(!l.get("config_hash"))CloudflareVerifier.prototype.persistConfig.call({ledger:l},config,await sha(canonical(config)),await sha("old"));
    return fn(l,state);
  });
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
  it("coalesces a fresh queued wake even while the old running lease is stale",async()=>storage("requeued",l=>{
    expect(l.wake(at)).toBe(true);expect(l.claim(at)).toBe(true);
    expect(l.wake(at+1021)).toBe(true);expect(l.wake(at+1081)).toBe(false);
    expect(l.wake(at+2041)).toBe(false);expect(l.wake(at+2042)).toBe(true);
  }));
  it("reclaims an abandoned queued task after the grace",async()=>storage("queued",l=>{
    expect(l.wake(at)).toBe(true);expect(l.wake(at+1020)).toBe(false);
    expect(l.wake(at+1021)).toBe(true);expect(l.claim(at+1021)).toBe(true);
  }));
  it("chunks and reconstructs a signed 17,033-member snapshot within SQL row limits",async()=>storage("snapshot-boundary",async(l,state)=>{
    const objects=Array.from({length:17033},(_,n)=>({Key:"p/"+String(n).padStart(8,"0")+"é.csv",ETag:"e".repeat(32),Size:12345,Format:"csv"}));
    const encode=(s:string)=>{const bytes=utf8.encode(s);let raw="";for(let n=0;n<bytes.length;n+=32768)raw+=String.fromCharCode(...bytes.subarray(n,n+32768));return btoa(raw).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");};
    const payload=canonical({members:objects.map(m=>({key:m.Key,etag:m.ETag,size:m.Size,format:m.Format})),provider:"r2",bucket:config.bucket});
    const pair=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
    const input=encode(canonical({alg:"EdDSA",typ:"aim-scan-snapshot+jwt"}))+"."+encode(canonical({payload_b64:encode(payload),manifest_hash:await sha(payload)}));
    const snapshot=input+"."+b64(new Uint8Array(await crypto.subtle.sign("Ed25519",pair.privateKey,utf8.encode(input))));
    expect(utf8.encode(JSON.stringify({snapshot,objects})).length).toBeGreaterThan(4_000_000);
    const r=l.admit(job(1),snapshot,objects,at,at,at)!;
    const rebuilt=new Ledger(state.storage).active()!;
    expect(rebuilt.snapshot).toBe(snapshot);expect(rebuilt.objects).toEqual(objects);
    const rows=l.storage.sql.exec<{id:string;n:number;data:string}>("SELECT * FROM admission_chunks").toArray();
    expect(rows.length).toBeGreaterThan(4);
    for(const row of rows)expect(utf8.encode(row.data).length+utf8.encode(row.id).length+8).toBeLessThanOrEqual(1048576);
    expect(l.storage.sql.exec<{n:number}>("SELECT length(CAST(record AS BLOB)) n FROM admissions").one().n).toBeLessThan(1048576);
    l.commit(r,"{}",await sha("{}"),at);expect(new Ledger(state.storage).active()?.objects).toEqual(objects);
    l.settle(r,"reported",at);expect(l.storage.sql.exec("SELECT COUNT(*) n FROM admission_chunks").one().n).toBe(0);
    expect(l.record(r.id)?.token).toBe(r.token);l.prune(at+RETENTION+1);expect(l.record(r.id)).toBeUndefined();
  }));
  it.each(["missing","corrupt","index","extra","descriptor"])("refuses %s admission chunks before commit or reads",async fault=>storage("snapshot-"+fault,async(l,state)=>{
    const r=l.admit(job(1),"x".repeat(1100000),[],at,at,at)!;
    if(fault==="missing")l.storage.sql.exec("DELETE FROM admission_chunks WHERE n=1");
    if(fault==="corrupt")l.storage.sql.exec("UPDATE admission_chunks SET data='y'||substr(data,2) WHERE n=1");
    if(fault==="index")l.storage.sql.exec("UPDATE admission_chunks SET n=9 WHERE n=1");
    if(fault==="extra")l.storage.sql.exec("INSERT INTO admission_chunks VALUES (?,9,'extra')",r.id);
    if(fault==="descriptor")l.storage.sql.exec("UPDATE admissions SET record=json_remove(record,'$.data')");
    const restored=new Ledger(state.storage);expect(()=>restored.active()).toThrow();
    const hash=await sha("{}");expect(()=>restored.commit(r,"{}",hash,at)).toThrow();
    expect(l.storage.sql.exec("SELECT COUNT(*) n FROM outbox").one().n).toBe(0);
  }));
  it("rolls back chunks and quota with a failed admission insert",async()=>storage("chunk-rollback",l=>{
    const r=l.admit(job(1),"first",[],at,at,at)!;l.settle(r,"reported",at);
    const duplicate={...job(2),Envelope:{...job(2).Envelope,iid:r.iid}};
    expect(()=>l.admit(duplicate,"x".repeat(1100000),[],at,at,at)).toThrow();
    expect(l.storage.sql.exec("SELECT COUNT(*) n FROM admission_chunks").one().n).toBe(0);
    expect(l.storage.sql.exec("SELECT n FROM daily").one().n).toBe(1);
  }));
  it("migrates v1 custody atomically and refuses a lost v2 chunk table",async()=>storage("chunk-migration",(l,state)=>{
    const r=l.admit(job(1),"legacy snapshot",[{Key:"p/é.csv",ETag:"etag",Size:2,Format:"csv"}],at,at,at)!;
    l.storage.sql.exec("UPDATE admissions SET record=? WHERE id=?",JSON.stringify(r),r.id);
    l.storage.sql.exec("DROP TABLE admission_chunks");l.put("schema","verifier-state-v1");
    const upgraded=new Ledger(state.storage);expect(upgraded.active()).toEqual(r);expect(upgraded.get("schema")).toBe("verifier-state-v2");
    l.storage.sql.exec("DROP TABLE admission_chunks");expect(()=>new Ledger(state.storage)).toThrow();
  }));
});
describe("seller control and private bridge",()=>{
  it("authenticates seller only, accepts exactly {}, never forwards operator payload",async()=>{
    const enqueue=vi.fn().mockResolvedValue(undefined);
    const e={DEPLOYMENT_CONFIG:JSON.stringify(shipped),RUN_NOW_SECRET:"s".repeat(43),VERIFIER:routing({enqueue,operatorPage:CloudflareVerifier.prototype.operatorPage})};
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
      const fake={runtimeConfig:CloudflareVerifier.prototype.runtimeConfig,ledger:l,ctx:s,env:{SOURCE:env.SOURCE,DEPLOYMENT_CONFIG:JSON.stringify(shipped)}};
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
  it.each([
    {committed:false,trigger:"cron"},{committed:false,trigger:"operator"},
    {committed:true,trigger:"cron"},{committed:true,trigger:"operator"},
  ])("$trigger recovers a hard interruption (committed=$committed) through SDK one-shot retries",async({committed,trigger})=>storage("hard-"+trigger+committed,async(l,state)=>{
    const t=now(),clock=vi.spyOn(Date,"now").mockReturnValue(t*1000),sec=await testSecret();l.put("bootstrap","saved");
    const source={head:vi.fn(),get:vi.fn()},paths:string[]=[],bodies:string[]=[];
    const body=canonical({terminal_error_code:committed?null:"scanner_failure",evidence:"exact committed bytes"});
    const compute=vi.fn(async(path:string)=>{paths.push(path);if(path!=="/terminal")throw new Error("consumed traversal must not restart");return {body};});
    // Use SDK 0.3.7's actual SQL scheduler/alarm, with only Container lifecycle
    // and network stubbed. Its normal-return deletion is part of this test.
    state.storage.sql.exec(`CREATE TABLE container_schedules(id TEXT PRIMARY KEY,callback TEXT NOT NULL,payload TEXT,type TEXT NOT NULL,time INTEGER,delayInSeconds INTEGER)`);
    const fake={runtimeConfig:CloudflareVerifier.prototype.runtimeConfig,ledger:l,ctx:state,env:{DEPLOYMENT_CONFIG:JSON.stringify(shipped),SOURCE:source},load:async()=>sec,compute,
      enqueue:CloudflareVerifier.prototype.enqueue,pollTask:CloudflareVerifier.prototype.pollTask,recover:CloudflareVerifier.prototype.recover,
      schedule:Container.prototype.schedule,scheduleNextAlarm:Container.prototype.scheduleNextAlarm,
      getSchedule:Container.prototype.getSchedule,toSchedule:Container.prototype.toSchedule,
      sql:(strings:TemplateStringsArray,...values:unknown[])=>state.storage.sql.exec(strings.join("?"),...values.map(v=>v===undefined?null:v)).toArray(),
      container:{running:false},syncPendingStoppedEvents:vi.fn().mockResolvedValue(undefined),stop:vi.fn().mockResolvedValue(undefined)};
    const e={DEPLOYMENT_CONFIG:JSON.stringify(shipped),RUN_NOW_SECRET:"s".repeat(43),VERIFIER:routing(fake)};
    const triggerWake=async()=>{
      if(trigger==="cron")await worker.scheduled({},e);
      else expect((await worker.fetch(new Request("https://seller.invalid/operator/run-now",{method:"POST",headers:{Authorization:"Bearer "+e.RUN_NOW_SECRET},body:"{}"}),e)).status).toBe(202);
    };
    try {
      await triggerWake();expect(l.get("task")).toBe("queued");
      clock.mockReturnValue((t+1)*1000);expect(l.claim(now())).toBe(true);
      const j=job(1);j.Payload.accepted_at_utc=new Date(t*1000).toISOString();j.Payload.expires_at_utc=new Date((t+3600)*1000).toISOString();
      const r=l.admit(j,"saved snapshot",[{Key:"p/data.csv",ETag:"old",Size:4,Format:"csv"}],now(),t,t+1)!;
      if(committed)l.commit(r,body,await sha(body),now());
      // Hard interruption: no finally/release; reconstruct durable custody.
      fake.ledger=new Ledger(state.storage);expect(fake.ledger.get("task")).toBe("running");
      vi.stubGlobal("fetch",async(url:string,init:RequestInit)=>{
        const request=new Request(url,init);await authClaims(request,sec.pub);
        const path=new URL(url).pathname.split("/").at(-1)!;paths.push(path);
        if(path==="report"){bodies.push(await request.text());return new Response(canonical({iid:r.iid,status:"stored"}));}
        return new Response(canonical({work_jws:j.Token})); // replay must not prepare/execute
      });
      clock.mockReturnValue((t+901)*1000);await triggerWake();
      await Container.prototype.alarm.call(fake,{isRetry:true,retryCount:1});
      expect(paths).toEqual([]);expect(fake.ledger.get("task")).toBe("running");
      const pending=state.storage.sql.exec<{time:number}>("SELECT time FROM container_schedules").toArray();
      expect(pending).toEqual([{time:t+1022}]);expect(await state.storage.getAlarm()).toBe((t+1022)*1000);
      clock.mockReturnValue((t+1021)*1000);await triggerWake();
      expect(fake.ledger.get("task")).toBe("running");expect(state.storage.sql.exec("SELECT COUNT(*) n FROM container_schedules").one().n).toBe(1);
      clock.mockReturnValue((t+1022)*1000);await triggerWake();expect(fake.ledger.get("task")).toBe("queued");
      clock.mockReturnValue((t+1023)*1000);await Container.prototype.alarm.call(fake);
      expect(paths.slice(0,committed?2:3)).toEqual(committed?["report","work"]:["/terminal","report","work"]);
      expect(bodies).toEqual([body]);expect(compute).toHaveBeenCalledTimes(committed?0:1);
      expect(source.head).not.toHaveBeenCalled();expect(source.get).not.toHaveBeenCalled();
      expect(fake.ledger.active()).toBeUndefined();expect(fake.ledger.record(r.id)?.state).toBe("reported");
      expect(fake.ledger.get("task")).toBe("");expect(state.storage.sql.exec("SELECT COUNT(*) n FROM container_schedules").one().n).toBe(0);
      clock.mockReturnValue((t+1083)*1000);await triggerWake();expect(fake.ledger.get("task")).toBe("queued");
      clock.mockReturnValue((t+1084)*1000);await Container.prototype.alarm.call(fake);
      expect(paths.filter(p=>p==="report")).toHaveLength(1);expect(paths.at(-1)).toBe("work");
    }finally{clock.mockRestore();await state.storage.deleteAlarm();vi.stubGlobal("fetch",()=>{throw new Error("network disabled in tests");});}
  }));
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
    const fake={runtimeConfig:CloudflareVerifier.prototype.runtimeConfig,ledger:l,ctx:state,env:{DEPLOYMENT_CONFIG:JSON.stringify(shipped)},load:async()=>sec,compute,recover:CloudflareVerifier.prototype.recover,stop:vi.fn().mockResolvedValue(undefined),schedule:vi.fn().mockResolvedValue(undefined)};
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
    const fake={runtimeConfig:CloudflareVerifier.prototype.runtimeConfig,ledger:l,ctx:state,env:{DEPLOYMENT_CONFIG:JSON.stringify(shipped)},compute};
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
    const schedule=vi.fn().mockResolvedValue(undefined),fake={ledger:l,ctx:state,env:{DEPLOYMENT_CONFIG:JSON.stringify(shipped)},schedule};
    await Promise.all([CloudflareVerifier.prototype.enqueue.call(fake),CloudflareVerifier.prototype.enqueue.call(fake)]);
    expect(schedule).toHaveBeenCalledTimes(1);expect(schedule).toHaveBeenCalledWith(1,"pollTask");
  }));
});

function fresh(name:string,fn:(l:Ledger,state:DurableObjectState)=>unknown){
  return runInDurableObject(env.STORAGE.getByName("bootstrap-"+name),async(_instance,state)=>fn(new Ledger(state.storage),state));
}
async function bootstrapFake(l:Ledger,state:DurableObjectState){
  const sec=await testSecret();sec.Runner="";sec.Receipt="";sec.Ack="";
  const original=canonical({registration_token:random(),deployment_config_sha256:await sha(canonical(config)),connection_id:config.connection_id,key_proof:"old",registered_at_utc:new Date().toISOString()});
  sec.Registration=b64(utf8.encode(original));
  const fake={ledger:l,ctx:state,env:{DEPLOYMENT_CONFIG:canonical(shipped),REGISTRATION_TOKEN:random(),SOURCE:{head:vi.fn(),get:vi.fn()}},
    runtimeConfig:CloudflareVerifier.prototype.runtimeConfig,persistConfig:CloudflareVerifier.prototype.persistConfig,pullConfig:CloudflareVerifier.prototype.pullConfig,
    load:CloudflareVerifier.prototype.load,save:CloudflareVerifier.prototype.save,recover:CloudflareVerifier.prototype.recover,
    compute:vi.fn(async(path:string)=>{if(path==="/create")return sec;if(path==="/register")return {...sec,Runner:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",Receipt:"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",Ack:"ack"};throw new Error("unexpected compute");}),
    schedule:vi.fn().mockResolvedValue(undefined),stop:vi.fn().mockResolvedValue(undefined)};
  return {fake,sec,original};
}
function configResponse(c=config,hash?:string){return new Response(canonical({deployment_config:c,deployment_config_sha256:hash}));}
describe("Amendment A bootstrap and recovery",()=>{
  it("matches Python deployment config bytes, code-point order and string escaping",async()=>{
    expect(await sha(deploymentConfigCanonical(deploymentVector.deployment_config))).toBe(deploymentVector.deployment_config_sha256);
    expect(await sha(canonical(deploymentVector.deployment_config))).toBe(deploymentVector.escaped_sha256);
    expect(deploymentConfigCanonical({"😀":"astral","\ue000":"BMP","é":"\x00\b\f\n\r\t\x1f\"\\\x7fé日本"})).toBe('{"é":"\\u0000\\b\\f\\n\\r\\t\\u001f\\\"\\\\\x7fé日本","\ue000":"BMP","😀":"astral"}');
    for(const v of ["\ud800","\udfff",{"\ud800":"key"},{key:"\udfff"}])expect(()=>deploymentConfigCanonical(v)).toThrow();
    expect(()=>deploymentConfigCanonical({key:undefined})).toThrow();
  });
  it.each([false,true])("bootstraps Unicode config with backend hash; escaped hash refused=%s",async(escaped)=>fresh("unicode-"+escaped,async(l,state)=>{
    const {fake,sec}=await bootstrapFake(l,state),c=deploymentVector.bootstrap_config,hash=deploymentVector.bootstrap_sha256;
    Object.assign(sec,{Connection:c.connection_id,Version:c.scanner_version,Release:c.release_id,Digest:c.binary_sha256,Worker:c.worker_identity});
    fake.env.DEPLOYMENT_CONFIG=canonical({release_id:c.release_id,scanner_version:c.scanner_version,binary_sha256:c.binary_sha256,worker_identity:c.worker_identity,jurisdiction:c.jurisdiction});
    const calls:string[]=[];
    fake.compute.mockImplementation(async(path:string)=>{
      calls.push(path);expect(await fake.runtimeConfig()).toEqual(c);expect(l.get("config_hash")).toBe(hash);
      if(path==="/create")return sec;
      return {...sec,Runner:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",Receipt:"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",Ack:"ack"};
    });
    const network=vi.fn(async(url:string)=>url.endsWith("/deployment-config")?configResponse(c,escaped?await sha(canonical(c)):hash):new Response(canonical({work_jws:null})));
    vi.stubGlobal("fetch",network);
    try{
      await CloudflareVerifier.prototype.pollTask.call(fake);
      if(escaped){expect(fake.compute).not.toHaveBeenCalled();expect(l.get("config_hash")).toBeUndefined();expect(l.get("wrap")).toBeUndefined();expect(network).toHaveBeenCalledTimes(1);}
      else{
        expect(calls).toEqual(["/create","/register"]);expect(await fake.runtimeConfig()).toEqual(c);expect(l.get("last_poll")).toBeDefined();
        fake.ledger=new Ledger(state.storage);await CloudflareVerifier.prototype.pollTask.call(fake);expect(calls).toHaveLength(2);expect(network).toHaveBeenCalledTimes(3);
      }
    }finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled");});}
  }));

  it("parses only the shipped identity and refuses scope or invalid identity vars",()=>{
    expect(identity(canonical(shipped))).toEqual(shipped);
    for(const value of [config,{...shipped,binary_sha256:"bad"},{...shipped,jurisdiction:"eu"},{...shipped,worker_identity:{mode:"other",sha256:"c".repeat(64)}},{...shipped,release_id:""},{...shipped,scanner_version:1}])expect(()=>identity(canonical(value))).toThrow();
  });
  it("refuses malformed deployment identity JSON uniformly",()=>{
    for(const raw of ["{", "", "undefined", '{"release_id":}'])expect(()=>identity(raw)).toThrowError(new Error("verification_refused"));
  });
  it("routes cron, run-now and the private bridge to the fixed DO before config exists",async()=>{
    const enqueue=vi.fn().mockResolvedValue(undefined),fetch=vi.fn().mockResolvedValue(new Response("refused",{status:403})),namespace=routing({enqueue,fetch,operatorPage:CloudflareVerifier.prototype.operatorPage});
    const e={DEPLOYMENT_CONFIG:"{}",RUN_NOW_SECRET:"s".repeat(43),VERIFIER:namespace};
    await worker.scheduled({},e);
    expect((await worker.fetch(new Request("https://seller.invalid/operator"),e)).status).toBe(200);
    expect((await worker.fetch(new Request("https://seller.invalid/operator/run-now",{method:"POST",headers:{Authorization:"Bearer "+e.RUN_NOW_SECRET},body:"{}"}),e)).status).toBe(202);
    await CloudflareVerifier.outboundByHost["r2-bridge.internal"](new Request("http://r2-bridge.internal/member/0",{method:"HEAD"}),e,{containerId:"not-a-routing-input"});
    expect(namespace.idFromName).toHaveBeenCalledTimes(4);expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("bootstraps with canonical token-only request, persists before keys, registers then polls",async()=>fresh("happy",async(l,state)=>{
    const {fake,sec}=await bootstrapFake(l,state),hash=await sha(canonical(config)),calls:string[]=[];
    fake.compute.mockImplementation(async(path:string,c:unknown)=>{
      calls.push(path);expect(await fake.runtimeConfig()).toEqual(config);expect(l.get("config_hash")).toBe(hash);expect(l.get("wrap")).toBeDefined();
      if(path==="/create")return sec;
      return {...sec,Runner:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",Receipt:"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",Ack:"ack"};
    });
    vi.stubGlobal("fetch",async(url:string,init:RequestInit)=>{
      if(url.endsWith("/deployment-config")){calls.push("pull");expect(init.redirect).toBe("manual");expect(init.body).toBe(canonical({registration_token:fake.env.REGISTRATION_TOKEN}));expect(l.get("wrap")).toBeUndefined();return configResponse(config,hash);}
      calls.push("poll");return new Response(canonical({work_jws:null}));
    });
    try{
      await CloudflareVerifier.prototype.pollTask.call(fake);expect(calls).toEqual(["pull","/create","/register","poll"]);
      const stored=await fake.load(config);expect(stored.Runner).not.toBe("");
      // Reconstruct storage and redeploy the same identity with a new secret.
      fake.ledger=new Ledger(state.storage);fake.env.REGISTRATION_TOKEN=random();
      await CloudflareVerifier.prototype.pollTask.call(fake);expect(calls).toEqual(["pull","/create","/register","poll","poll"]);
      expect(fake.env.SOURCE.head).not.toHaveBeenCalled();expect(fake.env.SOURCE.get).not.toHaveBeenCalled();
    }finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled");});}
  }));
  it.each(["hash","identity","scope"])("refuses %s before first-start or key generation",async(kind)=>fresh(kind,async(l,state)=>{
    const {fake}=await bootstrapFake(l,state);
    const c=kind==="identity"?{...config,binary_sha256:"e".repeat(64)}:kind==="scope"?{...config,keys:["outside"]}:config;
    vi.stubGlobal("fetch",async()=>configResponse(c,kind==="hash"?"0".repeat(64):await sha(canonical(c))));
    try{await CloudflareVerifier.prototype.pollTask.call(fake);expect(fake.compute).not.toHaveBeenCalled();expect(l.get("bootstrap")).toBeUndefined();expect(l.get("wrap")).toBeUndefined();expect(l.get("secret")).toBeUndefined();}
    finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled");});}
  }));
  it("reloads persisted config, refuses corruption and mismatched connection without reads",async()=>storage("config-corrupt",async(l,state)=>{
    const {fake}=await bootstrapFake(l,state);expect(await fake.runtimeConfig()).toEqual(config);
    l.put("connection_id","22222222-2222-2222-2222-222222222222");await expect(fake.runtimeConfig()).rejects.toThrow();
    expect(()=>fake.persistConfig({...config,connection_id:"33333333-3333-3333-3333-333333333333"},"a".repeat(64),"token")).toThrow();
    l.put("connection_id",config.connection_id);l.put("config_0",canonical({...config,keys:["p/other"]}));await expect(fake.runtimeConfig()).rejects.toThrow();
    await CloudflareVerifier.prototype.pollTask.call(fake);expect(fake.compute).not.toHaveBeenCalled();
  }));
  it("refuses a pre-registration HEAD without any source call or bootstrap pull",async()=>fresh("no-head",async(l,state)=>{
    const {fake}=await bootstrapFake(l,state),network=vi.fn();vi.stubGlobal("fetch",network);
    try{await expect(CloudflareVerifier.prototype.bridge.call(fake,new Request("http://r2-bridge.internal/member/0",{method:"HEAD"}))).rejects.toThrow();expect(network).not.toHaveBeenCalled();expect(fake.env.SOURCE.head).not.toHaveBeenCalled();}
    finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled");});}
  }));
  it("lost-ack retry keeps original bytes even with a replacement secret and never pulls",async()=>storage("lost-registration-ack",async(l,state)=>{
    const {fake,sec,original}=await bootstrapFake(l,state);l.firstStart(random(),now());await fake.save(sec,config);
    const sent:string[]=[];let lost=true;
    fake.compute.mockImplementation(async(path:string,c:unknown,s:typeof sec)=>{
      expect(path).toBe("/register");sent.push(new TextDecoder().decode(Uint8Array.from(atob(s.Registration.replaceAll("-","+").replaceAll("_","/")),c=>c.charCodeAt(0))));
      if(lost){lost=false;throw new Error("lost reply");}
      return {...s,Runner:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",Receipt:"bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb",Ack:"ack"};
    });
    const network=vi.fn(async()=>new Response(canonical({work_jws:null})));vi.stubGlobal("fetch",network);
    try{await CloudflareVerifier.prototype.pollTask.call(fake);fake.ledger=new Ledger(state.storage);await CloudflareVerifier.prototype.pollTask.call(fake);expect(sent).toEqual([original,original]);expect(network).toHaveBeenCalledTimes(1);expect(network.mock.calls[0][0]).not.toContain("deployment-config");}
    finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled");});}
  }));
  it("expired unconsumed token replacement refetches and persists a newly signed hash",async()=>storage("token-replacement",async(l,state)=>{
    const {fake,sec,original}=await bootstrapFake(l,state);l.firstStart(random(),now());await fake.save(sec,config);
    const next={...config,keys:["p/data.csv","p/new.csv"]},hash=await sha(canonical(next)),sent:string[]=[];
    fake.compute.mockImplementation(async(path:string,c:unknown,s:typeof sec)=>{
      expect(path).toBe("/register");const raw=new TextDecoder().decode(Uint8Array.from(atob(s.Registration.replaceAll("-","+").replaceAll("_","/")),c=>c.charCodeAt(0)));sent.push(raw);
      if(sent.length===1)throw new Error("registration_refused");
      const request=JSON.parse(raw),proof=request.key_proof;delete request.key_proof;
      expect(request.registration_token).toBe(fake.env.REGISTRATION_TOKEN);expect(request.deployment_config_sha256).toBe(hash);expect(l.get("config_hash")).toBe(hash);
      const key=await crypto.subtle.importKey("raw",sec.pub,"Ed25519",false,["verify"]);
      expect(await crypto.subtle.verify("Ed25519",key,Uint8Array.from(atob(proof.replaceAll("-","+").replaceAll("_","/")),c=>c.charCodeAt(0)),utf8.encode(canonical(request)))).toBe(true);
      return {...s,Runner:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",Receipt:"bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb",Ack:"ack"};
    });
    let pulls=0;vi.stubGlobal("fetch",async(url:string)=>{if(url.endsWith("/deployment-config")){pulls++;return configResponse(next,hash);}return new Response(canonical({work_jws:null}));});
    try{await CloudflareVerifier.prototype.pollTask.call(fake);expect(pulls).toBe(1);expect(sent[0]).toBe(original);expect(sent[1]).not.toBe(original);expect(await fake.runtimeConfig()).toEqual(next);expect((await fake.load(next)).Registration).not.toBe(sec.Registration);}
    finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled");});}
  }));
});

it("bootstrap config and first-start roll back together on persistence failure",async()=>fresh("atomic",async(l,state)=>{
  const {fake}=await bootstrapFake(l,state);fake.persistConfig=()=>{throw new Error("storage failure");};
  vi.stubGlobal("fetch",async()=>configResponse(config,await sha(canonical(config))));
  try{await CloudflareVerifier.prototype.pollTask.call(fake);expect(l.get("wrap")).toBeUndefined();expect(l.get("bootstrap")).toBeUndefined();expect(l.get("config_hash")).toBeUndefined();expect(fake.compute).not.toHaveBeenCalled();}
  finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled");});}
}));
it("rejects a replacement config for another connection",async()=>storage("replacement-connection",async(l,state)=>{
  const {fake}=await bootstrapFake(l,state),other={...config,connection_id:"22222222-2222-2222-2222-222222222222"};
  vi.stubGlobal("fetch",async()=>configResponse(other,await sha(canonical(other))));
  try{await expect(fake.pullConfig()).rejects.toThrow();expect(await fake.runtimeConfig()).toEqual(config);}
  finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled");});}
}));
it("stores a near-1 MiB config in bounded SQL rows and checks all chunks on reload",async()=>fresh("config-boundary",async(l,state)=>{
  const {fake}=await bootstrapFake(l,state),large={...config,keys:Array.from({length:17033},(_,i)=>"p/"+"a".repeat(46)+i)};
  const raw=canonical(large);expect(utf8.encode(raw).length).toBeLessThanOrEqual(1048576);expect(raw.length).toBeGreaterThan(524288);
  fake.persistConfig(large,await sha(raw),await sha(fake.env.REGISTRATION_TOKEN));
  expect(l.get("config_chunks")).toBe("2");expect(await fake.runtimeConfig()).toEqual(large);
  expect(l.storage.sql.exec("SELECT max(length(CAST(v AS BLOB))) n FROM meta").one().n).toBeLessThanOrEqual(524288);
  l.storage.sql.exec("DELETE FROM meta WHERE k='config_1'");await expect(fake.runtimeConfig()).rejects.toThrow();
}));
it("bootstraps and reloads exact UTF-8 config bytes with an astral character across the chunk boundary",async()=>fresh("config-astral-boundary",async(l,state)=>{
  const {fake}=await bootstrapFake(l,state),c={...config,keys:["p/😀",...Array.from({length:999},(_,i)=>"p/"+i)]};
  const initial=deploymentConfigCanonical(c),padding=524287-initial.indexOf("😀");
  c.keys[0]="p/"+"a".repeat(padding)+"😀";
  const raw=deploymentConfigCanonical(c),bytes=utf8.encode(raw),hash=await sha(bytes);
  expect(raw.indexOf("😀")).toBe(524287);expect(raw.slice(524287,524289)).toBe("😀");
  expect(bytes.slice(524287,524291)).toEqual(utf8.encode("😀"));
  const network=vi.fn(async(url:string)=>url.endsWith("/deployment-config")?configResponse(c,hash):new Response(canonical({work_jws:null})));
  vi.stubGlobal("fetch",network);
  try{
    await CloudflareVerifier.prototype.pollTask.call(fake);
    expect(l.get("bootstrap")).toBe("saved");expect(l.get("last_poll")).toBeDefined();expect(l.get("config_hash")).toBe(hash);
    const rows=l.storage.sql.exec<{data:ArrayBuffer;kind:string}>("SELECT v data,typeof(v) kind FROM meta WHERE k IN ('config_0','config_1') ORDER BY k").toArray();
    expect(rows).toHaveLength(2);for(const row of rows){expect(row.kind).toBe("blob");expect(row.data.byteLength).toBeLessThanOrEqual(524288);}
    const rebuilt=new Uint8Array(rows.reduce((sum,row)=>sum+row.data.byteLength,0));let offset=0;
    for(const row of rows){rebuilt.set(new Uint8Array(row.data),offset);offset+=row.data.byteLength;}
    expect(rebuilt).toEqual(bytes);expect(new TextDecoder("utf-8",{fatal:true}).decode(rebuilt)).toBe(raw);expect(await sha(rebuilt)).toBe(hash);
    expect(await fake.runtimeConfig()).toEqual(c);expect(fake.compute.mock.calls.map(call=>call[0])).toEqual(["/create","/register"]);
    // Simulated restart: fresh Worker methods and Ledger over the same real DO SQL storage.
    const {fake:restarted}=await bootstrapFake(new Ledger(state.storage),state);
    await CloudflareVerifier.prototype.pollTask.call(restarted);
    expect(await restarted.runtimeConfig()).toEqual(c);expect(restarted.compute).not.toHaveBeenCalled();
    expect(network).toHaveBeenCalledTimes(3);
  }finally{vi.stubGlobal("fetch",()=>{throw new Error("network disabled");});}
}));
it("compute carries the saved hash and preserves the Go base64 registration representation",async()=>storage("compute-contract",async(l,state)=>{
  const {fake,sec}=await bootstrapFake(l,state);
  const containerFetch=vi.fn(async(url:string,init:RequestInit)=>{
    const body=JSON.parse(init.body);expect(body.config.deployment_config_sha256).toBe(l.get("config_hash"));
    expect(body.secret.Registration).toMatch(/^[A-Za-z0-9+/]*={0,2}$/);
    return new Response(JSON.stringify(sec));
  });
  sec.Registration=btoa(canonical({registration_token:fake.env.REGISTRATION_TOKEN,key_proof:"x"}));
  await CloudflareVerifier.prototype.compute.call({...fake,containerFetch},"/register",config,sec);
  expect(containerFetch).toHaveBeenCalledTimes(1);
}));
