// All admission, counter, lease, clock, audit and outbox mutations are atomic.
import { createHash } from "node:crypto";
export type Job = {
  Token: string;
  Envelope: { iid: string; spec_hash: string; variant: string };
  Payload: Record<string, string>;
};
export type Admission = {
  id: string; token: string; hash: string; iid: string; variant: string;
  snapshot: string; objects: Member[]; pickup: number; start: number; state: string;
};
export type Member = { Key: string; ETag: string; Size: number; Format: string };
export const RETENTION = 30 * 86400;
export const LEASE_GRACE = 900 + 120;
const DATA_CHUNK = 512 * 1024;
type Stored = Omit<Admission, "snapshot" | "objects"> & {data?: {chunks:number;bytes:number;hash:string};snapshot?:string;objects?:Member[]};
const digest = (s:string) => createHash("sha256").update(s).digest("hex");
export function refuse(): never { throw new Error("verification_refused"); }

export class Ledger {
  constructor(readonly storage: DurableObjectStorage) {
    storage.transactionSync(() => {
      const tables = storage.sql.exec<{name:string}>("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('meta','admissions','daily','events','outbox','chunks','admission_chunks')").toArray();
      if (tables.length) {
        const version=this.get("schema");
        if (!((version==="verifier-state-v1" && tables.length===6) || (version==="verifier-state-v2" && tables.length===7))) refuse();
        for(const k of ["clock","active","lease","wake","task"])if(this.get(k)===undefined)refuse();
        if(version==="verifier-state-v1"){
          storage.sql.exec("CREATE TABLE admission_chunks(id TEXT NOT NULL,n INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(id,n))");
          for(const row of storage.sql.exec<{id:string;record:string}>("SELECT id,record FROM admissions")){
            const r:Admission=JSON.parse(row.record);
            if(r.id!==row.id || typeof r.snapshot!=="string" || !Array.isArray(r.objects))refuse();
            storage.sql.exec("UPDATE admissions SET record=? WHERE id=?",this.pack(r),row.id);
          }
          this.put("schema","verifier-state-v2");
        }
        return;
      }
      storage.sql.exec(`CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,hash TEXT NOT NULL,iid TEXT UNIQUE NOT NULL,nonce TEXT UNIQUE NOT NULL,authorization TEXT UNIQUE NOT NULL,record TEXT NOT NULL,until INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS daily(listing TEXT NOT NULL,day TEXT NOT NULL,n INTEGER NOT NULL,PRIMARY KEY(listing,day));
        CREATE TABLE IF NOT EXISTS events(at INTEGER NOT NULL,event TEXT NOT NULL,hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,hash TEXT NOT NULL,bytes INTEGER NOT NULL,chunks INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS chunks(id TEXT NOT NULL,n INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(id,n));
        CREATE TABLE IF NOT EXISTS admission_chunks(id TEXT NOT NULL,n INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(id,n));`);
      this.put("schema", "verifier-state-v2");
      for(const [k,v] of Object.entries({clock:"0",active:"",lease:"0",wake:"0",task:""}))this.put(k,v);
    });
  }
  get(k: string): string | undefined {
    return this.storage.sql.exec<{v: string}>("SELECT v FROM meta WHERE k=?", k).toArray()[0]?.v;
  }
  put(k: string, v: string) { this.storage.sql.exec("INSERT OR REPLACE INTO meta VALUES (?,?)", k, v); }
  event(event: string, hash: string, now: number) {
    this.storage.sql.exec("INSERT INTO events VALUES (?,?,?)", now, event, hash);
  }
  clock(now: number) {
    const last = Number(this.get("clock") ?? 0);
    if (!Number.isSafeInteger(now) || now < last - 300) refuse();
    this.put("clock", String(Math.max(now, last)));
  }
  observe(now: number) { this.storage.transactionSync(() => this.clock(now)); }
  firstStart(wrap: string, now: number): boolean {
    return this.storage.transactionSync(() => {
      this.clock(now);
      if (this.get("bootstrap")) {
        if (!this.get("wrap") || !this.get("secret")) refuse();
        return false;
      }
      // Partial state must never be mistaken for an empty, new installation.
      if (this.get("wrap") || this.get("secret") || this.storage.sql.exec("SELECT id FROM admissions LIMIT 1").toArray().length) refuse();
      this.put("bootstrap", "initializing"); this.put("wrap", wrap);
      this.event("bootstrap", "", now);
      return true;
    });
  }
  private pack(r:Admission):string {
    const {snapshot,objects,...meta}=r;
    if(["reported","expired","interrupted"].includes(r.state))return JSON.stringify({...meta,snapshot:"",objects:[]});
    // ASCII JSON keeps byte bounds exact, including non-ASCII object keys.
    const body=JSON.stringify({snapshot,objects}).replace(/[\u007f-\uffff]/g,c=>"\\u"+c.charCodeAt(0).toString(16).padStart(4,"0"));
    const chunks=Math.ceil(body.length/DATA_CHUNK);
    for(let n=0;n<chunks;n++)this.storage.sql.exec("INSERT INTO admission_chunks VALUES (?,?,?)",r.id,n,body.slice(n*DATA_CHUNK,(n+1)*DATA_CHUNK));
    return JSON.stringify({...meta,data:{chunks,bytes:body.length,hash:digest(body)}});
  }
  record(id: string): Admission | undefined {
    return this.storage.transactionSync(()=>{
      const row=this.storage.sql.exec<{record:string}>("SELECT record FROM admissions WHERE id=?",id).toArray()[0];
      if(!row)return;
      const {data,...meta}:Stored=JSON.parse(row.record);
      if(!data){
        if(!["reported","expired","interrupted"].includes(meta.state) || meta.snapshot!=="" || !Array.isArray(meta.objects) || meta.objects.length)refuse();
        return {...meta,snapshot:"",objects:[]};
      }
      const chunks=this.storage.sql.exec<{n:number;data:string}>("SELECT n,data FROM admission_chunks WHERE id=? ORDER BY n",id).toArray();
      if(!Number.isSafeInteger(data.chunks) || data.chunks<1 || chunks.length!==data.chunks || chunks.some((c,i)=>c.n!==i || !c.data.length || c.data.length>DATA_CHUNK || /[^\x00-\x7f]/.test(c.data)))refuse();
      const body=chunks.map(c=>c.data).join("");
      if(body.length!==data.bytes || digest(body)!==data.hash)refuse();
      const payload=JSON.parse(body);
      if(typeof payload.snapshot!=="string" || !Array.isArray(payload.objects) || payload.objects.length>17033)refuse();
      return {...meta,snapshot:payload.snapshot,objects:payload.objects};
    });
  }
  active(): Admission | undefined {
    const id = this.get("active");
    if (!id) return;
    return this.record(id) ?? refuse();
  }
  wake(now: number): boolean {
    return this.storage.transactionSync(() => {
      this.clock(now);
      const wake=Number(this.get("wake")??0),lease=Number(this.get("lease")??0);
      const task=this.get("task"),marker=task==="queued"?wake:lease||wake;
      if (wake > now - 60 || (task && now <= marker+LEASE_GRACE)) return false;
      this.put("wake", String(now)); this.put("task", "queued"); return true;
    });
  }
  claim(now: number): boolean {
    return this.storage.transactionSync(() => {
      this.clock(now);
      const lease = Number(this.get("lease") ?? 0);
      if (lease && now <= lease + LEASE_GRACE) return false;
      this.put("lease", String(now)); this.put("task", "running"); return true;
    });
  }
  release() { this.storage.transactionSync(() => { this.put("lease", "0"); this.put("task", ""); }); }
  admit(job: Job, snapshot: string, objects: Member[], now: number, pickup: number, start: number): Admission | undefined {
    return this.storage.transactionSync(() => {
      this.clock(now);
      const p = job.Payload;
      const existing = this.record(p.spec_id);
      if (existing) {
        if (existing.token !== job.Token || existing.hash !== job.Envelope.spec_hash) refuse();
        return;
      }
      if (this.active() || now > Date.parse(p.expires_at_utc)/1000 || now > Date.parse(p.accepted_at_utc)/1000 + 86400 || now > pickup + 1920) refuse();
      const day = new Date(now * 1000).toISOString().slice(0,10);
      const n = this.storage.sql.exec<{n: number}>("SELECT n FROM daily WHERE listing=? AND day=?", p.listing_id, day).toArray()[0]?.n ?? 0;
      if (n >= 10) refuse();
      const r: Admission = {id:p.spec_id,token:job.Token,hash:job.Envelope.spec_hash,iid:job.Envelope.iid,variant:job.Envelope.variant,snapshot,objects,pickup,start,state:"accepted"};
      this.storage.sql.exec("INSERT INTO admissions VALUES (?,?,?,?,?,?,?)", r.id,r.hash,r.iid,p.nonce,p.owner_authorization_id,this.pack(r),now+RETENTION);
      this.storage.sql.exec("INSERT OR REPLACE INTO daily VALUES (?,?,?)",p.listing_id,day,n+1);
      this.put("active", r.id); this.event("accepted", r.hash, now);
      return r;
    });
  }
  commit(r: Admission, body: string, hash: string, now: number) {
    const bytes = new TextEncoder().encode(body);
    if (!bytes.length || bytes.length > 2<<20 || !/^[a-f0-9]{64}$/.test(hash)) refuse();
    // Reports use ASCII canonical JSON. Chunk on codepoints, never UTF-8 bytes.
    if ([...body].some(c => c.charCodeAt(0)>127)) refuse();
    this.storage.transactionSync(() => {
      this.clock(now);
      const current = this.record(r.id);
      if (!current || current.state !== "accepted" || this.get("active") !== r.id || now > r.pickup+1920) refuse();
      const count = Math.ceil(body.length / 131072);
      for (let n=0;n<count;n++) this.storage.sql.exec("INSERT INTO chunks VALUES (?,?,?)",r.id,n,body.slice(n*131072,(n+1)*131072));
      this.storage.sql.exec("INSERT INTO outbox VALUES (?,?,?,?)",r.id,hash,bytes.length,count);
      this.update({...current,state:"committed"},now);
      this.event("committed",r.hash,now);
    });
  }
  body(r: Admission): {body: string; hash: string} {
    return this.storage.transactionSync(() => {
      const d = this.storage.sql.exec<{hash:string;bytes:number;chunks:number}>("SELECT * FROM outbox WHERE id=?",r.id).toArray()[0];
      const chunks = this.storage.sql.exec<{n:number;data:string}>("SELECT n,data FROM chunks WHERE id=? ORDER BY n",r.id).toArray();
      if (!d || chunks.length!==d.chunks || chunks.some((c,i)=>c.n!==i)) refuse();
      const body = chunks.map(c=>c.data).join("");
      if (body.length!==d.bytes) refuse();
      return {body,hash:d.hash};
    });
  }
  update(r: Admission, now: number) {
    // Snapshot custody is immutable; state/timing updates retain its descriptor.
    const {snapshot,objects,...meta}=r;
    const row=this.storage.sql.exec<{record:string}>("SELECT record FROM admissions WHERE id=?",r.id).toArray()[0]??refuse();
    const saved:Stored=JSON.parse(row.record);
    this.storage.sql.exec("UPDATE admissions SET record=?,until=? WHERE id=?",JSON.stringify({...meta,...(saved.data?{data:saved.data}:{snapshot:"",objects:[]})}),now+RETENTION,r.id);
  }
  settle(r: Admission, state: string, now: number) {
    this.storage.transactionSync(() => {
      this.clock(now); this.update({...r,state},now);this.event(state,r.hash,now);
      this.storage.sql.exec("DELETE FROM chunks WHERE id=?",r.id);this.storage.sql.exec("DELETE FROM outbox WHERE id=?",r.id);
      this.storage.sql.exec("UPDATE admissions SET record=json_set(json_remove(record,'$.data'),'$.snapshot','','$.objects',json('[]')) WHERE id=?",r.id);
      this.storage.sql.exec("DELETE FROM admission_chunks WHERE id=?",r.id);
      this.put("active", "");
    });
  }
  prune(now: number) {
    this.storage.transactionSync(() => {
      this.storage.sql.exec("DELETE FROM admissions WHERE until<? AND id NOT IN (SELECT id FROM outbox) AND id!=? AND json_extract(record,'$.state') IN ('reported','expired','interrupted')",now,this.get("active")??"");
      this.storage.sql.exec("DELETE FROM admission_chunks WHERE id NOT IN (SELECT id FROM admissions)");
      this.storage.sql.exec("DELETE FROM events WHERE at<?",now-RETENTION);
      this.storage.sql.exec("DELETE FROM daily WHERE day<?",new Date((now-RETENTION)*1000).toISOString().slice(0,10));
    });
  }
}
