import { refuse } from "./state";
export const utf8 = new TextEncoder();
export const now = () => Math.floor(Date.now()/1000);
export function b64(b: Uint8Array): string { return btoa(String.fromCharCode(...b)).replaceAll("+","-").replaceAll("/","_").replaceAll("=",""); }
export function unb64(s: string): Uint8Array<ArrayBuffer> {return Uint8Array.from(atob(s.replaceAll("-","+").replaceAll("_","/")),c=>c.charCodeAt(0));}
export function random(): string { return b64(crypto.getRandomValues(new Uint8Array(32))); }
export async function sha(s: string | Uint8Array<ArrayBuffer>): Promise<string> {return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",typeof s==="string"?utf8.encode(s):s)),b=>b.toString(16).padStart(2,"0")).join("");}
// Python ensure_ascii=True, sorted compact JSON for control envelopes.
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return "["+v.map(canonical).join(",")+"]";
  if (v !== null && typeof v === "object") return "{"+Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,v])=>canonical(k)+":"+canonical(v)).join(",")+"}";
  const s=JSON.stringify(v);
  if (s===undefined) refuse();
  return s.replace(/[\u007f-\uffff]/g,c=>"\\u"+c.charCodeAt(0).toString(16).padStart(4,"0"));
}
// Deployment config uses Python ensure_ascii=False. Its schema contains no numbers.
export function deploymentConfigCanonical(v: unknown): string {
  if (typeof v === "string") {
    for (const c of v) {
      const cp=c.codePointAt(0)!;
      if(cp>=0xd800 && cp<=0xdfff)refuse();
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "["+v.map(deploymentConfigCanonical).join(",")+"]";
  if (v !== null && typeof v === "object") {
    const compare=(a:string,b:string):number=>{
      const x=Array.from(a,c=>c.codePointAt(0)!),y=Array.from(b,c=>c.codePointAt(0)!);
      for(let i=0;i<Math.min(x.length,y.length);i++)if(x[i]!==y[i])return x[i]-y[i];
      return x.length-y.length;
    };
    return "{"+Object.entries(v).sort(([a],[b])=>compare(a,b)).map(([k,z])=>deploymentConfigCanonical(k)+":"+deploymentConfigCanonical(z)).join(",")+"}";
  }
  if(v===null || typeof v==="boolean")return JSON.stringify(v);
  return refuse();
}
export async function encrypt(wrap: string, connection: string, value: unknown): Promise<string> {
  const key=await crypto.subtle.importKey("raw",unb64(wrap),"AES-GCM",false,["encrypt"]);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:utf8.encode(connection+"/secret-v1")},key,utf8.encode(JSON.stringify(value)));
  // State can contain a 1 MiB frozen registration; avoid spread stack limits.
  return JSON.stringify({iv:b64(iv),cipher:Array.from(new Uint8Array(cipher),b=>b.toString(16).padStart(2,"0")).join("")});
}
export async function decrypt<T>(wrap: string, connection: string, value: string): Promise<T> {
  try {
    const v=JSON.parse(value);
    if(Object.keys(v).sort().join(" ")!=="cipher iv" || typeof v.iv!=="string" || unb64(v.iv).length!==12 || typeof v.cipher!=="string" || !/^[0-9a-f]+$/.test(v.cipher) || v.cipher.length%2 || v.cipher.length>4*1048576)refuse();
    const key=await crypto.subtle.importKey("raw",unb64(wrap),"AES-GCM",false,["decrypt"]);
    const cipher=Uint8Array.from(v.cipher.match(/../g), (s:string)=>parseInt(s,16));
    const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(v.iv),additionalData:utf8.encode(connection+"/secret-v1")},key,cipher);
    return JSON.parse(new TextDecoder().decode(plain));
  } catch {return refuse();}
}
export async function equalSecret(a: string,b: string): Promise<boolean> {
  const x=await sha(a),y=await sha(b);let diff=0;
  for(let i=0;i<x.length;i++)diff|=x.charCodeAt(i)^y.charCodeAt(i);
  return diff===0;
}
export async function bounded(response: Response,limit: number): Promise<string> {
  if(!response.body)return "";
  const reader=response.body.getReader();const chunks:Uint8Array[]=[];let n=0;
  try { for(;;){const r=await reader.read();if(r.done)break;n+=r.value.length;if(n>limit)refuse();chunks.push(r.value);} }
  finally {await reader.cancel();}
  const out=new Uint8Array(n);let at=0;for(const c of chunks){out.set(c,at);at+=c.length;}
  return new TextDecoder("utf-8",{fatal:true}).decode(out);
}
