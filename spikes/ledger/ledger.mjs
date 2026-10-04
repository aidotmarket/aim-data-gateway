import { DurableObject } from "cloudflare:workers";
/** @typedef {{payload_b64: string, signature_b64: string}} Envelope */
/** @typedef {{listing_id: string, listing_version_id: string, nonce: string, owner_authorization_id: string, accepted_at_utc: string, issued_at_utc: string, event: {mode: string, bucket: string, objects: Array<{key: string, etag?: string, version_id?: string, format: string}>}}} SpikeSpec */
const DAY = 86400000;
function from64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
// Measurement fixture protocol only, not the marketplace scan-spec protocol.
// Signature covers the exact payload bytes; a configured public key is mandatory.
/** @returns {Promise<SpikeSpec>} */
export async function verifyEnvelope(envelope, env) {
  const raw = from64(envelope.payload_b64);
  if (raw.length > 65536 || !env.SPIKE_SPEC_PUBLIC_KEY_B64) throw new Error("invalid_spec");
  const key = await crypto.subtle.importKey("raw", from64(env.SPIKE_SPEC_PUBLIC_KEY_B64), "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", key, from64(envelope.signature_b64), raw)) throw new Error("invalid_signature");
  return JSON.parse(new TextDecoder().decode(raw));
}
export function validate(spec, env, now) {
  for (const k of ["listing_id", "listing_version_id", "nonce", "owner_authorization_id", "accepted_at_utc", "issued_at_utc"]) {
    if (typeof spec[k] !== "string" || !spec[k] || spec[k].length > 256) throw new Error("missing_binding");
  }
  if (!env.LISTING_ID || !env.LISTING_VERSION_ID || spec.listing_id !== env.LISTING_ID || spec.listing_version_id !== env.LISTING_VERSION_ID) throw new Error("wrong_version");
  const issued = Date.parse(spec.issued_at_utc), accepted = Date.parse(spec.accepted_at_utc);
  if (!Number.isFinite(issued) || !Number.isFinite(accepted) || issued > now + 300000 || issued < now - DAY || accepted > now + 300000 || accepted > issued + 300000 || accepted < now - DAY) throw new Error("expired_spec");
  if (!spec.event || !["scan", "probe", "throughput"].includes(spec.event.mode) || !Array.isArray(spec.event.objects) || !spec.event.objects.length) throw new Error("invalid_event");
}
/** @typedef {{SPIKE_SPEC_PUBLIC_KEY_B64: string, LISTING_ID: string, LISTING_VERSION_ID: string}} LedgerEnv */
/** @extends {DurableObject<LedgerEnv>} */
export class Ledger extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS used (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)");
    ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS counts (listing TEXT, day TEXT, n INTEGER NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(listing,day))");
  }
  /** @param {Envelope} envelope @returns {Promise<SpikeSpec>} */
  async admit(envelope) {
    console.log(JSON.stringify({phase:"received"}));
    try {
      const spec = await verifyEnvelope(envelope, this.env);
      const now = Date.now(); validate(spec, this.env, now);
      // One synchronous transaction commits BOTH uniqueness markers and the counter
      // before returning permission to read bytes. Exceptions roll back all writes.
      this.ctx.storage.transactionSync(() => {
        const sql = this.ctx.storage.sql;
        sql.exec("DELETE FROM used WHERE expires <= ?", now);
        sql.exec("DELETE FROM counts WHERE expires <= ?", now);
        const ids = ["nonce:" + spec.nonce, "authorization:" + spec.owner_authorization_id];
        for (const id of ids) {
          if (sql.exec("SELECT id FROM used WHERE id = ?", id).toArray().length) throw new Error("replay");
        }
        const day = new Date(now).toISOString().slice(0,10);
        const row = sql.exec("SELECT n FROM counts WHERE listing = ? AND day = ?", spec.listing_id, day).toArray()[0];
        const n = row?.n ?? 0; if (n >= 10) throw new Error("daily_limit");
        for (const id of ids) sql.exec("INSERT INTO used VALUES (?,?)", id, now + 30*DAY);
        sql.exec("INSERT INTO counts VALUES (?,?,?,?) ON CONFLICT(listing,day) DO UPDATE SET n=excluded.n", spec.listing_id, day, n+1, now+30*DAY);
      });
      console.log(JSON.stringify({phase:"accepted"})); return spec;
    } catch (error) {
      console.log(JSON.stringify({phase:"refused"})); throw error;
    }
  }
}
