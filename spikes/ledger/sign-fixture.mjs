// Generates a fresh synthetic fixture key in memory, never a marketplace identity.
import {generateKeyPairSync, sign, randomUUID} from "node:crypto";
import {readFile} from "node:fs/promises";
const event=JSON.parse(await readFile(process.argv[2],"utf8"));
const {privateKey,publicKey}=generateKeyPairSync("ed25519");
const now=new Date().toISOString();
const payload=Buffer.from(JSON.stringify({listing_id:"synthetic-listing",listing_version_id:"synthetic-v1",nonce:randomUUID(),owner_authorization_id:randomUUID(),accepted_at_utc:now,issued_at_utc:now,event}));
console.log(JSON.stringify({public_key_b64:publicKey.export({type:"spki",format:"der"}).subarray(-32).toString("base64"),envelope:{payload_b64:payload.toString("base64"),signature_b64:sign(null,payload,privateKey).toString("base64")}},null,2));
