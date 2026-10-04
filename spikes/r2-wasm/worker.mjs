// Illustrative only: both compilation and a seller-account runtime test are needed.
import "./dist/wasm_exec.js";
import wasm from "./dist/scan-js.wasm";
export { Ledger } from "../ledger/ledger.mjs";
// Go installs one process-global callback; serialize scans in this isolate.
let tail = Promise.resolve();
let runtime;
function initialize() {
  runtime ??= (async () => {
    const go = new globalThis.Go();
    const instance = await WebAssembly.instantiate(wasm, go.importObject);
    void go.run(instance).catch(() => console.log('{"phase":"wasm_runtime_error"}'));
    await Promise.resolve();
  })();
  return runtime;
}
async function execute(spec, env) {
  const object = spec.event.objects[0];
  if (spec.event.mode !== "scan" || spec.event.objects.length !== 1 || !object.key.startsWith("spike/") || !object.etag) throw new Error("unsupported_fixture");
  const body = await env.DATA.get(object.key, {onlyIf:{etagMatches:object.etag.replace(/^"|"$/g, "")}});
  if (!body || !body.body) throw new Error("artifact_changed");
  // Deliberately in-memory for S-R2. Refuse before buffering beyond the fixture cap.
  if (body.size > 50_000_000) throw new Error("fixture_memory_cap");
  const data = new Uint8Array(await body.arrayBuffer());
  await initialize();
  const result = JSON.parse(globalThis.spikeScan(data, object.format));
  console.log(JSON.stringify(result));
}
export default {
  fetch() { return new Response("Measurement spike: scheduled only", {status:404}); },
  scheduled(_controller, env, ctx) {
    const work = tail.then(async () => {
      if (!env.SPIKE_SPEC_JSON) return;
      const spec = await env.LEDGER.getByName("spike-runner").admit(JSON.parse(env.SPIKE_SPEC_JSON));
      await execute(spec, env);
    });
    tail = work.catch(() => {});
    ctx.waitUntil(work);
  }
};
