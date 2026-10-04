// Secret names are not present in wrangler.jsonc; no values are embedded.
declare global { interface Env { R2_ACCESS_KEY_ID: string; R2_SECRET_ACCESS_KEY: string; SPIKE_SPEC_JSON: string; } }
import { Container, getContainer } from "@cloudflare/containers";
export { Ledger } from "../ledger/ledger.mjs";
export class Scanner extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = "2m";
  envVars = {
    R2_ENDPOINT: this.env.R2_ENDPOINT,
    R2_ACCESS_KEY_ID: this.env.R2_ACCESS_KEY_ID,
    R2_SECRET_ACCESS_KEY: this.env.R2_SECRET_ACCESS_KEY,
  };
}
export default {
  fetch() { return new Response("Measurement spike: scheduled only", {status:404}); },
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil((async () => {
      if (!env.SPIKE_SPEC_JSON) return;
      const spec = await env.LEDGER.getByName("spike-runner").admit(JSON.parse(env.SPIKE_SPEC_JSON));
      const response = await getContainer(env.SCANNER, "only-instance").fetch(new Request("http://container/", {
        method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(spec.event)
      }));
      if (!response.ok) throw new Error("container_failure");
      // Harness response is bounded, contains measurements/digest only.
      const text = await response.text();
      if (text.length > 65536) throw new Error("result_too_large");
      console.log(text);
    })());
  }
} satisfies ExportedHandler<Env>;
