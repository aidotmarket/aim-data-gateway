export { Ledger } from "./ledger.mjs";
export default {
 async fetch(request, env) {
  try { const spec = await env.LEDGER.getByName("test-runner").admit(await request.json()); return Response.json({accepted:true, mode:spec.event.mode}); }
  catch (error) { return Response.json({error:error.message}, {status:409}); }
 }
};
