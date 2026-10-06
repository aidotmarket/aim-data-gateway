import { DurableObject } from "cloudflare:workers";
export class Harness extends DurableObject {}
export default {fetch(){return new Response("test only");}};
