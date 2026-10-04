// Go js/wasm smoke check on synthetic bytes, without any cloud binding.
import "./dist/wasm_exec.js";
import {readFile} from "node:fs/promises";
const go=new globalThis.Go();
const module=await WebAssembly.compile(await readFile(new URL("./dist/scan-js.wasm",import.meta.url)));
const instance=await WebAssembly.instantiate(module,go.importObject);
void go.run(instance);
const bytes=new Uint8Array(await readFile(process.argv[2]));
const result=JSON.parse(globalThis.spikeScan(bytes,process.argv[3] ?? "csv"));
console.log(JSON.stringify(result));
process.exit(result.error ? 1 : 0);
