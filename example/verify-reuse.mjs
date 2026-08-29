// Verify the reclaim fix in the WASM build: call getData() many times on ONE reused
// Anisette instance (my getData change no longer re-inits per call). Old behavior would
// re-init every call; the point is that reuse now works past the ~117-request limit.
import fs from "node:fs/promises";
import path from "node:path";
const { Anisette, loadWasm } = await import("../js/dist/index.js");

const [ssc, core, libDir = "./anisette/", n = "150"] = process.argv.slice(2);
const wasmModule = await loadWasm({ printErr: () => {} });
const storeservices = new Uint8Array(await fs.readFile(ssc));
const coreadi = new Uint8Array(await fs.readFile(core));
const opt = (p) => fs.readFile(p).then((b) => new Uint8Array(b)).catch(() => null);
const [adiPb, deviceJsonBytes] = await Promise.all([
  opt(path.join(libDir, "adi.pb")),
  opt(path.join(libDir, "device.json")),
]);

const anisette = await Anisette.fromSo(storeservices, coreadi, wasmModule, {
  init: { libraryPath: libDir, adiPb, deviceJsonBytes },
});
console.log("provisioned:", anisette.isProvisioned);

const N = Number(n);
const t0 = Date.now();
let first, last;
for (let i = 0; i < N; i++) {
  const h = await anisette.getData();
  if (i === 0) first = h["X-Apple-I-MD"];
  last = h["X-Apple-I-MD"];
}
const ms = Date.now() - t0;
console.log(`OK ${N} getData() calls in ${ms} ms (${(ms / N).toFixed(1)} ms/call)`);
console.log("first MD:", first.slice(0, 16), "last MD:", last.slice(0, 16));
