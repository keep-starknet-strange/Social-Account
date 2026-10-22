// Downloads the browser prover's wasm modules into public/prover/ and checks each against
// manifest.json (size and sha256). The modules are release assets, not committed. Already
// verified files are kept. Run from client/: bun run prover:assets
import { createHash } from 'node:crypto';
import manifest from '../public/prover/manifest.json';

const root = new URL('../public/prover/', import.meta.url);
const sha256 = (b: ArrayBuffer) => createHash('sha256').update(new Uint8Array(b)).digest('hex');

for (const asset of manifest.assets) {
  const file = Bun.file(new URL(asset.path, root));
  const valid = (b: ArrayBuffer) => b.byteLength === asset.bytes && sha256(b) === asset.sha256;
  if ((await file.exists()) && valid(await file.arrayBuffer())) {
    console.log(`verified ${asset.path}`);
    continue;
  }
  const res = await fetch(asset.url, { signal: AbortSignal.timeout(300_000) });
  if (!res.ok) throw new Error(`${asset.name}: HTTP ${res.status}`);
  const bytes = await res.arrayBuffer();
  if (!valid(bytes)) throw new Error(`${asset.name}: size or sha256 differs from manifest.json`);
  await Bun.write(file, bytes);
  console.log(`downloaded ${asset.path} (${(bytes.byteLength / 1e6).toFixed(1)} MB)`);
}
