// Bind the local generator's artifact and manifest to the spec the installer actually read.
// This checks identity, not independent reproduction of the manifest's claims about the Wasm.
import { createHash } from 'node:crypto';
import { cliSpecHash } from './check-runner.mjs';

export async function checkArtifact(spec, wasm, manifest) {
  const wasmHash = createHash('sha256').update(wasm).digest('hex');
  if (manifest?.wasm_hash !== wasmHash || manifest.rule_index !== 0
      || manifest.registry_snapshot !== spec.registry_snapshot
      || typeof manifest.spec_hash !== 'string' || !/^[0-9a-f]{64}$/.test(manifest.spec_hash)) {
    throw new Error('build-manifest.json does not identify this artifact for rule 0 of this spec');
  }
  if (manifest.spec_hash !== await cliSpecHash(spec)) {
    throw new Error('build-manifest.json spec_hash does not match the validated spec');
  }
  return wasmHash;
}
