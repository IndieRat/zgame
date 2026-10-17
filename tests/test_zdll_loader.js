const assert = require("node:assert/strict");
const { createHash, webcrypto } = require("node:crypto");
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const { decodeZdllContainer, normalizeLibraryName, findZdllEntries } = require("../web/zwasm_host.js");

function makeContainer(overrides = {}) {
  const wasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const digest = createHash("sha256").update(wasm).digest();
  const manifest = Buffer.from(JSON.stringify({
    schema: "zwasm.zdll/1",
    formatVersion: 1,
    name: "kernel32",
    abi: "zworld.v1",
    module: "module.wasm",
    sha256: digest.toString("hex")
  }));
  const offset = 64 + manifest.length;
  const result = Buffer.alloc(offset + wasm.length);
  Buffer.from("ZDLLG01" + String.fromCharCode(0), "binary").copy(result, 0);
  result.writeUInt32LE(1, 8);
  result.writeUInt32LE(0, 12);
  result.writeBigUInt64LE(BigInt(offset), 16);
  result.writeBigUInt64LE(BigInt(wasm.length), 24);
  digest.copy(result, 32);
  manifest.copy(result, 64);
  wasm.copy(result, offset);
  if (overrides.mutate) overrides.mutate(result);
  return new Uint8Array(result);
}

(async () => {
  const decoded = await decodeZdllContainer(makeContainer());
  assert.equal(decoded.manifest.name, "kernel32");
  assert.equal(decoded.manifest.abi, "zworld.v1");
  assert.deepEqual(Buffer.from(decoded.wasmBytes), Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
  assert.equal(normalizeLibraryName("zwasm_guest/zdlls/Kernel32.zdll"), "kernel32");
  const slash = String.fromCharCode(92);
  assert.equal(normalizeLibraryName("C:" + slash + "Game" + slash + "bin" + slash + "USER32.DLL"), "user32");
  assert.equal(findZdllEntries({ entries: [{ path: "zwasm_guest/zdlls/kernel32.zdll" }] }).length, 1);

  await assert.rejects(() => decodeZdllContainer(makeContainer({ mutate: b => { b[0] = 0x58; } })), /bad ZDLL magic/);
  await assert.rejects(() => decodeZdllContainer(makeContainer({ mutate: b => { b[16] = 0xff; } })), /payload bounds/);
  await assert.rejects(() => decodeZdllContainer(makeContainer({ mutate: b => { b[b.length - 1] ^= 1; } })), /payload SHA-256 mismatch/);
  await assert.rejects(() => decodeZdllContainer(makeContainer({ mutate: b => { b[8] = 2; } })), /unsupported ZDLL version/);
  console.log("ZDLL loader tests passed");
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
