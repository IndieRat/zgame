const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const loader = fs.readFileSync(path.join(root, "web", "zwasm.js"), "utf8");
const builder = fs.readFileSync(path.join(root, "tools", "zwasm_build.py"), "utf8");
const batch = fs.readFileSync(path.join(root, "tools", "build_isaac_179c.bat"), "utf8");

assert.equal(loader.includes("skipping legacy wasm zdll loader"), false,
  "obsolete top-level ZDLL stub must not remain");
assert.match(loader, /decodeZdllContainer\(container\)/,
  "ZDLL modules must use the current validated container decoder");
assert.match(loader, /normalizeLibraryName\(zfn\.dll\)/,
  "API dispatch should normalize library names");
assert.match(loader, /returning -1/,
  "unsupported APIs must not silently claim success with zero");

const start = loader.indexOf("async start()");
const stop = loader.indexOf("verifyImage(label)", start);
assert.ok(start >= 0 && stop > start, "GuestRuntime.start must be present");
const lifecycle = loader.slice(start, stop);
const orderedCalls = [
  "await this.loadZApis()",
  "await this.loadZDLLs()",
  "await this.loadXapiManifests()",
  "ex.x86_dll_rebind_imports()"
].map((token) => lifecycle.indexOf(token));
assert.ok(orderedCalls.every((index) => index >= 0),
  "all API registration and import rebinding stages must exist");
assert.ok(orderedCalls.every((index, i) => i === 0 || orderedCalls[i - 1] < index),
  "API manifests and modules must load before guest import rebinding");

assert.match(builder, /--guest-dll/,
  "native Windows DLLs must use the guest-DLL packaging path");
assert.equal(builder.includes("DLL_CONVERTER"), false,
  "native PE DLLs must not be wrapped in the WebAssembly .zdll format");
assert.match(batch, /C:\\TBOIRG\\The Binding of Isaac Rebirth Repentance v1\.7\.9c/,
  "the convenience build script must target the requested Isaac directory");
assert.match(batch, /--work-dir/,
  "the convenience build script must keep generated files outside the game install");

console.log("API loading contract tests passed");
