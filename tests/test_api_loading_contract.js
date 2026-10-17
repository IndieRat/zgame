const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const loader = fs.readFileSync(path.join(root, "web", "zwasm.js"), "utf8");
const builder = fs.readFileSync(path.join(root, "tools", "zwasm_build.py"), "utf8");
const batch = fs.readFileSync(path.join(root, "tools", "build_isaac_179c.bat"), "utf8");
const runtime = fs.readFileSync(path.join(root, "runtime", "x86", "runtime.c"), "utf8");

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


assert.match(runtime, /import_rva,import_size/,
  "loaded DLL records must preserve their import directory");

assert.match(runtime, /#define X86_MEM_REGION_MAX 4096u/,
  "guest memory-region metadata must not exhaust during CRT startup allocations");
assert.match(runtime, /X\(_callnewh,1,0\)/,
  "the CRT new-handler probe must resolve rather than trap");
assert.match(runtime, /X\(BringWindowToTop,1,1\)/,
  "common USER32 window calls must resolve through the Win32 shim catalogue");
assert.match(runtime, /X\(GetProcessTimes,5,1\)/,
  "the common Kernel32 system query imports must resolve");
assert.match(runtime, /case SHIM_GetCursorPos/,
  "cursor position calls must have safe output handling");
assert.match(runtime, /case SHIM_timeGetDevCaps/,
  "multimedia capability queries must resolve with a compatible return code");
assert.match(runtime, /case SHIM_BringWindowToTop/,
  "window-management imports must not fall through to unresolved traps");
assert.match(runtime, /case SHIM_GetProcessTimes/,
  "common Kernel32 system information queries must write defined outputs");

const host = fs.readFileSync(path.join(root, "web", "zwasm_host.js"), "utf8");
assert.match(host, /dynamicIatBytes\.has\(va \+ k\)/,
  "image verification must ignore IAT bytes changed by successful import binding");
assert.match(loader, /this\.guestPe, base, this\.instance\.exports/,
  "runtime import metadata must be supplied to the image verifier");
assert.match(runtime, /case SHIM_free:x86_crt_free_impl\(ARG\(0\)\);break;/,
  "free must release CRT allocation records");
assert.match(runtime, /case SHIM_realloc:r=x86_crt_realloc_impl\(ARG\(0\),ARG\(1\)\);break;/,
  "realloc must use the CRT allocation tracker");
assert.match(runtime, /x86_dll_name_equal\(dll,m->requested_name\)/,
  "DLL resolution must accept a loaded module's requested filename as well as its internal export name");
const rebindStart = runtime.indexOf("static void x86_dll_rebind_all(void){");
const rebindStop = runtime.indexOf("/* Implicit TLS", rebindStart);
assert.ok(rebindStart >= 0 && rebindStop > rebindStart,
  "native DLL rebind implementation must exist");
const rebind = runtime.slice(rebindStart, rebindStop);
assert.match(rebind, /if\(loaded\)scan_imports\(\)/,
  "rebind should refresh the main executable IAT");
assert.match(rebind, /x86_dll_resolve_imports\(m->base,m->size,m->import_rva,m->import_size,&ok,&bad\)/,
  "rebind should revisit loaded DLL dependency imports");

assert.match(runtime, /x86_pe_section_header_for_address/,
  "x86 crash diagnostics must map addresses back to loaded PE sections");
assert.match(runtime, /x86_dll_get_name_byte/,
  "x86 diagnostics must identify the requested filename of a loaded DLL");
assert.match(loader, /describeAddress\("fault-eip"/,
  "x86 faults must report the PE image/DLL section containing the failing EIP");
assert.match(loader, /describeAddress\("control-target"/,
  "indirect control-flow diagnostics must identify the target module and PE section");

assert.match(runtime, /legitimate cross-module transfer/,
  "valid host API and mapped DLL targets must not be reported as bad control transfers");
assert.match(loader, /formatTrace\(ex, 64\)/,
  "crash diagnostics must preserve enough trace history to locate the first bad branch");
assert.match(loader, /dumpPeBytes\("call-chain-.*-callee"/,
  "crash diagnostics must dump bytes at caller/callee addresses when they map to PE images");

assert.match(loader, /trace-section\[/,
  "recent instruction history must report PE section transitions near the failure");

assert.match(runtime, /tls_rva,tls_size,tls_index,tls_block/,
  "native DLL images must preserve TLS directory and per-module storage metadata");
assert.match(runtime, /export_name\("x86_dll_initialize_all"\)/,
  "the runtime must expose native DLL process-attach initialization");
assert.match(runtime, /export_name\("x86_dll_get_init_fail_eip"\)/,
  "DLL initializer faults must identify the instruction address that failed");
assert.match(loader, /x86_dll_initialize_all\(\)/,
  "the browser must initialize mapped DLLs after import rebinding and before game execution");
assert.ok(loader.indexOf("x86_dll_initialize_all()") < loader.indexOf('this.running = true'),
  "native DLL initializers must run before the guest executable begins");

assert.match(runtime, /if\(m->imports_failed\)\s*\{\s*m->init_state=4u;\s*x86_dll_init_skipped_count\+\+;/,
  "native DLL initializers must not run with unresolved imports still pointing at trap addresses");
assert.match(runtime, /export_name\("x86_dll_get_init_skipped_count"\)/,
  "the runtime must report native DLLs skipped because required imports are unresolved");
assert.match(loader, /native DLL imports unresolved:/,
  "the shell must report per-DLL unresolved imports before initialization");

assert.match(runtime, /x86_dll_init_capture_import_for_slot/,
  "native DLL initialization faults must trace unresolved IAT slots back to DLL and function names");
assert.match(runtime, /!x86_dll_cname_equal\(m->requested_name,"steam_api\.dll"\)/,
  "the packed Steam API DLL must still be offered initialization when its imports are partially unresolved");
assert.match(loader, /native DLL initializer trapped on unresolved import:/,
  "the loader must identify the missing import when a native DLL initializer traps");

console.log("API loading contract tests passed");
