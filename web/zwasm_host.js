/* ZWASM host helpers: pure logic (no DOM) so the shell and the tests share it. */
(function (root) {
  "use strict";

  const GUEST_PATHS = ["zwasm_guest/guest.pe", "instance/zwasm_guest/guest.pe"];

  /* Packages built before the manifest recorded "guest" store the PE as an
   * instance entry ("instance/zwasm_guest/guest.pe"); newer ones as "zwasm_guest/guest.pe". */
  function findGuestEntry(manifest) {
    const entries = manifest.entries || [];
    const byPath = (p) => entries.find((e) => e.path === p) || null;
    for (const p of [manifest.guest, ...GUEST_PATHS]) {
      if (p && byPath(p)) return byPath(p);
    }
    return entries.find((e) => /(^|\/)guest\.pe$/i.test(e.path)) || null;
  }

  function findGuestDlls(manifest) {
    const entries = manifest.entries || [];
    const listed = Array.isArray(manifest.guestDlls) ? manifest.guestDlls : [];
    const out = [];
    for (const p of listed) {
      const e = entries.find((x) => x.path === p);
      if (e) out.push(e);
    }
    if (out.length) return out;
    return entries.filter((e) =>
      /(^|\/)zwasm_guest\/dlls\/[^/]+\.dll$/i.test(e.path));
  }

  function findXapiEntries(manifest) {
    const listed = Array.isArray(manifest.xapi) ? manifest.xapi : [];
    const entries = manifest.entries || [];
    const out = listed.map((p) => entries.find((x) => x.path === p)).filter(Boolean);
    return out.length ? out : entries.filter((e) => /\.xapi(\.json)?$/i.test(e.path));
  }

  /* Decide what a boot module is from what it exports, never from which
   * package entries happen to exist. */
  function runtimeKind(exportNames) {
    const names = new Set(exportNames);
    if (names.has("x86_load_pe") && names.has("x86_run")) return "x86";
    if (names.has("zwasm_init") && (names.has("zwasm_frame") || names.has("zwasm_input"))) return "boot";
    return "unknown";
  }

  /* Give every import the module declares a value. Known imports are kept;
   * anything else becomes a counted, logged-once stub instead of failing
   * WebAssembly.instantiate with "function import requires a callable". */
  function fillMissingImports(WA, module, imports, onStub) {
    const stubbed = [];
    for (const item of WA.Module.imports(module)) {
      const ns = (imports[item.module] ??= {});
      if (ns[item.name] !== undefined) continue;
      if (item.kind === "function") {
        const key = item.module + "." + item.name;
        let warned = false;
        const stub = () => {
          if (!warned) { warned = true; if (onStub) onStub(key); }
          stub.calls++;
          return 0;
        };
        stub.calls = 0;
        ns[item.name] = stub;
        stubbed.push(key);
      } else if (item.kind === "memory") {
        ns[item.name] = new WA.Memory({ initial: 1024, maximum: 4096 });
      } else if (item.kind === "table") {
        ns[item.name] = new WA.Table({ initial: 0, element: "funcref" });
      } else if (item.kind === "global") {
        ns[item.name] = new WA.Global({ value: "i32", mutable: false }, 0);
      }
    }
    return stubbed;
  }

  function cstring(bytes, start) {
    let end = start;
    while (end < bytes.length && bytes[end]) end++;
    let s = "";
    for (let i = start; i < end; i++) s += String.fromCharCode(bytes[i]);
    return { text: s, next: end + 1 };
  }

  /* id -> {lib,name,nargs,ret,abi} from the runtime's registered xapi table. */
  function readXapiTable(ex, memBuffer) {
    const table = new Map();
    const count = ex.x86_get_xapi_count ? ex.x86_get_xapi_count() : 0;
    for (let i = 0; i < count; i++) {
      const sig = ex.x86_xapi_describe(i) >>> 0;
      if (sig === 0xFFFFFFFF) continue;
      const scratch = ex.x86_xapi_scratch();
      const bytes = new Uint8Array(memBuffer, scratch, 512);
      const lib = cstring(bytes, 0);
      const name = cstring(bytes, lib.next);
      table.set(ex.x86_get_xapi_id(i) >>> 0, {
        lib: lib.text, name: name.text,
        nargs: sig & 0xFF, ret: (sig >>> 8) & 0xFF, abi: (sig >>> 16) & 0xFF,
      });
    }
    return table;
  }

  const api = { GUEST_PATHS, findGuestEntry, findGuestDlls, findXapiEntries,
                runtimeKind, fillMissingImports, readXapiTable };
  if (typeof module === "object" && module && module.exports) module.exports = api;
  else root.ZWASMHost = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
