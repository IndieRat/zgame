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

  function findZapiEntries(manifest) {
    const listed = Array.isArray(manifest.zapi) ? manifest.zapi : [];
    const entries = manifest.entries || [];
    const out = listed.map((p) => entries.find((x) => x.path === p)).filter(Boolean);
    if (out.length) return out;
    return entries.filter((e) => /\.zapi$/i.test(e.path));
  }

	function findZdllEntries(manifest) {
		const listed = Array.isArray(manifest.zdlls)
			? manifest.zdlls
			: [];

		const entries = manifest.entries || [];

		const out = listed
			.map((p) => entries.find((x) => x.path === p))
			.filter(Boolean);

		if (out.length)
			return out;

		return entries.filter((e) =>
			/\.zdll$/i.test(e.path));
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


  /* Last n executed instructions from the runtime's trace ring (oldest first). Works with any
   * build that exports x86_get_trace_*; ESP/EBP columns need x86_get_trace_post_esp/ebp. */
  function formatTrace(ex, n) {
    const hex = (v) => "0x" + (v >>> 0).toString(16);
    const count = ex.x86_get_trace_count ? ex.x86_get_trace_count() : 0;
    const out = [];
    for (let i = Math.max(0, count - n); i < count; i++) {
      const k = ex.x86_get_trace_index(i);
      let id = "";
      if (ex.x86_get_trace_semantic_id_len) {
        const len = ex.x86_get_trace_semantic_id_len(k);
        for (let j = 0; j < len; j++) id += String.fromCharCode(ex.x86_get_trace_semantic_id_char(k, j));
      }
      out.push("trace[" + (i - count) + "] eip=" + hex(ex.x86_get_trace_eip(k)) + " -> " + hex(ex.x86_get_trace_next_eip(k)) +
        " op=" + (ex.x86_get_trace_opcode(k) & 255).toString(16).padStart(2, "0") +
        (ex.x86_get_trace_post_esp ? " esp=" + hex(ex.x86_get_trace_post_esp(k)) + " ebp=" + hex(ex.x86_get_trace_post_ebp(k)) : "") +
        " eax=" + hex(ex.x86_get_trace_post_eax(k)) + " ecx=" + hex(ex.x86_get_trace_post_ecx(k)) + (id ? " " + id : ""));
    }
    return out;
  }


  /* Compare the mapped image in guest memory with the PE file it was loaded from.
   * Returns human-readable lines: one per section (ok / mismatch with first differing RVA). */
  function verifyImage(memBuffer, pe, imageBase) {
    const dv = new DataView(pe.buffer, pe.byteOffset, pe.byteLength);
    const mem = new Uint8Array(memBuffer);
    const out = [];
    const peOff = dv.getUint32(0x3c, true);
    const nsec = dv.getUint16(peOff + 6, true), optsz = dv.getUint16(peOff + 20, true);
    const entryRva = dv.getUint32(peOff + 24 + 16, true);
    let sh = peOff + 24 + optsz;
    for (let i = 0; i < nsec; i++, sh += 40) {
      let name = ""; for (let j = 0; j < 8 && pe[sh + j]; j++) name += String.fromCharCode(pe[sh + j]);
      const va = dv.getUint32(sh + 12, true), raw = dv.getUint32(sh + 20, true), rawsz = dv.getUint32(sh + 16, true);
      let bad = -1, zeroRun = 0;
      for (let k = 0; k < rawsz; k++) {
        if (mem[imageBase + va + k] !== pe[raw + k]) { bad = k; break; }
      }
      const hasEntry = entryRva >= va && entryRva < va + rawsz;
      out.push("section " + name.padEnd(8) + " rva=0x" + va.toString(16) + " raw=" + rawsz + (hasEntry ? " [entry]" : "") +
        (bad < 0 ? " ok" : " MISMATCH at rva 0x" + (va + bad).toString(16) + " (mem=" + mem[imageBase + va + bad].toString(16) + " file=" + pe[raw + bad].toString(16) + ")"));
    }
    return out;
  }


  /* Last n calls into host-implemented imports (oldest first): name, args, return value. */
  function formatApiLog(ex, n) {
    if (!ex.x86_get_apilog_count) return [];
    const hex = (v) => "0x" + (v >>> 0).toString(16);
    const total = Math.min(ex.x86_get_apilog_count(), 128), out = [];
    for (let i = Math.min(n, total) - 1; i >= 0; i--) {
      let name = "";
      for (let j = 0; j < 80; j++) { const c = ex.x86_get_apilog_name_char(i, j); if (!c) break; name += String.fromCharCode(c); }
      const target = ex.x86_get_apilog(i, 0);
      out.push("api[-" + i + "] " + (name || "host#" + hex(target)) + "(" + [4, 5, 6, 7].map((f) => hex(ex.x86_get_apilog(i, f))).join(", ") + ") -> " + hex(ex.x86_get_apilog(i, 2)) +
        "  from " + hex(ex.x86_get_apilog(i, 1)) + " step " + ex.x86_get_apilog(i, 3));
    }
    return out;
  }

  const api = { formatApiLog, verifyImage, formatTrace, GUEST_PATHS, findGuestEntry, findGuestDlls, findZapiEntries, findZdllEntries, findXapiEntries,
                runtimeKind, fillMissingImports, readXapiTable };
  if (typeof module === "object" && module && module.exports) module.exports = api;
  else root.ZWASMHost = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
