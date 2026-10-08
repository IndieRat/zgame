const $ = (s) => document.querySelector(s);
const state = { pkg: null, runtime: null, log: [], frame: 0, keys: new Set(), bridge: { calls: 0, unsupported: 0, lastApi: 0, lastResult: 0 } };

function log(msg) {
  const line = "[" + new Date().toLocaleTimeString() + "] " + msg;
  state.log.push(line);
  if (state.log.length > 500) state.log.shift();
  $("#console").textContent = state.log.join("\n");
  $("#console").scrollTop = $("#console").scrollHeight;
}

function fmtBytes(value) {
  let n = Number(value) || 0, i = 0;
  const units = ["B", "KiB", "MiB", "GiB"];
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + units[i];
}

function extractZdllPayload(bytes) {

    const magic =
        new TextDecoder()
            .decode(bytes.slice(0, 4));

    if (magic !== "ZDLL") {
        return bytes;
    }

    const view =
        new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength
        );

    const manifestSize =
        view.getUint32(8, true);

    const payloadOffset =
        12 + manifestSize;

    const payload =
        bytes.slice(payloadOffset);

    if (
        payload.length < 2 ||
        payload[0] !== 0x4D ||
        payload[1] !== 0x5A
    ) {
        throw new Error(
            "ZDLL payload is not a PE image"
        );
    }

    return payload;
}

function setStatus(text) { $("#status").textContent = text; }

async function readSlice(source, offset, length) {
  if (source instanceof File || source instanceof Blob) {
    return new Uint8Array(await source.slice(offset, offset + length).arrayBuffer());
  }
  const end = offset + length - 1;
  const response = await fetch(source, { headers: { Range: "bytes=" + offset + "-" + end } });
  if (response.status !== 206 && !(offset === 0 && response.ok)) {
    throw new Error("range read failed: HTTP " + response.status);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (offset !== 0 && bytes.length !== length) {
    throw new Error("range read returned " + bytes.length + " bytes; wanted " + length);
  }
  return bytes;
}

class ZGameReader {
  constructor(source) { this.source = source; this.manifest = null; }

  async load() {
    const header = await readSlice(this.source, 0, 64);
    if (header.length !== 64) throw new Error("short ZWASM header");
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    if (new TextDecoder().decode(header.slice(0, 8)) !== "ZWASMG01") {
      throw new Error("bad ZWASM magic");
    }
    const version = view.getUint32(8, true);
    if (version !== 1) throw new Error("unsupported ZWASM version " + version);
    const indexOffset = Number(view.getBigUint64(16, true));
    const indexSize = Number(view.getBigUint64(24, true));
    const payloadOffset = Number(view.getBigUint64(32, true));
    const count = view.getUint32(40, true);
    const indexBytes = await readSlice(this.source, indexOffset, indexSize);
    this.manifest = JSON.parse(new TextDecoder().decode(indexBytes));
    if (!Array.isArray(this.manifest.entries) || this.manifest.entries.length !== count) {
      throw new Error("invalid manifest entry count");
    }
    if (payloadOffset < indexOffset + indexSize) throw new Error("payload overlaps index");
    for (const entry of this.manifest.entries) {
      if (typeof entry.path !== "string" || !entry.path || entry.path.startsWith("/") ||
          entry.path.split("/").includes("..")) {
        throw new Error("unsafe package entry path");
      }
      const offset = Number(entry.offset), size = Number(entry.storedSize);
      if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) ||
          offset < payloadOffset || offset + size > Number.MAX_SAFE_INTEGER) {
        throw new Error("invalid package bounds: " + entry.path);
      }
    }
    this.payloadOffset = payloadOffset;
    return this;
  }

  entry(path) {
    return this.manifest.entries.find((entry) => entry.path === path) || null;
  }

  async readEntry(path) {
    const entry = this.entry(path);
    if (!entry) throw new Error("entry not found: " + path);
    const blob = await readSlice(this.source, Number(entry.offset), Number(entry.storedSize));
    if (entry.compression === "none") return blob;
    if (entry.compression !== "gzip") throw new Error("unsupported compression: " + entry.compression);
    if (!("DecompressionStream" in globalThis)) throw new Error("browser lacks gzip decompression");
    const stream = new Blob([blob]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }
}

function renderEntries() {
  const host = $("#entries");
  const query = ($("#filter").value || "").toLowerCase();
  host.innerHTML = "";
  const entries = (state.pkg ? state.pkg.manifest.entries : []).filter(
    (entry) => !query || entry.path.toLowerCase().includes(query)
  );
  for (const entry of entries) {
    const row = document.createElement("div");
    row.className = "entry";
    const left = document.createElement("div");
    left.className = "entry-path";
    left.textContent = entry.path;
    const right = document.createElement("div");
    right.className = "entry-meta";
    right.textContent = entry.kind + " · " + fmtBytes(entry.size);
    row.append(left, right);
    host.append(row);
  }
}

function drawBootFrame() {
  const canvas = $("#screen");
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#050608";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#9ba8ba";
  ctx.font = "16px monospace";
  ctx.fillText("ZWASM boot runtime active", 24, 32);
  ctx.font = "13px monospace";
  ctx.fillText("frame: " + state.frame, 24, 56);
  if (state.pkg?.manifest?.image) {
    const image = state.pkg.entry(state.pkg.manifest.image);
    ctx.fillText("prepared image: " + fmtBytes(image.size), 24, 80);
  }
}

const XAPI_BUILTINS = {
  "kernel32!gettickcount": () => Math.floor(performance.now()) >>> 0,
  "winmm!timegettime": () => Math.floor(performance.now()) >>> 0,
  "kernel32!sleep": () => 0,
  "user32!getasynckeystate": (rt, s) => (state.keys.has(s[0] | 0) ? 0x8000 : 0),
  "user32!getkeystate": (rt, s) => (state.keys.has(s[0] | 0) ? 0x8000 : 0),
  "kernel32!queryperformancefrequency": (rt, s) => { rt.writeU64(s[0], 1000000); return 1; },
  "kernel32!queryperformancecounter": (rt, s) => { rt.writeU64(s[0], Math.floor(performance.now() * 1000)); return 1; },
};

class ZDLLModule {
  constructor(entry, manifest, instance) {
    this.entry = entry;
    this.manifest = manifest;
    this.instance = instance;
    this.exports = instance.exports;
  }

  call(exportName, id, args) {
    const fn = this.exports[exportName || "zdll_call"];
    if (typeof fn !== "function") throw new Error("zdll " + this.manifest.name + " lacks export " + (exportName || "zdll_call"));
    const a = [id | 0, 0, 0, 0, 0];
    for (let i = 0; i < Math.min(4, args.length); i++) a[i + 1] = args[i] | 0;
    return fn(a[0], a[1], a[2], a[3], a[4]) | 0;
  }
}

async function loadZDLL(reader, entry, hostApi) {
    log(
        "skipping legacy wasm zdll loader: " +
        entry.path
    );

    return null;
}

class GuestRuntime {
  constructor(reader, module) {
    this.reader = reader; this.module = module; this.instance = null; this.memory = null;
    this.running = false; this.inputQueue = []; this.audio = null; this.ctx2d = null; this.imageData = null;
    this.xapiTable = new Map(); this.zapiTable = new Map(); this.zdlls = new Map(); this.xapiUnsupported = new Map(); this.diagShown = false;
    this.unresolved = new Map(); this.pendingDll = "";
  }

  mem() { return new Uint8Array(this.instance.exports.memory.buffer); }

  writeU64(addr, value) {
    const ex = this.instance.exports, a = addr >>> 0;
    const lo = value % 4294967296, hi = Math.floor(value / 4294967296);
    for (let i = 0; i < 4; i++) { ex.x86_guest_write8(a + i, (lo >>> (i * 8)) & 255); ex.x86_guest_write8(a + 4 + i, (hi >>> (i * 8)) & 255); }
  }

  allocCopy(bytes, region) {
    const ex = this.instance.exports, ptr = (region ? ex.x86_alloc_region : ex.x86_alloc)(bytes.length + 1);
    if (!ptr) throw new Error("x86_alloc failed for " + bytes.length + " bytes");
    const m = this.mem(); m.set(bytes, ptr); m[ptr + bytes.length] = 0;
    return ptr;
  }

  buildImports() {
    const canvas = $("#screen"), self = this, imports = { env: {} }, env = imports.env;
    this.ctx2d = canvas.getContext("2d");
    const readString = (p, n) => { const m = self.mem(); if (p < 0 || p >= m.length) return ""; let e = p; while (e < m.length && e - p < n && m[e]) e++; return new TextDecoder().decode(m.slice(p, e)); };
    const ensureAudio = () => { if (!self.audio) self.audio = new AudioContext(); if (self.audio.state === "suspended") self.audio.resume().catch(() => {}); return self.audio; };
    const css = (c) => "#" + ((c >>> 0) & 0xffffff).toString(16).padStart(6, "0");
    const resize = (w, h) => { w = Math.max(1, Math.min(1920, w | 0)); h = Math.max(1, Math.min(1080, h | 0)); canvas.width = w; canvas.height = h; self.imageData = self.ctx2d.createImageData(w, h); };
    resize(640, 360);
    env.z_host_log = (level, ptr, len) => {
      const text = readString(ptr, Math.min(len >>> 0, 4096));
      if (level === 2) { // runtime reports each unresolved import as two lines: the DLL, then the function
        if (/\.dll$/i.test(text)) self.pendingDll = text;
        else { const g = self.unresolved.get(self.pendingDll || "?") || new Set(); g.add(text); self.unresolved.set(self.pendingDll || "?", g); }
        return;
      }
      log("x86[" + level + "]: " + text);
    };
    env.z_host_input_quit = () => { self.inputQueue.push({ quit: true }); };
    env.z_host_input_poll = (ptr, remove) => {
      const ev = self.inputQueue[0]; if (!ev) return 0;
      const m = self.mem(); if (ptr < 0 || ptr + 28 > m.length) return 0;
      const d = new DataView(m.buffer);
      d.setUint32(ptr, 0, true); d.setUint32(ptr + 4, ev.type >>> 0, true); d.setUint32(ptr + 8, ev.code >>> 0, true);
      d.setUint32(ptr + 12, ev.value >>> 0, true); d.setUint32(ptr + 16, (Date.now() / 1) | 0, true);
      d.setInt32(ptr + 20, ev.x | 0, true); d.setInt32(ptr + 24, ev.y | 0, true);
      if (remove) self.inputQueue.shift();
      return 1;
    };
    env.z_host_audio_beep = (f, ms) => { try { const a = ensureAudio(), o = a.createOscillator(), g = a.createGain(); o.frequency.value = Math.max(40, Math.min(12000, f || 440)); g.gain.value = 0.045; o.connect(g).connect(a.destination); o.start(); o.stop(a.currentTime + Math.max(0.01, Math.min(2, (ms || 50) / 1000))); } catch (e) { log("audio: " + e.message); } };
    env.z_host_gfx_create = (w, h) => { resize(w, h); return 1; };
    env.z_host_gfx_clear = (c) => { self.ctx2d.fillStyle = css(c); self.ctx2d.fillRect(0, 0, canvas.width, canvas.height); const d = self.imageData.data, r = (c >>> 16) & 255, g = (c >>> 8) & 255, b = c & 255; for (let i = 0; i < d.length; i += 4) { d[i] = r; d[i + 1] = g; d[i + 2] = b; d[i + 3] = 255; } return 0; };
    env.z_host_gfx_pixel = (x, y, c) => { const im = self.imageData; if (!im) return 0; x |= 0; y |= 0; if (x < 0 || y < 0 || x >= im.width || y >= im.height) return 0; const p = (y * im.width + x) * 4; im.data[p] = (c >>> 16) & 255; im.data[p + 1] = (c >>> 8) & 255; im.data[p + 2] = c & 255; im.data[p + 3] = 255; return 0; };
    env.z_host_gfx_rect = (l, t, r, b, c) => { const im = self.imageData; if (!im) return 0; const x0 = Math.max(0, l | 0), y0 = Math.max(0, t | 0), x1 = Math.min(im.width, r | 0), y1 = Math.min(im.height, b | 0); const R = (c >>> 16) & 255, G = (c >>> 8) & 255, B = c & 255; for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) { const p = (y * im.width + x) * 4; im.data[p] = R; im.data[p + 1] = G; im.data[p + 2] = B; im.data[p + 3] = 255; } return 0; };
    env.z_host_gfx_present = () => { if (self.imageData) self.ctx2d.putImageData(self.imageData, 0, 0); return 0; };
    env.z_host_xapi_call = (id, argc) => self.xapiCall(id >>> 0, argc | 0);
    return imports;
  }

  xapiCall(id, argc) {
    state.bridge.calls++; state.bridge.lastApi = id;
    const ex = this.instance.exports;
    const slots = new Float64Array(ex.memory.buffer, ex.x86_xapi_slots(), 16);
    const zfn = this.zapiTable.get(id >>> 0);
    let result = 0;
    if (zfn) {
      const dll = this.zdlls.get(String(zfn.dll).toLowerCase()) || this.zdlls.get(zfn.dll);
      if (!dll) {
        state.bridge.unsupported++;
        log("zapi missing zdll: " + zfn.dll + " for api " + id);
      } else {
        const args = [];
        for (let i = 0; i < Math.min(argc | 0, zfn.argc, 4); i++) args.push(slots[i] | 0);
        try { result = dll.call(zfn.export, id, args); }
        catch (e) { log("zdll " + zfn.dll + " api " + id + " threw: " + e.message); result = -1; }
      }
    } else {
      const fn = this.xapiTable.get(id);
      const key = fn ? (fn.lib + "!" + fn.name).toLowerCase() : null;
      const handler = key ? XAPI_BUILTINS[key] : null;
      if (handler) {
        try { result = handler(this, slots, fn) | 0; } catch (e) { log("legacy xapi " + key + " threw: " + e.message); result = -1; }
      } else {
        state.bridge.unsupported++;
        const label = key || ("id " + id);
        const n = (this.xapiUnsupported.get(label) || 0) + 1;
        this.xapiUnsupported.set(label, n);
        if (n === 1) log("api unsupported: " + label + " (argc=" + argc + ") -> returning 0");
      }
    }
    state.bridge.lastResult = result;
    return result;
  }

  async loadZApis() {
    for (const entry of ZWASMHost.findZapiEntries(this.reader.manifest)) {
      const doc = JSON.parse(new TextDecoder().decode(await this.reader.readEntry(entry.path)));
      if (doc.schema !== "zwasm.zapi/1" || doc.abi !== "zworld.v1" || doc.frame !== "i32x5") {
        throw new Error("invalid zapi frame: " + entry.path);
      }
      const dllName = String(doc.dll || "");
      if (!dllName) throw new Error("zapi has no dll: " + entry.path);
      for (const fn of doc.functions || []) {
        const id = fn.id >>> 0;
        if (this.zapiTable.has(id)) throw new Error("duplicate zapi id " + id);
        this.zapiTable.set(id, {
          dll: String(fn.dll || dllName),
          export: String(fn.export || "zdll_call"),
          argc: Math.max(0, Math.min(4, fn.argc | 0)),
          name: String(fn.name || ("api_" + id)),
        });
      }
      log("zapi loaded: " + entry.path + " · " + (doc.functions || []).length + " functions");
    }
  }

	async loadNativeZDLLs() {
		const entries = ZWASMHost.findZdllEntries(this.reader.manifest);

		const ex = this.instance.exports;

		this.nativeDllNames = [];

		let registered = 0;

		for (const entry of entries) {
			try {
				const container =
					await this.reader.readEntry(
						entry.path
					);

				const dllBytes =
					extractZdllPayload(
						container
					);

				const name = entry.path
					.split("/")
					.pop()
					.replace(/\.zdll$/i, ".dll");

				log(
					"container bytes " +
					name +
					": " +
					[...container.slice(0, 4)]
						.map(v => v.toString(16))
						.join(" ")
				);

				log(
					"payload bytes " +
					name +
					": " +
					[...dllBytes.slice(0, 4)]
						.map(v => v.toString(16))
						.join(" ")
				);

				const namePtr =
					this.allocCopy(
						new TextEncoder().encode(name)
					);

				const dataPtr =
					this.allocCopy(
						dllBytes,
						true
					);

				const ok =
					ex.x86_dll_register_image(
						namePtr,
						dataPtr,
						dllBytes.length
					);

				if (ok) {
					registered++;
					this.nativeDllNames.push(name);
				}

				log(
					"native zdll registered: " +
					name +
					" · " +
					fmtBytes(dllBytes.length)
				);
			}
			catch (e) {
				log(
					"zdll register failed: " +
					entry.path +
					" : " +
					e.message
				);
			}
		}

		log(
			"native zdlls registered: " +
			registered +
			"/" +
			entries.length
		);
	}
  zapiCallDirect(id, args) {
    const fn = this.zapiTable.get(id >>> 0);
    if (!fn) return -1;
    const dll = this.zdlls.get(fn.dll.toLowerCase()) || this.zdlls.get(fn.dll);
    if (!dll) return -1;
    return dll.call(fn.export, id, args);
  }

  async loadXapiManifests() {
    const ex = this.instance.exports;
    for (const entry of ZWASMHost.findXapiEntries(this.reader.manifest)) {
      if (!/\.xapi\.json$/i.test(entry.path)) { log("xapi: " + entry.path + " is not JSON; binary containers need converting with .xapi.json export"); continue; }
      const doc = JSON.parse(new TextDecoder().decode(await this.reader.readEntry(entry.path)));
      const put = (...parts) => { const bytes = new TextEncoder().encode(parts.join("\0") + "\0"); new Uint8Array(ex.memory.buffer).set(bytes, ex.x86_xapi_scratch()); };
      let ok = 0, bad = 0;
      for (const [alias, target] of Object.entries(doc.aliases || {})) { put(alias, target); ex.x86_xapi_register_alias(); }
      for (const f of doc.functions || []) {
        const args = f.args || [];
        const scratch = ex.x86_xapi_scratch(), head = new TextEncoder().encode(f.lib + "\0" + f.name + "\0");
        const m = new Uint8Array(ex.memory.buffer); m.set(head, scratch); m.set(args, scratch + head.length);
        const r = ex.x86_xapi_register(f.id >>> 0, f.abi | 0, args.length, f.ret | 0) >>> 0;
        if (r === 0xFFFFFFFF) bad++; else ok++;
      }
      log("xapi: " + entry.path + " registered " + ok + " functions" + (bad ? ", " + bad + " rejected" : ""));
    }
    this.xapiTable = ZWASMHost.readXapiTable(ex, ex.memory.buffer);
  }

  async start() {
    const manifest = this.reader.manifest;
    const imports = this.buildImports();
    const stubbed = ZWASMHost.fillMissingImports(WebAssembly, this.module, imports, (k) => log("runtime import stub called: " + k));
    if (stubbed.length) log("host does not implement: " + stubbed.join(", "));
    this.instance = await WebAssembly.instantiate(this.module, imports);
    const ex = this.instance.exports;
    this.memory = ex.memory;
    if (!this.memory) throw new Error("x86 runtime does not export memory");
    ex.zwasm_init();

    const guest = ZWASMHost.findGuestEntry(manifest);
    if (!guest) throw new Error("package has no guest PE (looked for " + ZWASMHost.GUEST_PATHS.join(", ") + "); rebuild with tools/zwasm_build.py --guest <game.exe>");
    log("guest: " + guest.path + " · " + fmtBytes(guest.size));

    const dlls = ZWASMHost.findGuestDlls(manifest);
    for (const dll of dlls) {
      const bytes = await this.reader.readEntry(dll.path);
      const name = dll.path.split("/").pop();
      const namePtr = this.allocCopy(new TextEncoder().encode(name));
      const dataPtr = this.allocCopy(bytes, true);
      const ok = ex.x86_dll_register_image(namePtr, dataPtr, bytes.length) === 1; // 1 = registered, 0 = failed
      log("dll register " + name + " · " + fmtBytes(bytes.length) + (ok ? " ok" : " FAILED last_error=" + ex.x86_dll_get_last_error()));
    }

    const pe = await this.reader.readEntry(guest.path);
    const ptr = this.allocCopy(pe);
    const rc = ex.x86_load_pe(ptr, pe.length);
    this.guestPe = pe;
    this.verifyImage("after PE load");
    log("x86 PE load rc=" + rc + " bytes=" + fmtBytes(pe.length));
    if (rc !== 0) throw new Error("x86_load_pe failed rc=" + rc + " load_error=" + (ex.x86_get_load_error?.() ?? "?"));

    for (const dll of dlls) {
      const name = dll.path.split("/").pop();
      const base = ex.x86_dll_load_registered(this.allocCopy(new TextEncoder().encode(name))) >>> 0;
      log("dll load " + name + " -> " + (base ? "base=0x" + base.toString(16) : "FAILED last_error=" + ex.x86_dll_get_last_error()));
    }
    await this.loadNativeZDLLs();

	for (const name of this.nativeDllNames || []) {

		const ptr = this.allocCopy(
			new TextEncoder().encode(name)
		);

		const base = ex.x86_dll_load_registered(ptr) >>> 0;

		log(
			"zdll load " +
			name +
			" -> " +
			(base
				? "base=0x" + base.toString(16)
				: "FAILED")
		);
	}

	const unresolved = ex.x86_dll_rebind_imports();

	log(
		"zdll rebind: unresolved=" +
		unresolved
	);

	this.reportUnresolved();

	await this.loadZApis();
	await this.loadXapiManifests();

    log("imports: " + ex.x86_get_import_resolved() + "/" + ex.x86_get_import_count() + " resolved, " + ex.x86_get_import_failed() + " failed · xapi functions: " + ex.x86_get_xapi_count());

    this.verifyImage("before run");
    this.running = true; $("#runtimeState").textContent = "RUNNING"; setStatus("Running");
    log("x86 runtime online; image base=0x" + (ex.x86_get_image_base?.() ?? 0).toString(16));
    this.loop();
  }

  verifyImage(label) {
    if (!this.guestPe || !this.instance) return;
    const base = this.instance.exports.x86_get_image_base ? this.instance.exports.x86_get_image_base() : 0x400000;
    for (const line of ZWASMHost.verifyImage(this.instance.exports.memory.buffer, this.guestPe, base)) log("image " + label + ": " + line);
  }

  reportUnresolved() {
    if (!this.unresolved.size) return;
    let total = 0;
    for (const [dll, set] of [...this.unresolved].sort((a, b) => b[1].size - a[1].size)) {
      const fns = [...set];
      total += fns.length;
      log("unresolved " + dll + ": " + fns.length + " (" + fns.slice(0, 8).join(", ") + (fns.length > 8 ? ", ..." : "") + ")");
    }
    log("unresolved total: " + total);
  }

  diagnostics(reason) {
    if (this.diagShown || !this.instance) return;
    this.diagShown = true;
    const ex = this.instance.exports, hex = (v) => "0x" + (v >>> 0).toString(16);
    log("diag: " + reason + " eip=" + hex(ex.x86_get_eip()) + " steps=" + ex.x86_get_steps() + " cpu_error=" + hex(ex.x86_get_cpu_error()) + " halted=" + ex.x86_get_halted());
    let bytes = ""; for (let i = 0; i < 12; i++) bytes += (ex.x86_get_current_byte(i) & 255).toString(16).padStart(2, "0") + " ";
    log("diag: bytes at eip: " + bytes + "| last x87 op=" + hex(ex.x86_get_x87_last_opcode()) + " modrm=" + hex(ex.x86_get_x87_last_modrm()) + " at " + hex(ex.x86_get_x87_last_eip()));
    if (ex.x86_get_esp) log("diag: GPR ESP="+hex(ex.x86_get_esp())+" EBP="+hex(ex.x86_get_ebp?.() ?? 0)+" stack=["+hex(ex.x86_get_stack_region_base?.() ?? 0)+".."+hex(ex.x86_get_stack_region_top?.() ?? 0)+"]");
    if (ex.x86_get_last_stack_fault_esp) log("diag: stack fault kind="+ex.x86_get_last_stack_fault_kind()+" esp="+hex(ex.x86_get_last_stack_fault_esp())+" eip="+hex(ex.x86_get_last_stack_fault_eip()));
    if (ex.x86_get_flow_count) { const n=Math.min(ex.x86_get_flow_count(),16); for(let i=0;i<n;i++) log("diag: flow[-"+i+"] eip="+hex(ex.x86_get_flow_eip(i))+" op="+hex(ex.x86_get_flow_opcode(i))+" esp="+hex(ex.x86_get_flow_esp(i))+" ebp="+hex(ex.x86_get_flow_ebp(i))); }
    log("diag: memory faults=" + ex.x86_get_memory_faults() + " first fault eip=" + hex(ex.x86_get_first_fault_eip()) + " last fault eip=" + hex(ex.x86_get_last_fault_eip()) + " last fault addr=" + hex(ex.x86_get_last_memory_fault_address()) + " size=" + ex.x86_get_last_memory_fault_size() + " kind=" + ex.x86_get_last_memory_fault_kind());
    for (const line of ZWASMHost.formatTrace(ex, 16)) log("diag: " + line);
    for (const line of ZWASMHost.formatApiLog(ex, 40)) log("diag: " + line);
    if (ex.x86_get_shadow_stat) {
      const st = (n) => ex.x86_get_shadow_stat(n);
      log("diag: shadow stack depth=" + st(0) + " calls=" + st(2) + " rets=" + st(3) + " unbalanced rets=" + st(4) + " unmatched rets=" + st(5) + " esp jumps=" + st(6));
      const ev = (kind, label) => {
        if (!(kind < 2 ? st(4) : st(5))) return;
        const f = (n) => ex.x86_get_shadow_event(kind, n);
        log("diag: " + label + " ret@" + hex(f(0)) + " -> " + hex(f(1)) + " esp=" + hex(f(2)) + (kind < 2 ? " expected=" + hex(f(3)) : "") + " callee=" + hex(f(4)) + " callsite=" + hex(f(5)) + " step=" + f(6) + " depth=" + f(7));
      };
      ev(0, "first unbalanced ret"); ev(2, "first unmatched ret"); ev(3, "last unmatched ret");
      for (let n = Math.max(0, st(0) - 12); n < st(0); n++) log("diag: call chain[" + n + "] callee=" + hex(ex.x86_get_shadow_frame(n, 0)) + " from=" + hex(ex.x86_get_shadow_frame(n, 1)));
      for (let k = 0; k < Math.min(st(6), 4); k++) {
        log("diag: ESP jump #" + k + " at eip=" + hex(ex.x86_get_espw_event(k, 0)) + " esp " + hex(ex.x86_get_espw_event(k, 1)) + " -> " + hex(ex.x86_get_espw_event(k, 2)) + " step=" + ex.x86_get_espw_event(k, 4));
        for (let n = 0; n < 24; n++) { const e = ex.x86_get_espw_snap(k, n, 0); if (e) log("diag:   " + hex(e) + " op=" + hex(ex.x86_get_espw_snap(k, n, 1)) + " esp=" + hex(ex.x86_get_espw_snap(k, n, 2)) + " ebp=" + hex(ex.x86_get_espw_snap(k, n, 3))); }
      }
    }
    log("diag: imports " + ex.x86_get_import_resolved() + "/" + ex.x86_get_import_count() + " resolved, " + ex.x86_get_import_failed() + " failed; crt exited=" + ex.x86_crt_get_exited() + " code=" + ex.x86_crt_get_exit_code() + " last xapi id=" + ex.x86_get_last_xapi_id());
    const str = (fnName, i) => { let s = ""; for (let j = 0; j < 255; j++) { const c = ex[fnName](i, j); if (!c) break; s += String.fromCharCode(c); } return s; };
    let shown = 0;
    for (let i = 0, n = ex.x86_get_gdr_count(); i < n && shown < 25; i++) {
      if (ex.x86_get_gdr_target(i) !== 0) continue;
      log("diag: unresolved import " + str("x86_get_gdr_dll_name_byte", i) + "!" + str("x86_get_gdr_func_name_byte", i)); shown++;
    }
    for (const [k, n] of this.xapiUnsupported) log("diag: unsupported xapi " + k + " x" + n);
  }

  loop() {
    if (!this.running || !this.instance) return;
    const ex = this.instance.exports, t0 = performance.now();
    try {
      while (performance.now() - t0 < 12) {
        const rc = ex.x86_run(20000);
        if (rc < 0) { log("x86_run rc=" + rc + " cpu_error=0x" + ex.x86_get_cpu_error().toString(16)); this.running = false; this.diagnostics("cpu fault"); break; }
        if (rc === 1 || ex.x86_get_halted()) { this.running = false; this.diagnostics("guest halted"); break; }
      }
      state.frame++;
    } catch (e) { log("x86 runtime error: " + e.message); this.running = false; this.diagnostics("host exception"); }
    if (this.running) requestAnimationFrame(() => this.loop());
    else { $("#runtimeState").textContent = "STOPPED"; setStatus("Stopped"); }
  }

  input(code, down) {
    this.inputQueue.push({ type: down ? 0x100 : 0x101, code: code >>> 0, value: down ? 1 : 0, x: 0, y: 0 });
    state.bridge.calls++;
  }
  stop() { this.running = false; this.instance = null; state.runtime = null; $("#runtimeState").textContent = "READY"; }
}

class BootRuntime {
  constructor(reader, module) { this.reader = reader; this.module = module; this.instance = null; }
  async start() {
    let instance = null;
    const imports = { env: {
      z_host_log: (ptr, len) => { if (!instance) return; const mem = new Uint8Array(instance.exports.memory.buffer); log("boot: " + new TextDecoder().decode(mem.slice(ptr, ptr + len))); },
      z_host_image_size: () => Number(this.reader.entry(this.reader.manifest.image)?.size || 0),
      z_host_frame: () => { drawBootFrame(); return 0; },
      z_host_input: (code, down) => { log("input " + code + " " + (down ? "down" : "up")); return 0; },
      z_host_api: (api, a0, a1, a2, a3) => { state.bridge.calls++; state.bridge.lastApi = api | 0; let result = -1; switch (api | 0) { case 1: result = Math.floor(performance.now()) >>> 0; break; case 2: result = 0; break; case 10: result = Math.floor(performance.now() * 1000); break; case 11: result = 1000000; break; case 100: case 101: result = state.keys.has(a0 | 0) ? 0x8000 : 0; break; } if (result === -1) { state.bridge.unsupported++; log("bridge unsupported api=" + api + " args=" + [a0, a1, a2, a3].join(",")); } state.bridge.lastResult = result | 0; return result | 0; },
    } };
    const stubbed = ZWASMHost.fillMissingImports(WebAssembly, this.module, imports, (k) => log("boot import stub called: " + k));
    if (stubbed.length) log("boot host does not implement: " + stubbed.join(", "));
    instance = await WebAssembly.instantiate(this.module, imports); this.instance = instance;
    if (typeof instance.exports.zwasm_init !== "function") throw new Error("boot module lacks zwasm_init");
    const rc = instance.exports.zwasm_init(); if (rc !== 0) throw new Error("zwasm_init returned " + rc);
    $("#runtimeState").textContent = "RUNNING"; setStatus("Running"); log("adapter boot instantiated; init rc=" + rc);
    this.loop();
  }
  loop() { if (!this.instance) return; state.frame++; this.instance.exports.zwasm_frame?.(state.frame); requestAnimationFrame(() => this.loop()); }
  input(code, down) { this.instance?.exports.zwasm_input?.(code, down ? 1 : 0); }
  stop() { this.instance = null; state.runtime = null; $("#runtimeState").textContent = "READY"; }
}
async function saveState() {
  if (!state.pkg) return log("nothing loaded");
  const db = await openSaveDB();
  const tx = db.transaction("saves", "readwrite");
  tx.objectStore("saves").put({
    id: state.pkg.manifest.name || "default",
    frame: state.frame,
    time: Date.now()
  });
  await new Promise((resolve, reject) => {
    tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);
  });
  log("save checkpoint stored in IndexedDB");
}

async function loadState() {
  if (!state.pkg) return log("nothing loaded");
  const db = await openSaveDB();
  const tx = db.transaction("saves", "readonly");
  const request = tx.objectStore("saves").get(state.pkg.manifest.name || "default");
  const value = await new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  if (!value) return log("no save checkpoint for this package");
  state.frame = Number(value.frame || 0);
  log("save checkpoint restored at frame " + state.frame);
}

function openSaveDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("zwasm-saves", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("saves", { keyPath: "id" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function loadSource(source, label, size) {
  setStatus("Loading");
  $("#runtimeState").textContent = "LOADING";
  $("#overlay").style.display = "grid";
  log("opening " + label);

  const reader = new ZGameReader(source);
  await reader.load();
  state.pkg = reader;

  const manifest = reader.manifest;
  const entries = manifest.entries;
  const total = entries.reduce((sum, entry) => sum + Number(entry.size || 0), 0);
  const instances = entries.filter((entry) => entry.kind === "instance").length;

  $("#pkgName").textContent = manifest.name || "unnamed";
  $("#pkgEntries").textContent = String(entries.length);
  $("#pkgBoot").textContent = manifest.boot ? "present" : "none";
  $("#pkgImage").textContent = manifest.image ? "present" : "none";
  $("#pkgSize").textContent = size == null ? "HTTP source" : fmtBytes(size);
  $("#gameTitle").textContent = manifest.name || "ZWASM package";
  $("#runtimeState").textContent = "READY";
  setStatus("Ready");
  renderEntries();

  log("loaded " + (manifest.name || "(unnamed)") + " · " + entries.length +
      " entries · " + fmtBytes(total) + " logical");
  log("instance entries: " + instances);

  if (manifest.boot) {
    const boot = reader.entry(manifest.boot);
    log("boot: " + manifest.boot + " · " + fmtBytes(boot.size) + " · " + boot.compression);
  } else {
    log("no browser boot module is embedded");
  }
  if (manifest.image) {
    const image = reader.entry(manifest.image);
    log("image: " + manifest.image + " · " + fmtBytes(image.size) + " · " + image.compression);
  }

  if (!manifest.boot) {
    $("#overlay span").textContent = "Package loaded. No boot module is embedded.";
    return reader;
  }
  const module = await WebAssembly.compile(await reader.readEntry(manifest.boot));
  const kind = ZWASMHost.runtimeKind(WebAssembly.Module.exports(module).map((e) => e.name));
  log("runtime kind: " + kind);
  if (kind === "unknown") throw new Error("boot module exports neither the x86 runtime (x86_load_pe/x86_run) nor the boot adapter (zwasm_init/zwasm_frame)");
  $("#overlay span").textContent = kind === "x86" ? "Package loaded. Starting x86 guest runtime…" : "Package loaded. Starting browser boot runtime…";
  const runtime = kind === "x86" ? new GuestRuntime(reader, module) : new BootRuntime(reader, module);
  state.runtime = runtime;
  await runtime.start();
  if (runtime instanceof BootRuntime) drawBootFrame();
  $("#overlay").style.display = "none";
  return reader;
}

async function inspectBoot() {
  if (!state.pkg?.manifest.boot) return log("no boot module is loaded");
  try {
    const path = state.pkg.manifest.boot;
    const bytes = await state.pkg.readEntry(path);
    const module = await WebAssembly.compile(bytes);
    const imports = WebAssembly.Module.imports(module);
    const exports = WebAssembly.Module.exports(module);
    log("WASM imports: " + imports.length);
    for (const item of imports) log("  import " + item.module + "." + item.name + " [" + item.kind + "]");
    log("WASM exports: " + exports.length);
    for (const item of exports.slice(0, 80)) log("  export " + item.name + " [" + item.kind + "]");
  } catch (error) {
    log("boot inspection failed: " + error.message);
  }
}

async function openFile(file) {
  try {
    await loadSource(file, file.name, file.size);
  } catch (error) {
    setStatus("Error");
    $("#runtimeState").textContent = "ERROR";
    log("ERROR: " + error.message);
  }
}

$("#pick").addEventListener("click", () => $("#file").click());
$("#inspectBoot").addEventListener("click", inspectBoot);
$("#file").addEventListener("change", () => {
  const file = $("#file").files?.[0];
  if (file) openFile(file);
});
$("#dropzone").addEventListener("click", () => $("#file").click());

for (const eventName of ["dragenter", "dragover"]) {
  $("#dropzone").addEventListener(eventName, (event) => {
    event.preventDefault();
    $("#dropzone").classList.add("drag");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  $("#dropzone").addEventListener(eventName, (event) => {
    event.preventDefault();
    $("#dropzone").classList.remove("drag");
  });
}
$("#dropzone").addEventListener("drop", (event) => {
  const file = [...event.dataTransfer.files].find((item) =>
    item.name.toLowerCase().endsWith(".zgame")
  );
  if (file) openFile(file); else log("drop ignored: choose a .zgame file");
});
$("#filter").addEventListener("input", renderEntries);
$("#copyLog").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(state.log.join("\n"));
    log("copied console");
  } catch (error) { log("clipboard unavailable: " + error.message); }
});
$("#fullscreen").addEventListener("click", async () => {
  const target = $("#gameCard");
  if (document.fullscreenElement) await document.exitFullscreen();
  else if (target.requestFullscreen) await target.requestFullscreen();
});
if ($("#save")) $("#save").addEventListener("click", saveState);
if ($("#loadSave")) $("#loadSave").addEventListener("click", loadState);

$("#clear").addEventListener("click", () => {
  state.runtime?.stop();
  state.pkg = null;
  state.runtime = null;
  state.frame = 0;
  state.log = [];
  $("#console").textContent = "";
  $("#entries").innerHTML = "";
  $("#pkgName").textContent = "—";
  $("#pkgEntries").textContent = "—";
  $("#pkgBoot").textContent = "—";
  $("#pkgImage").textContent = "—";
  $("#pkgSize").textContent = "—";
  $("#status").textContent = "Waiting";
  $("#runtimeState").textContent = "IDLE";
  $("#gameTitle").textContent = "No package loaded";
  $("#overlay").style.display = "grid";
  log("cleared");
});

const keyCodes = new Map([
  ["ArrowUp", 38], ["ArrowDown", 40], ["ArrowLeft", 37], ["ArrowRight", 39],
  ["Space", 32], ["Enter", 13], ["Escape", 27]
]);

window.addEventListener("keydown", (event) => {
  if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Space"].includes(event.code)) {
    event.preventDefault();
  }
  state.keys.add(keyCodes.get(event.code) || event.keyCode || 0);
  state.runtime?.input(keyCodes.get(event.code) || event.keyCode || 0, true);
});
window.addEventListener("keyup", (event) => {
  state.keys.delete(keyCodes.get(event.code) || event.keyCode || 0);
  state.runtime?.input(keyCodes.get(event.code) || event.keyCode || 0, false);
});

const heldKeys = new Set();
$("#screen").addEventListener("mousedown", () => $("#screen").focus());
$("#screen").addEventListener("contextmenu", (event) => event.preventDefault());

log("ZWASM shell ready");
