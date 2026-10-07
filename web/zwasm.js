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

class GuestRuntime {
  constructor(reader) {
    this.reader=reader; this.instance=null; this.memory=null; this.running=false;
    this.inputQueue=[]; this.audio=null; this.ctx2d=null; this.imageData=null;
  }

  async start() {
    const manifest=this.reader.manifest;
    const bytes=await this.reader.readEntry(manifest.boot);
    const module=await WebAssembly.compile(bytes);
    const imports={env:{}};
    let instance=null;
    const canvas=$("#screen");
    this.ctx2d=canvas.getContext("2d");
    const refreshMemory=()=>this.memory=(instance?.exports?.memory)||this.memory;
    const memView=()=>new Uint8Array(refreshMemory()?.buffer||new ArrayBuffer(0));
    const readString=(p,n=4096)=>{const m=memView();if(p<0||p>=m.length)return "";let e=p;while(e<m.length&&e-p<n&&m[e])e++;return new TextDecoder().decode(m.slice(p,e));};
    const ensureAudio=()=>{if(!this.audio)this.audio=new AudioContext(); if(this.audio.state==="suspended")this.audio.resume().catch(()=>{});return this.audio;};
    const present=()=>{if(this.ctx2d&&this.imageData)this.ctx2d.putImageData(this.imageData,0,0);};
    const resizeSurface=(w,h)=>{w=Math.max(1,Math.min(1920,w|0));h=Math.max(1,Math.min(1080,h|0));canvas.width=w;canvas.height=h;this.imageData=this.ctx2d?.createImageData(w,h)||null;};
    resizeSurface(640,360);

    imports.env.z_host_log=(level,ptr,len)=>log("x86["+level+"]: "+readString(ptr,Math.min(len>>>0,4096)));
    imports.env.z_host_input_quit=()=>{this.inputQueue.push({quit:true});};
    imports.env.z_host_input_poll=(ptr,remove)=>{const ev=this.inputQueue[0];if(!ev)return 0;const m=memView();if(ptr<0||ptr+28>m.length)return 0;
      const d=new DataView(m.buffer);d.setUint32(ptr,0,true);d.setUint32(ptr+4,ev.type>>>0,true);d.setUint32(ptr+8,ev.code>>>0,true);d.setUint32(ptr+12,ev.value>>>0,true);d.setUint32(ptr+16,Date.now()/1|0,true);d.setInt32(ptr+20,ev.x|0,true);d.setInt32(ptr+24,ev.y|0,true);
      if(remove)this.inputQueue.shift(); return 1;};
    imports.env.z_host_audio_beep=(frequency,duration)=>{try{const a=ensureAudio(),o=a.createOscillator(),g=a.createGain();o.frequency.value=Math.max(40,Math.min(12000,frequency||440));g.gain.value=.045;o.connect(g).connect(a.destination);o.start();o.stop(a.currentTime+Math.max(.01,Math.min(2,(duration||50)/1000)));}catch(e){log("audio: "+e.message);}};
    imports.env.z_host_gfx_create=(w,h)=>{resizeSurface(w,h);return 1;};
    imports.env.z_host_gfx_clear=(color)=>{if(!this.ctx2d)return 0;const c=color>>>0;this.ctx2d.save();this.ctx2d.fillStyle="#"+(c&0xffffff).toString(16).padStart(6,"0");this.ctx2d.fillRect(0,0,canvas.width,canvas.height);this.ctx2d.restore();return 0;};
    imports.env.z_host_gfx_pixel=(x,y,color)=>{if(!this.imageData)return 0;x|=0;y|=0;if(x<0||y<0||x>=this.imageData.width||y>=this.imageData.height)return 0;const c=color>>>0,p=(y*this.imageData.width+x)*4;this.imageData.data[p]=(c>>>16)&255;this.imageData.data[p+1]=(c>>>8)&255;this.imageData.data[p+2]=c&255;this.imageData.data[p+3]=255;return 0;};
    imports.env.z_host_gfx_rect=(l,t,r,b,color)=>{if(!this.ctx2d)return 0;const c=color>>>0;this.ctx2d.fillStyle="#"+(c&0xffffff).toString(16).padStart(6,"0");this.ctx2d.fillRect(l|0,t|0,Math.max(0,(r-l)|0),Math.max(0,(b-t)|0));return 0;};
    imports.env.z_host_gfx_present=()=>{present();return 0;};
    imports.env.z_host_xapi_call=(id,argc)=>{state.bridge.calls++;state.bridge.lastApi=id|0;state.bridge.lastResult=0;return 0;};

    const moduleImports=WebAssembly.Module.imports(module);
    for(const item of moduleImports){
      if(item.kind==="function" && imports[item.module]?.[item.name]===undefined){
        (imports[item.module]??={})[item.name]=(...args)=>{log("runtime import stub: "+item.module+"."+item.name);return 0;};
      } else if(item.kind==="memory" && imports[item.module]?.[item.name]===undefined){
        imports[item.module]??={};
        imports[item.module][item.name]=new WebAssembly.Memory({initial:1024,maximum:4096});
      } else if(item.kind==="table" && imports[item.module]?.[item.name]===undefined){
        imports[item.module]??={};
        imports[item.module][item.name]=new WebAssembly.Table({initial:0,element:"funcref"});
      }
    }
    for (const item of moduleImports) {
      const value = imports[item.module]?.[item.name];
      if (item.kind === "function" && typeof value !== "function") {
        throw new Error("missing callable WASM import: " + item.module + "." + item.name);
      }
    }
    const result=await WebAssembly.instantiate(module,imports);instance=result;
    this.instance=instance;refreshMemory();
    if(!this.memory)throw new Error("x86 runtime does not export/import memory");
    if(typeof instance.exports.zwasm_init==="function")instance.exports.zwasm_init();

    const guestPath=manifest.guest||"zwasm_guest/guest.pe";
    let guest=this.reader.entry(guestPath);
    if(!guest){guest=this.reader.manifest.entries.find(e=>e.path.endsWith("/guest.pe")||e.path.endsWith(".guest.pe"));}
    if(!guest)throw new Error("package has no raw PE guest; rebuild with zwasm_build.py so zwasm_guest/guest.pe is embedded");
    const pe=await this.reader.readEntry(guest.path);
    if(typeof instance.exports.x86_alloc!=="function"||typeof instance.exports.x86_load_pe!=="function"){
      throw new Error("runtime lacks x86_alloc/x86_load_pe; package was not built with the ZWASM x86 runtime");
    }
    const ptr=instance.exports.x86_alloc(pe.length);
    if(!ptr)throw new Error("x86_alloc failed for "+pe.length+" bytes");
    new Uint8Array(this.memory.buffer).set(pe,ptr);
    const rc=instance.exports.x86_load_pe(ptr,pe.length);
    log("x86 PE load rc="+rc+" bytes="+fmtBytes(pe.length));
    if(rc!==0)throw new Error("x86_load_pe failed rc="+rc+" load_error="+(instance.exports.x86_get_load_error?.()??"?"));
    this.running=true;$("#runtimeState").textContent="RUNNING";setStatus("Running");
    log("x86 runtime online; guest entry=0x"+(instance.exports.x86_get_image_base?.()??0).toString(16));
    this.loop();
  }

  loop(){
    if(!this.running||!this.instance)return;
    try{
      const run=this.instance.exports.x86_run;
      if(typeof run==="function"){const rc=run(50000); if(rc<0){log("x86_run rc="+rc+" cpu_error=0x"+(this.instance.exports.x86_get_cpu_error?.()??0).toString(16));this.running=false;}}
      state.frame++;
      if(typeof this.instance.exports.x86_get_loaded==="function"&&this.instance.exports.x86_get_loaded()===0)this.running=false;
    }catch(e){log("x86 runtime error: "+e.message);this.running=false;}
    if(this.running)requestAnimationFrame(()=>this.loop());
  }

  input(code,down){
    this.inputQueue.push({type:down?0x100:0x101,code:code>>>0,value:down?1:0,x:0,y:0});
    if(this.instance?.exports?.x86_get_message_count) state.bridge.calls++;
  }
  stop(){this.running=false;this.instance=null;state.runtime=null;$("#runtimeState").textContent="READY";}
}

class BootRuntime {
  constructor(reader){this.reader=reader;this.instance=null;}
  async start(){
    const bytes=await this.reader.readEntry(this.reader.manifest.boot);let instance=null;
    const imports={env:{
      z_host_log:(ptr,len)=>{if(!instance)return;const mem=new Uint8Array(instance.exports.memory.buffer);log("boot: "+new TextDecoder().decode(mem.slice(ptr,ptr+len)));},
      z_host_image_size:()=>Number(this.reader.entry(this.reader.manifest.image)?.size||0),
      z_host_frame:(frame)=>{drawBootFrame();return 0;},
      z_host_input:(code,down)=>{log("input "+code+" "+(down?"down":"up"));return 0;},
      z_host_api:(api,a0,a1,a2,a3)=>{state.bridge.calls++;state.bridge.lastApi=api|0;let result=-1;switch(api|0){case 1:result=Math.floor(performance.now())>>>0;break;case 2:result=0;break;case 10:result=Math.floor(performance.now()*1000);break;case 11:result=1000000;break;case 100:case 101:result=state.keys.has(a0|0)?0x8000:0;break;}if(result===-1){state.bridge.unsupported++;log("bridge unsupported api="+api+" args="+[a0,a1,a2,a3].join(","));}state.bridge.lastResult=result|0;return result|0;}
    }};
    const result=await WebAssembly.instantiate(bytes,imports);instance=result.instance;this.instance=instance;
    if(typeof instance.exports.zwasm_init!=="function")throw new Error("boot module lacks zwasm_init");
    const rc=instance.exports.zwasm_init();if(rc!==0)throw new Error("zwasm_init returned "+rc);
    $("#runtimeState").textContent="RUNNING";setStatus("Running");log("adapter boot instantiated; init rc="+rc);
    this.loop();
  }
  loop(){if(!this.instance)return;state.frame++;this.instance.exports.zwasm_frame?.(state.frame);requestAnimationFrame(()=>this.loop());}
  input(code,down){this.instance?.exports.zwasm_input?.(code,down?1:0);}
  stop(){this.instance=null;state.runtime=null;$("#runtimeState").textContent="READY";}
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
  manifest.guest = manifest.guest || "zwasm_guest/guest.pe";
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

  $("#overlay span").textContent = manifest.boot
    ? (reader.entry("zwasm_guest/guest.pe") ? "Package loaded. Starting x86 guest runtime…" : "Package loaded. Starting browser boot runtime…")
    : "Package loaded. No boot module is embedded.";

  if (manifest.boot) {
    const runtime = reader.entry("zwasm_guest/guest.pe") ? new GuestRuntime(reader) : new BootRuntime(reader);
    state.runtime = runtime;
    await runtime.start();
    if (runtime instanceof BootRuntime) drawBootFrame();
    $("#overlay").style.display = "none";
  }
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
