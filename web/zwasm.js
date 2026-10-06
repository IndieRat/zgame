const $ = (s) => document.querySelector(s);
const state = { pkg: null, log: [] };

function log(msg) {
  const line = "[" + new Date().toLocaleTimeString() + "] " + msg;
  state.log.push(line);
  if (state.log.length > 500) state.log.shift();
  $("#console").textContent = state.log.join("\n");
  $("#console").scrollTop = $("#console").scrollHeight;
}

function fmtBytes(value) {
  let n = Number(value) || 0;
  const units = ["B", "KiB", "MiB", "GiB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return n.toFixed(i ? 1 : 0) + " " + units[i];
}

function setStatus(text) {
  $("#status").textContent = text;
}

async function readSlice(source, offset, length) {
  if (source instanceof File || source instanceof Blob) {
    return new Uint8Array(
      await source.slice(offset, offset + length).arrayBuffer()
    );
  }

  const end = offset + length - 1;
  const response = await fetch(source, {
    headers: { Range: "bytes=" + offset + "-" + end }
  });

  if (response.status !== 206 && !(offset === 0 && response.ok)) {
    throw new Error("range read failed: HTTP " + response.status);
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  if (offset !== 0 && bytes.length !== length) {
    throw new Error(
      "range read returned " + bytes.length + " bytes; wanted " + length
    );
  }
  return bytes;
}

class ZGameReader {
  constructor(source) {
    this.source = source;
    this.manifest = null;
  }

  async load() {
    const header = await readSlice(this.source, 0, 64);
    if (header.length !== 64) {
      throw new Error("short ZWASM header");
    }

    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    const magic = new TextDecoder().decode(header.slice(0, 8));
    if (magic !== "ZWASMG01") {
      throw new Error("bad ZWASM magic: " + magic);
    }

    const version = view.getUint32(8, true);
    if (version !== 1) {
      throw new Error("unsupported ZWASM version " + version);
    }

    const indexOffset = Number(view.getBigUint64(16, true));
    const indexSize = Number(view.getBigUint64(24, true));
    const payloadOffset = Number(view.getBigUint64(32, true));
    const count = view.getUint32(40, true);

    const indexBytes = await readSlice(this.source, indexOffset, indexSize);
    this.manifest = JSON.parse(new TextDecoder().decode(indexBytes));

    if (!Array.isArray(this.manifest.entries)) {
      throw new Error("manifest.entries is not an array");
    }
    if (this.manifest.entries.length !== count) {
      throw new Error("header entry count does not match index");
    }
    if (payloadOffset < indexOffset + indexSize) {
      throw new Error("payload overlaps index");
    }

    for (const entry of this.manifest.entries) {
      if (typeof entry.path !== "string" || !entry.path || entry.path.startsWith("/")) {
        throw new Error("invalid package entry path");
      }
      if (entry.path.split("/").includes("..")) {
        throw new Error("unsafe package entry path: " + entry.path);
      }
      const end = Number(entry.offset) + Number(entry.storedSize);
      if (Number(entry.offset) < payloadOffset || end < Number(entry.offset)) {
        throw new Error("invalid package bounds: " + entry.path);
      }
    }

    this.payloadOffset = payloadOffset;
    return this;
  }

  entry(path) {
    return this.manifest.entries.find(function (entry) {
      return entry.path === path;
    }) || null;
  }

  async readEntry(path) {
    const entry = this.entry(path);
    if (!entry) {
      throw new Error("entry not found: " + path);
    }

    const blob = await readSlice(
      this.source,
      Number(entry.offset),
      Number(entry.storedSize)
    );

    if (entry.compression === "none") {
      return blob;
    }

    if (entry.compression !== "gzip") {
      throw new Error("unsupported compression: " + entry.compression);
    }

    if (!("DecompressionStream" in globalThis)) {
      throw new Error("browser lacks DecompressionStream(gzip)");
    }

    const stream = new Blob([blob]).stream().pipeThrough(
      new DecompressionStream("gzip")
    );
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }
}

function renderEntries() {
  const host = $("#entries");
  const query = ($("#filter").value || "").toLowerCase();
  host.innerHTML = "";

  const entries = (state.pkg ? state.pkg.manifest.entries : []).filter(
    function (entry) {
      return !query || entry.path.toLowerCase().includes(query);
    }
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
  const total = entries.reduce(function (sum, entry) {
    return sum + Number(entry.size || 0);
  }, 0);
  const instances = entries.filter(function (entry) {
    return entry.kind === "instance";
  }).length;

  $("#pkgName").textContent = manifest.name || "unnamed";
  $("#pkgEntries").textContent = String(entries.length);
  $("#pkgBoot").textContent = manifest.boot ? "present" : "none";
  $("#pkgImage").textContent = manifest.image ? "present" : "none";
  $("#pkgSize").textContent = size == null ? "HTTP source" : fmtBytes(size);
  $("#gameTitle").textContent = manifest.name || "ZWASM package";
  $("#runtimeState").textContent = "READY";
  setStatus("Ready");
  renderEntries();

  log(
    "loaded " + (manifest.name || "(unnamed)") +
    " · " + entries.length + " entries · " + fmtBytes(total) + " logical"
  );
  log("instance entries: " + instances);

  if (manifest.boot) {
    const boot = reader.entry(manifest.boot);
    log(
      "boot: " + manifest.boot + " · " +
      fmtBytes(boot.size) + " · " + boot.compression
    );
  } else {
    log("no browser boot module is embedded; package is inspectable but not launchable");
  }

  if (manifest.image) {
    const image = reader.entry(manifest.image);
    log(
      "image: " + manifest.image + " · " +
      fmtBytes(image.size) + " · " + image.compression
    );
  }

  $("#overlay span").textContent = manifest.boot
    ? "Package loaded. Boot adapter/runtime integration is the next layer."
    : "Package loaded. No boot module is embedded.";

  return reader;
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

$("#pick").addEventListener("click", function () {
  $("#file").click();
});

$("#file").addEventListener("change", function () {
  const file = $("#file").files && $("#file").files[0];
  if (file) openFile(file);
});

$("#dropzone").addEventListener("click", function () {
  $("#file").click();
});

for (const eventName of ["dragenter", "dragover"]) {
  $("#dropzone").addEventListener(eventName, function (event) {
    event.preventDefault();
    $("#dropzone").classList.add("drag");
  });
}

for (const eventName of ["dragleave", "drop"]) {
  $("#dropzone").addEventListener(eventName, function (event) {
    event.preventDefault();
    $("#dropzone").classList.remove("drag");
  });
}

$("#dropzone").addEventListener("drop", function (event) {
  const file = [...event.dataTransfer.files].find(function (item) {
    return item.name.toLowerCase().endsWith(".zgame");
  });
  if (file) openFile(file);
  else log("drop ignored: choose a .zgame file");
});

$("#filter").addEventListener("input", renderEntries);

$("#copyLog").addEventListener("click", async function () {
  try {
    await navigator.clipboard.writeText(state.log.join("\n"));
    log("copied console");
  } catch (error) {
    log("clipboard unavailable: " + error.message);
  }
});

$("#fullscreen").addEventListener("click", async function () {
  const target = $("#gameCard");
  if (document.fullscreenElement) {
    await document.exitFullscreen();
  } else if (target.requestFullscreen) {
    await target.requestFullscreen();
  }
});

$("#clear").addEventListener("click", function () {
  state.pkg = null;
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
  log("cleared");
});

const heldKeys = new Set();

window.addEventListener("keydown", function (event) {
  heldKeys.add(event.code);
  if (
    ["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Space"].includes(event.code)
  ) {
    event.preventDefault();
  }
});

window.addEventListener("keyup", function (event) {
  heldKeys.delete(event.code);
});

$("#screen").addEventListener("mousedown", function () {
  $("#screen").focus();
});

$("#screen").addEventListener("contextmenu", function (event) {
  event.preventDefault();
});

log("ZWASM shell ready");
