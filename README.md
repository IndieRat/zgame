# ZWASM

ZWASM is a browser-oriented packaging format and loader for large prepared game builds.

The design is intentionally different from the x86-to-WASM emulator approach in XWASM:

- the package contains a browser-ready boot module;
- the executable memory image is a separate package entry;
- the game filesystem is exported as lazy-readable instance entries;
- the browser shell can load a .zgame from a file picker or over HTTP;
- large entries are read on demand instead of requiring an eagerly materialized filesystem.

## Build a .zgame

With LLVM/clang installed:

    python tools/zwasm_build.py "C:\Games\MyGame"

On Windows the builder automatically checks clang and the normal LLVM install path:

    C:\Program Files\LLVM\bin\clang.exe

It creates .zwasm/boot.wasm, then invokes the native packager and writes dist/MyGame.zgame.

For a prepared image:

    python tools/zwasm_build.py "C:\Games\Isaac" --image "C:\Build\isaac.segs.bin"

An existing browser runtime can be supplied instead:

    python tools/zwasm_build.py "C:\Games\Isaac" --boot "C:\Build\boot.wasm" --image "C:\Build\isaac.segs.bin"

The builder does not convert a Windows .exe into a runnable WASM module. A prepared image/runtime must already exist for the actual game execution layer.

## Browser shell

Open web/index.html and choose the .zgame. The shell:

- validates the ZWASM header/index and entry bounds;
- lazily reads boot/image/instance entries;
- instantiates boot.wasm with a concrete host ABI;
- forwards keyboard input and frame callbacks;
- renders a working browser viewport;
- keeps lightweight save checkpoints in IndexedDB;
- reports WASM imports/exports and runtime status;
- works from a local file picker.

## Reference architecture

The shell follows the useful boundary visible in the supplied TBOI web reference:

    boot module -> prepared memory image -> archives/chunks -> virtual instance tree -> lazy/ranged reads -> browser host/UI

The reference exposes separate module, memory-image, archive/chunk, and host stages. ZWASM keeps those concerns separate while making the package and boot contract concrete.

## Status

v0.2 provides:

- native .zgame packaging;
- stable manifests with SHA-256 entry hashes;
- optional auto/forced gzip compression;
- native-code exclusion by default;
- package verification;
- local-file and HTTP loading;
- a generated clang/wasm32 boot adapter;
- actual WASM instantiation and host callbacks in the browser shell;
- save checkpoints through IndexedDB;
- entry inspector, fullscreen canvas, keyboard/mouse capture, and diagnostics.

Not included yet: a generic PE translator or a complete Win32/OpenGL host ABI. Those belong in the runtime/translator layer rather than the container format.
