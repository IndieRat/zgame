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

## Native API frame: .zapi and .zdll

ZWASM has its own native API vocabulary; it does not require XWASM's .xapi format. The stable frame is zworld.v1 with a fixed i32x5 call shape: API ID, up to four 32-bit arguments, and one 32-bit return value.

A .zapi manifest maps stable API IDs to a .zdll implementation:

    .zapi -> API ID/name/argc -> .zdll -> zdll_call(id, a0, a1, a2, a3)

The browser shell now validates, instantiates, initializes, and registers bundled .zdll modules, then routes .zapi calls into them. .xapi remains accepted by the builder as a compatibility alias and is normalized into the ZWASM .zapi package role.

A minimal .zapi looks like:

    {
      "schema": "zwasm.zapi/1",
      "formatVersion": 1,
      "name": "kernel32",
      "abi": "zworld.v1",
      "frame": "i32x5",
      "dll": "kernel32.zdll",
      "functions": [
        {"id": 1, "name": "GetTickCount", "argc": 0, "export": "zdll_call"}
      ]
    }

Build with native ZWASM terms:

    python tools/zwasm_build.py "C:\\Games\\MyGame" --zapi kernel32.zapi --zdll kernel32.zdll

The shell loads those modules into WebAssembly before guest API dispatch, so the package boundary is now:

    PE guest -> runtime -> .zapi -> .zdll -> WASM/native host frame


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

    boot module -> prepared memory image -> archives/chunks -> virtual instance tree
        -> bridge ABI -> browser host/UI

The bridge ABI is deliberately explicit. The first host calls are:
- KERNEL32 GetTickCount (API 1)
- KERNEL32 Sleep (API 2)
- USER32 GetAsyncKeyState (API 100)
- USER32 GetKeyState (API 101)

Unsupported calls return -1 and are counted/traced instead of being silently faked. This gives the eventual game runtime a concrete import-dispatch boundary that can be expanded one API at a time.

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
- an explicit host bridge ABI with traced unsupported calls;
- initial Kernel32/User32/OpenGL32 bridge IDs and browser dispatch scaffolding;
- browser implementations for basic timing and keyboard state;
- actual WASM instantiation and host callbacks in the browser shell;
- save checkpoints through IndexedDB;
- entry inspector, fullscreen canvas, keyboard/mouse capture, and diagnostics.

Not included yet: a generic PE translator or a complete Win32/OpenGL host ABI. Those belong in the runtime/translator layer rather than the container format.


## Executable x86 guest mode

ZWASM can host the existing XWASM x86 runtime as its executable browser module. Build an x86 package with:

    python tools/zwasm_build.py "C:\\Games\\Isaac"

The builder now uses the vendored x86 runtime by default; --runtime remains available for an explicit runtime. It also accepts --zapi and --zdll inputs. When it finds a PE executable, it copies it to zwasm_guest/guest.pe and generates a safe zwasm_guest/image.bin when one was not supplied.

The browser lifecycle is:

    runtime.wasm
        -> instantiate host imports
        -> x86_alloc(raw PE size)
        -> copy zwasm_guest/guest.pe into linear memory
        -> x86_load_pe()
        -> x86_run() per requestAnimationFrame
        -> browser input / graphics / audio host callbacks

The generated adapter remains useful for testing the container and browser shell, but it is not an x86 CPU. The vendored x86 runtime is now the normal executable guest path.

The browser host currently maps the XWASM runtime graphics primitives to the game canvas, beep audio to Web Audio, and keyboard events to the runtime input queue. Unsupported runtime imports are stubbed and traced so missing coverage is visible instead of causing an opaque WebAssembly link failure.

This follows the same broad separation demonstrated by the supplied browser reference: executable Wasm module, guest image/executable state, virtualized files, and a browser host boundary. Emscripten likewise provides a virtual filesystem, lazy file loading, WebGL integration, and Web Audio/OpenAL integration. 
