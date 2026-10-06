# ZWASM

ZWASM is a browser-oriented packaging format and loader for large prepared game builds.

The design is intentionally different from the x86-to-WASM emulator approach in XWASM:

- the package contains a browser-ready boot module when one exists;
- the executable memory image is a separate package entry;
- the game filesystem is exported as lazy-readable instance entries;
- the browser shell can load a .zgame from a file picker or over HTTP;
- large entries are read on demand instead of requiring an eagerly materialized filesystem.

ZWASM v0.1 is a packaging/transport layer. It does not translate a PE/Windows executable into WASM by itself. A browser-ready boot.wasm and prepared image can be supplied with the packager, or a package can be made as a resource-only export while the boot/runtime work is developed separately.

## Quick start

    python packager/zwasm_pack.py "C:\Games\MyGame" --boot "C:\Build\boot.wasm" --image "C:\Build\image.bin"
    python packager/zwasm_verify.py .\dist\MyGame.zgame

Then open web/index.html and choose the .zgame.

## Package layout

A .zgame file is:

1. a fixed 64-byte header;
2. a UTF-8 JSON index;
3. padding to a page boundary;
4. raw or gzip-compressed file payloads.

The index contains role metadata (boot, image, instance, trail, meta) and byte offsets, so a browser can fetch only the bytes needed for a requested entry.

## Reference architecture

The loader was designed from the supplied TBOI browser-port reference:

    boot module -> prepared image -> virtual instance tree -> lazy/ranged reads -> browser host/UI

The reference uses a segmented image (isaac.segs.bin), a WASM module (boot.wasm), an indexed instance tree, lazy reads, range probing, read-ahead, and a boot trail. ZWASM adopts those ideas at the package boundary without baking Isaac-specific behavior into the file format.

## Status

v0.1 provides:

- native .zgame packaging;
- deterministic manifests and SHA-256 entry hashes;
- optional auto/forced gzip compression;
- native-code exclusion by default;
- package verification;
- local-file and HTTP loading in the HTML shell;
- entry inspector, progress reporting, fullscreen canvas, keyboard/mouse capture, diagnostics, and drag/drop.

Not yet included: a generic PE translator, an Isaac-specific WASM runtime, or a complete host ABI for an arbitrary game boot module.
