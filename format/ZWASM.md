# ZWASM Package Format v0.1

## Header

The first 64 bytes use little-endian fields:

    offset  size  field
    0       8     magic = "ZWASMG01"
    8       4     version = 1
    12      4     flags
    16      8     index_offset
    24      8     index_size
    32      8     payload_offset
    40      4     entry_count
    44      20    reserved

The current packer always puts the JSON index at offset 64 and aligns the first payload to 4096 bytes.

## Index

The index is UTF-8 JSON:

    {
      "schema": "zwasm.package/1",
      "formatVersion": 1,
      "name": "Example",
      "createdUtc": "2026-10-06T00:00:00Z",
      "boot": "boot.wasm",
      "image": "image.bin",
      "trail": "boot-trail.json",
      "entries": [
        {
          "path": "boot.wasm",
          "kind": "boot",
          "offset": 4096,
          "size": 123,
          "storedSize": 123,
          "compression": "none",
          "sha256": "...",
          "mode": 420
        }
      ]
    }

offset is the absolute byte offset in the .zgame file.

## Entry kinds

- boot: browser-ready WASM boot module;
- image: prepared memory image;
- instance: exported game filesystem object;
- trail: historical/ranked read windows used for prefetching;
- meta: auxiliary metadata.

The format does not require a boot or image. This lets the packager export a resource-only build while a runtime is developed separately.

## Compression

v0.1 supports:

- none;
- gzip.

Gzip applies to a whole entry. Browsers can use DecompressionStream("gzip") for lazy entry reads. Large archive-like files are kept uncompressed by the auto policy unless --gzip always is selected, because whole-entry compression prevents byte-range reads inside that entry.

Future versions can add chunked compressed streams without changing the top-level container contract.

## Security and path rules

Package paths are slash-separated relative paths. The packager rejects absolute paths and parent traversal. The browser treats the package as untrusted data and never writes package paths to the user's real filesystem.

A .zgame file can contain JavaScript only as an inert data entry in v0.1; the shell does not automatically execute packaged JavaScript.
