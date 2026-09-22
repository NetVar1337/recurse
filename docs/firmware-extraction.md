# Firmware format auto-extraction (`recurse_static::firmware`)

`crates/recurse-static/src/firmware.rs` scans an arbitrary blob (a
firmware image, a flash dump, an update package) for every known
embedded-file-format signature at every offset — binwalk's/unblob's core
"what's actually inside this blob" job, the first step before carving
out and recursing into whatever's found.

```rust
use recurse_static::firmware::scan;

let matches = scan(&firmware_image_bytes);
for m in &matches {
    println!("{:#x}: {}", m.offset, m.signature);
}
```

## Signatures are documented file-format specifications, not a curated corpus

`SIGNATURES` is a table of well-known, standardized magic byte sequences
(ELF, PE, gzip, ZIP, XZ, bzip2, 7-Zip, RAR, SquashFS, CramFS, JFFS2,
U-Boot images, device tree blobs, LZMA/LZ4/Zstandard, PNG, JPEG, CPIO,
tar) — public file-format specifications, the same honesty class as
`crate::capa`'s Win32 API names and `crate::driver`'s `CTL_CODE` bit
layout: documented facts about how a format identifies itself, not an
empirical claim about some sample corpus that would need curation to
back up.

`tar`'s `ustar` magic is handled as a special case (it sits at offset
257 within the archive's header block, not at the archive's own start),
matched with its own pass so [`SIGNATURES`]' table-driven scan stays a
simple "does this position start with this magic" check for everything
else.

## Scan, don't (yet) extract

`scan` finds every offset a known signature starts at — the "auto" part
of "auto-extraction": no human manually hex-dumping a blob looking for
magic bytes. It deliberately does **not** carve out, decompress, or
otherwise extract the matched region's payload.

`matches_as_string_refs` folds a match list into the same
`crate::engine::StringRef` shape strings/imports already use elsewhere
in this crate, for a caller that wants firmware-signature hits to show
up alongside other recovered-string-shaped data without inventing a
separate display path.

## Honest scope

- **Signature location only, not extraction.** Actually carving out and
  decompressing a matched region (gzip/XZ/zstd decompression, ZIP/7z/RAR
  archive parsing, SquashFS/CramFS/JFFS2 filesystem extraction) is real,
  substantial, per-format follow-up work — each format needs its own
  correct parser or a real decompression library, not something to bolt
  on as an afterthought.
- **No signature validation beyond the magic bytes themselves** — no
  CRC/checksum verification, no "does the declared length fit within the
  remaining blob" sanity check. A magic byte match at an arbitrary offset
  can be a coincidental false positive (an unrelated data byte sequence
  happening to match); this is the same tradeoff binwalk's own default
  signature scan makes, not a bug specific to this module.
- **Not recursive** — a real "extract, then re-scan the extracted
  content for more embedded formats" pipeline (the actual binwalk/unblob
  workflow) needs the extraction step above first.
- Not wired into `Engine`/`analyze` yet — a standalone, fully-tested
  library capability first, same path every other module in this series
  took.

## Trying it

```bash
cargo test -p recurse-static firmware::
```

8 tests: an ELF header found at a real non-zero offset after padding; a
gzip stream found embedded after padding; multiple distinct signatures
(PE/MZ and a ZIP local file header) found correctly in one blob; a tar
archive found via its real offset-257 `ustar` magic; a blob with no
known signatures yields no matches; empty input doesn't panic; matches
come back in ascending offset order; and `matches_as_string_refs`
carries offset/signature through correctly.
