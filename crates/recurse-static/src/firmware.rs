//! Firmware format auto-extraction: scan an arbitrary blob (a firmware
//! image, a flash dump, an update package) for every known
//! embedded-file-format signature at every offset — binwalk's/unblob's
//! core "what's actually inside this blob" job, the first step before
//! carving out and recursing into whatever's found.
//!
//! # Signatures are documented file-format specifications, not a
//! curated corpus
//!
//! [`SIGNATURES`] is a table of well-known, standardized magic byte
//! sequences (ELF, PE, gzip, ZIP, XZ, bzip2, 7z, tar, SquashFS, JFFS2,
//! U-Boot images, device tree blobs, PNG, JPEG, …) — public file-format
//! specifications, the same honesty class as `crate::capa`'s Win32 API
//! names and `crate::driver`'s `CTL_CODE` bit layout: documented facts
//! about how a format identifies itself, not an empirical claim about
//! some sample corpus that would need curation to back up.
//!
//! # Scan, don't (yet) extract
//!
//! [`scan`] finds every offset a known signature starts at — the
//! "auto" part of "auto-extraction": no human manually hex-dumping a
//! blob looking for magic bytes. It deliberately does **not** carve out,
//! decompress, or otherwise extract the matched region's payload; see
//! honest scope below for exactly why and what that would take.

use crate::engine::StringRef;

/// One known embedded-file-format signature.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    pub name: &'static str,
    /// Magic bytes, matched starting at the signature's own offset zero
    /// (a format whose magic is not at its own byte 0, like `tar`'s
    /// `ustar` at offset 257, is handled specially in [`scan`] rather
    /// than through this table — see [`scan`]'s doc).
    pub magic: &'static [u8],
}

/// Well-known embedded-file-format magic bytes. Public, standardized
/// file-format specifications (see module doc) — not exhaustive (there
/// is no such thing for "every format ever embedded in firmware"), but
/// real and genuinely useful for the formats firmware images actually
/// contain most often.
pub const SIGNATURES: &[Signature] = &[
    Signature {
        name: "ELF",
        magic: b"\x7FELF",
    },
    Signature {
        name: "PE/MZ",
        magic: b"MZ",
    },
    Signature {
        name: "gzip",
        magic: b"\x1F\x8B",
    },
    Signature {
        name: "ZIP (local file header)",
        magic: b"PK\x03\x04",
    },
    Signature {
        name: "ZIP (empty archive)",
        magic: b"PK\x05\x06",
    },
    Signature {
        name: "ZIP (spanned archive)",
        magic: b"PK\x07\x08",
    },
    Signature {
        name: "XZ",
        magic: b"\xFD7zXZ\x00",
    },
    Signature {
        name: "bzip2",
        magic: b"BZh",
    },
    Signature {
        name: "7-Zip",
        magic: b"7z\xBC\xAF\x27\x1C",
    },
    Signature {
        name: "RAR (v1.5+)",
        magic: b"Rar!\x1A\x07\x00",
    },
    Signature {
        name: "RAR (v5.0+)",
        magic: b"Rar!\x1A\x07\x01\x00",
    },
    Signature {
        name: "SquashFS (LE)",
        magic: b"hsqs",
    },
    Signature {
        name: "SquashFS (BE)",
        magic: b"sqsh",
    },
    Signature {
        name: "CramFS",
        magic: b"\x45\x3D\xCD\x28",
    },
    Signature {
        name: "JFFS2 (LE)",
        magic: b"\x85\x19",
    },
    Signature {
        name: "JFFS2 (BE)",
        magic: b"\x19\x85",
    },
    Signature {
        name: "U-Boot uImage",
        magic: b"\x27\x05\x19\x56",
    },
    Signature {
        name: "Device Tree Blob",
        magic: b"\xD0\x0D\xFE\xED",
    },
    Signature {
        name: "LZMA (alone format)",
        magic: b"\x5D\x00\x00",
    },
    Signature {
        name: "LZ4 (frame)",
        magic: b"\x04\x22\x4D\x18",
    },
    Signature {
        name: "Zstandard",
        magic: b"\x28\xB5\x2F\xFD",
    },
    Signature {
        name: "PNG",
        magic: b"\x89PNG\r\n\x1A\n",
    },
    Signature {
        name: "JPEG",
        magic: b"\xFF\xD8\xFF",
    },
    Signature {
        name: "CPIO (ASCII, new)",
        magic: b"070701",
    },
    Signature {
        name: "CPIO (ASCII, CRC)",
        magic: b"070702",
    },
    Signature {
        name: "CPIO (binary, old)",
        magic: b"\xC7\x71",
    },
];

/// A tar archive's `ustar` magic sits at offset 257 within the header
/// block, not at offset 0 — handled as a special case in [`scan`] since
/// [`Signature`]'s table assumes offset-zero matching.
const TAR_USTAR_MAGIC: &[u8] = b"ustar";
const TAR_USTAR_OFFSET: usize = 257;

/// One match: a signature found starting at `offset`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub offset: usize,
    pub signature: &'static str,
}

/// Scan `data` for every occurrence of every [`SIGNATURES`] entry (plus
/// the `tar` special case), at every offset — the same "brute-force
/// every position" approach binwalk's own default signature scan uses,
/// since an embedded file's start is not otherwise knowable in an
/// arbitrary blob. Matches are returned in ascending offset order,
/// overlapping matches included (a `gzip` stream immediately followed by
/// a `PNG` inside it, e.g., is two real, separate, valid matches, not a
/// conflict to resolve here).
#[must_use]
pub fn scan(data: &[u8]) -> Vec<Match> {
    let mut matches = Vec::new();
    for offset in 0..data.len() {
        for sig in SIGNATURES {
            if data[offset..].starts_with(sig.magic) {
                matches.push(Match {
                    offset,
                    signature: sig.name,
                });
            }
        }
    }
    // The tar case needs the archive's start offset, not the magic's own
    // offset partway into the header -- handled as its own pass so the
    // loop above stays a straightforward "does this position start with
    // this magic" check for every table-driven signature.
    if data.len() > TAR_USTAR_OFFSET + TAR_USTAR_MAGIC.len() {
        for start in 0..=(data.len() - TAR_USTAR_OFFSET - TAR_USTAR_MAGIC.len()) {
            if data[start + TAR_USTAR_OFFSET..].starts_with(TAR_USTAR_MAGIC) {
                matches.push(Match {
                    offset: start,
                    signature: "tar (ustar)",
                });
            }
        }
    }
    matches.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.signature.cmp(b.signature))
    });
    matches
}

/// Build a `crate::engine::StringRef`-shaped view of every match (offset
/// as `addr`, a synthesized description as `string`) — a convenience for
/// a caller that wants to fold firmware-signature hits into the same
/// list shape strings/imports already use elsewhere in this crate,
/// rather than inventing a new display path.
#[must_use]
pub fn matches_as_string_refs(matches: &[Match]) -> Vec<StringRef> {
    matches
        .iter()
        .map(|m| StringRef {
            addr: m.offset as u64,
            string: format!("{} signature", m.signature),
            kind: Some("firmware".to_string()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn finds_an_elf_header_at_a_nonzero_offset() {
        let mut data = vec![0u8; 16];
        data.extend_from_slice(b"\x7FELF\x02\x01\x01\x00");
        let matches = scan(&data);
        assert!(
            matches
                .iter()
                .any(|m| m.offset == 16 && m.signature == "ELF"),
            "{matches:?}"
        );
    }

    #[test]
    fn finds_a_gzip_stream_embedded_after_padding() {
        let mut data = vec![0xAAu8; 100];
        data.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]); // real gzip magic + a plausible flag/mtime start
        let matches = scan(&data);
        assert!(
            matches
                .iter()
                .any(|m| m.offset == 100 && m.signature == "gzip"),
            "{matches:?}"
        );
    }

    #[test]
    fn finds_multiple_distinct_signatures_in_one_blob() {
        let mut data = Vec::new();
        data.extend_from_slice(b"MZ\x90\x00"); // PE/MZ at 0
        data.extend_from_slice(&[0u8; 50]);
        data.extend_from_slice(b"PK\x03\x04"); // ZIP local file header at 54
        let matches = scan(&data);
        assert!(
            matches
                .iter()
                .any(|m| m.offset == 0 && m.signature == "PE/MZ"),
            "{matches:?}"
        );
        assert!(
            matches
                .iter()
                .any(|m| m.offset == 54 && m.signature == "ZIP (local file header)"),
            "{matches:?}"
        );
    }

    #[test]
    fn finds_a_tar_archive_by_its_offset_257_ustar_magic() {
        let mut data = vec![0u8; 257];
        data.extend_from_slice(b"ustar\x0000");
        let matches = scan(&data);
        assert!(
            matches
                .iter()
                .any(|m| m.offset == 0 && m.signature == "tar (ustar)"),
            "{matches:?}"
        );
    }

    #[test]
    fn a_blob_with_no_known_signatures_yields_no_matches() {
        let data = vec![0x41u8; 64]; // all 'A', matches nothing
        assert!(scan(&data).is_empty());
    }

    #[test]
    fn empty_input_does_not_panic() {
        assert!(scan(&[]).is_empty());
    }

    #[test]
    fn matches_are_returned_in_ascending_offset_order() {
        let mut data = Vec::new();
        data.extend_from_slice(b"PK\x03\x04"); // ZIP at 0
        data.extend_from_slice(&[0u8; 20]);
        data.extend_from_slice(b"\x7FELF"); // ELF at 24
        let matches = scan(&data);
        let offsets: Vec<usize> = matches.iter().map(|m| m.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn matches_as_string_refs_carries_offset_and_signature_through() {
        let matches = vec![Match {
            offset: 0x100,
            signature: "gzip",
        }];
        let refs = matches_as_string_refs(&matches);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].addr, 0x100);
        assert!(refs[0].string.contains("gzip"));
        assert_eq!(refs[0].kind.as_deref(), Some("firmware"));
    }
}
