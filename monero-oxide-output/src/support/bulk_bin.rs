//! Bulk binary (EPEE / portable_storage) decoding helpers.
//!
//! This module contains the “bulk bin decoding” utilities that were historically embedded
//! in `src/lib.rs` to support wallet2-style binary endpoints like `/getblocks.bin`.
//!
//! Design goals:
//! - Keep business logic out: these are decoding/inspection helpers only.
//! - Be defensive against malformed input (avoid panics, avoid unbounded loops).
//! - Keep APIs crate-internal (`pub(crate)`).
//!
//! Notes:
//! - We intentionally support only the marker shapes we observe from monerod in the wild.
//! - If we encounter new markers, fail fast with a clear error so we can extend safely.
//!
//! This file was created during refactoring to reduce the size of `src/lib.rs`.

use bytes::Buf;

use cuprate_epee_encoding::{EpeeValue, EpeeValueLimits};

/// Maximum number of blocks accepted in one wallet bulk-RPC response.
///
/// WalletCore clamps its configurable request batch to 2,000 blocks, so a larger response cannot
/// be legitimate for any request issued by this crate.
pub(crate) const MAX_EPEE_BLOCKS_PER_RESPONSE: usize = 2_000;

/// Defensive upper bound derived from WalletCore's existing 10 MiB per-block fallback limit and
/// Cuprate's conservative 32-byte minimum wire size for transaction entries.
pub(crate) const MAX_EPEE_TXS_PER_BLOCK: usize = (10 * 1024 * 1024) / 32;

/// A transaction cannot contain more output indices than the maximum number of transaction-sized
/// entries that fit inside WalletCore's existing per-block response envelope.
pub(crate) const MAX_EPEE_OUTPUTS_PER_TX: usize = MAX_EPEE_TXS_PER_BLOCK;

/// Maximum encoded block or transaction blob accepted by the tolerant binary-RPC decoders.
pub(crate) const MAX_EPEE_BLOB_BYTES: usize = 10 * 1024 * 1024;

/// `block_ids` is a packed sequence of 32-byte hashes. WalletCore retains at most 4,096 hashes.
pub(crate) const MAX_EPEE_BLOCK_IDS_BYTES: usize = 4_096 * 32;

/// Daemon status strings are short tokens such as `OK`; leave ample room for useful diagnostics
/// without allowing a malicious daemon to advertise an unbounded allocation.
pub(crate) const MAX_EPEE_STATUS_BYTES: usize = 4 * 1024;

#[inline]
pub(crate) const fn epee_limits(
    min_element_size: usize,
    max_sequence_len: usize,
) -> EpeeValueLimits {
    EpeeValueLimits {
        min_element_size,
        max_sequence_len,
    }
}

#[inline]
pub(crate) fn read_epee_value<T: EpeeValue, B: Buf>(
    r: &mut B,
) -> cuprate_epee_encoding::error::Result<T> {
    cuprate_epee_encoding::read_epee_value(r, EpeeValueLimits::default())
}

#[inline]
pub(crate) fn read_epee_value_limited<T: EpeeValue, B: Buf>(
    r: &mut B,
    limits: EpeeValueLimits,
) -> cuprate_epee_encoding::error::Result<T> {
    cuprate_epee_encoding::read_epee_value(r, limits)
}

pub(crate) fn checked_epee_sequence_len(
    len: u64,
    max: usize,
    _context: &'static str,
) -> cuprate_epee_encoding::error::Result<usize> {
    let len = usize::try_from(len).map_err(|_| {
        cuprate_epee_encoding::error::Error::Format("EPEE sequence length overflow")
    })?;
    if len > max {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "EPEE sequence length exceeds limit",
        ));
    }
    Ok(len)
}

/// One-time debug logging toggle for bulk binary decoding.
///
/// Enable via env var:
/// - `WALLETCORE_BULK_BIN_DEBUG=1`
///
/// This is cached at first successful “true” read to avoid repeated env reads on hot paths.
#[inline]
pub(crate) fn bulk_bin_debug_enabled() -> bool {
    // Intentionally not caching in a static here because this module is extracted from a larger
    // crate where the existing caching static may live elsewhere. If you want caching, wire a
    // shared AtomicBool in the crate root and call into it from here.
    //
    // For now, keep it simple and deterministic.
    std::env::var("WALLETCORE_BULK_BIN_DEBUG")
        .ok()
        .map(|s| s != "0")
        .unwrap_or(false)
}

/// Render a small hex dump of a byte prefix for diagnostics.
///
/// This is intentionally lightweight and does not allocate excessively beyond the output string.
pub(crate) fn hex_dump_prefix(bytes: &[u8], max_len: usize) -> String {
    let dump_len = std::cmp::min(max_len, bytes.len());
    let mut hex = String::new();
    for (i, b) in bytes[..dump_len].iter().enumerate() {
        if i > 0 {
            hex.push(' ');
        }
        // keep format stable for logs
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

/// Non-destructive peek of Monero portable_storage varint from a byte slice.
/// Returns `(value, bytes_used)` if the varint is well-formed and fits in `u64`.
pub(crate) fn peek_epee_varint_u64(bytes: &[u8]) -> Option<(u64, usize)> {
    let start = *bytes.first()?;
    let len = 1usize.checked_shl((start & 0b11) as u32)?;
    if bytes.len() < len {
        return None;
    }

    let mut tmp = &bytes[..len];
    let value = cuprate_epee_encoding::read_varint::<_, u64>(&mut tmp).ok()?;
    Some((value, len))
}

/// Consume a portable_storage varint from a `Buf`.
pub(crate) fn skip_epee_varint_u64<B: Buf>(r: &mut B) -> cuprate_epee_encoding::error::Result<u64> {
    cuprate_epee_encoding::read_varint::<_, u64>(r).map_err(|_| {
        cuprate_epee_encoding::error::Error::Format("skip_epee_varint_u64: invalid varint")
    })
}

/// Read an EPEE object field name (u8 length-prefixed UTF-8 string).
pub(crate) fn read_epee_field_name<B: Buf>(
    r: &mut B,
) -> cuprate_epee_encoding::error::Result<String> {
    if r.remaining() < 1 {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "read_epee_field_name: EOF reading name length",
        ));
    }
    let name_len_usize = r.get_u8() as usize;

    if r.remaining() < name_len_usize {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "read_epee_field_name: EOF reading field name",
        ));
    }

    let bytes = r.copy_to_bytes(name_len_usize);
    let s = std::str::from_utf8(&bytes).map_err(|_| {
        cuprate_epee_encoding::error::Error::Format("read_epee_field_name: invalid UTF-8")
    })?;

    Ok(s.to_string())
}

/// Read a portable_storage length-prefixed byte sequence.
///
/// `ctx` is included in any error messages for easier debugging.
pub(crate) fn read_epee_len_prefixed_bytes<B: Buf>(
    r: &mut B,
    _ctx: &'static str,
    max_len: usize,
) -> cuprate_epee_encoding::error::Result<Vec<u8>> {
    let len = skip_epee_varint_u64(r)?;
    let len_usize = usize::try_from(len).map_err(|_| {
        cuprate_epee_encoding::error::Error::Format("EPEE byte sequence length overflow")
    })?;

    if len_usize > max_len {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "EPEE byte sequence exceeds limit",
        ));
    }

    if r.remaining() < len_usize {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "EPEE byte sequence truncated",
        ));
    }

    Ok(r.copy_to_bytes(len_usize).to_vec())
}

/// Portable_storage "string/blob-like" markers we have observed from monerod in the wild.
///
/// `0x0a` / `0x0b` are classic string/blob markers.
/// We also treat `0xba` / `0xcf` as blob-like based on observed tx blob encodings.
#[inline]
pub(crate) fn is_supported_blob_marker(marker: u8) -> bool {
    matches!(marker, 0x0a | 0x0b | 0xba | 0xcf)
}

// -------------------------
// Generic EPEE value skipping
// -------------------------
//
// `cuprate_epee_encoding` object builders call `add_field(name, reader)` for each field.
// If we encounter an unknown field, we MUST consume its value to keep the reader aligned.
// Otherwise subsequent reads can fail with "Marker does not match expected Marker".
//
// This helper implements a generic skipper for EPEE-encoded values.
//
// It is intentionally conservative and only supports the marker kinds we actually see from monerod.
// If we encounter an unsupported marker, we return a Format error so we can extend support safely.

pub(crate) fn skip_epee_value<B: Buf>(r: &mut B) -> cuprate_epee_encoding::error::Result<()> {
    let mut budget = MAX_EPEE_SKIP_VALUES;
    skip_epee_value_bounded(r, 0, &mut budget)
}

const MAX_EPEE_NESTING: usize = 64;
const MAX_EPEE_SKIP_VALUES: usize = 1_000_000;

fn skip_epee_value_bounded<B: Buf>(
    r: &mut B,
    depth: usize,
    remaining_values: &mut usize,
) -> cuprate_epee_encoding::error::Result<()> {
    if !r.has_remaining() {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "skip_epee_value: unexpected EOF (no marker)",
        ));
    }

    let marker = r.get_u8();
    skip_epee_value_with_budget(r, marker, depth, remaining_values)
}

pub(crate) fn skip_epee_value_with_known_marker<B: Buf>(
    r: &mut B,
    marker: u8,
) -> cuprate_epee_encoding::error::Result<()> {
    let mut budget = MAX_EPEE_SKIP_VALUES;
    skip_epee_value_with_budget(r, marker, 0, &mut budget)
}

fn skip_epee_value_with_budget<B: Buf>(
    r: &mut B,
    marker: u8,
    depth: usize,
    remaining_values: &mut usize,
) -> cuprate_epee_encoding::error::Result<()> {
    if depth >= MAX_EPEE_NESTING || *remaining_values == 0 {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "EPEE nesting/work limit exceeded",
        ));
    }
    *remaining_values -= 1;
    if marker & 0x80 != 0 {
        let element_marker = marker & 0x7f;
        let elements = skip_epee_varint_u64(r)?;
        if elements > *remaining_values as u64 {
            return Err(cuprate_epee_encoding::error::Error::Format(
                "EPEE work limit exceeded",
            ));
        }
        for _ in 0..elements {
            skip_epee_value_with_budget(r, element_marker, depth + 1, remaining_values)?;
        }
        return Ok(());
    }

    let fixed_width = match marker {
        // i64, u64, f64
        0x01 | 0x05 | 0x09 => Some(8),
        // i32, u32
        0x02 | 0x06 => Some(4),
        // i16, u16
        0x03 | 0x07 => Some(2),
        // i8, u8, bool
        0x04 | 0x08 | 0x0b => Some(1),
        _ => None,
    };
    if let Some(width) = fixed_width {
        if r.remaining() < width {
            return Err(cuprate_epee_encoding::error::Error::Format(
                "skip_epee_value_with_known_marker: EOF reading fixed-width value",
            ));
        }
        r.advance(width);
        return Ok(());
    }

    match marker {
        // String/blob: varint length + bytes.
        0x0a => {
            let len = skip_epee_varint_u64(r)?;
            let len_usize = usize::try_from(len).map_err(|_| {
                cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value_with_known_marker: string length overflow",
                )
            })?;
            if r.remaining() < len_usize {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value_with_known_marker: EOF reading string",
                ));
            }
            r.advance(len_usize);
            Ok(())
        }

        // Object: varint field count + repeated (name, marker, value) tuples.
        0x0c => {
            let fields = skip_epee_varint_u64(r)?;
            if fields > *remaining_values as u64 {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "EPEE work limit exceeded",
                ));
            }
            for _ in 0..fields {
                if r.remaining() < 1 {
                    return Err(cuprate_epee_encoding::error::Error::Format(
                        "skip_epee_value_with_known_marker: EOF reading field name length",
                    ));
                }
                let name_len_usize = r.get_u8() as usize;
                if r.remaining() < name_len_usize {
                    return Err(cuprate_epee_encoding::error::Error::Format(
                        "skip_epee_value_with_known_marker: EOF reading field name",
                    ));
                }
                r.advance(name_len_usize);

                skip_epee_value_bounded(r, depth + 1, remaining_values)?;
            }
            Ok(())
        }

        _ => Err(cuprate_epee_encoding::error::Error::Format(
            "Unsupported EPEE marker",
        )),
    }
}

// -------------------------
// Typed-array parser for observed tx blob encoding (marker 0x8c)
// -------------------------

/// Spec-driven typed-array parser for the observed `txs` encoding in wallet2 `/getblocks.bin`.
///
/// Observed:
/// - marker 0x8c
/// - varint count
/// - schema header with element type name (e.g. `"blob"`)
/// - then N elements encoded as length-prefixed byte blobs
///
/// If we encounter an unexpected element type, we skip elements generically to keep cursor aligned.
///
/// Important: this helper focuses on maintaining cursor alignment and extracting bytes.
/// Interpretation of tx blobs is done elsewhere.
pub(crate) fn read_txs_typed_array_0x8c<B: Buf>(
    r: &mut B,
) -> cuprate_epee_encoding::error::Result<Vec<Vec<u8>>> {
    // Diagnostics: dump container start bytes (helps reverse-engineer layouts).
    if bulk_bin_debug_enabled() {
        let chunk0 = r.chunk();
        if !chunk0.is_empty() {
            walletcore_diagnostic!(
                "🧩 txs(0x8c) dump@container_start bytes[0..{}]={}",
                std::cmp::min(64, chunk0.len()),
                hex_dump_prefix(chunk0, 64)
            );
        }
    }

    if !r.has_remaining() {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "read_txs_typed_array_0x8c: EOF (missing marker)",
        ));
    }

    let marker = r.get_u8();
    if marker != 0x8c {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "Unexpected typed-array EPEE marker",
        ));
    }

    // 1) Element count
    let n_u64 = skip_epee_varint_u64(r)?;
    let n = checked_epee_sequence_len(n_u64, MAX_EPEE_TXS_PER_BLOCK, "read_txs_typed_array_0x8c")?;

    // 2) Typed-array schema header:
    // We observed bytes like: 08 04 'blob' ...
    // Interpret this as: <schema_marker:u8> <type_name_len:varint> <type_name_bytes>.
    if !r.has_remaining() {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "read_txs_typed_array_0x8c: EOF (missing schema marker)",
        ));
    }

    let _schema_marker = r.get_u8();
    let type_name_len = skip_epee_varint_u64(r)?;
    let type_name_len_usize = usize::try_from(type_name_len).map_err(|_| {
        cuprate_epee_encoding::error::Error::Format(
            "read_txs_typed_array_0x8c: type name length overflow",
        )
    })?;

    if r.remaining() < type_name_len_usize {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "read_txs_typed_array_0x8c: EOF reading type name",
        ));
    }

    let type_name_bytes = r.copy_to_bytes(type_name_len_usize);
    let elem_type = std::str::from_utf8(&type_name_bytes)
        .unwrap_or("")
        .to_string();

    if bulk_bin_debug_enabled() {
        let chunk1 = r.chunk();
        if !chunk1.is_empty() {
            walletcore_diagnostic!(
                "🧩 txs(0x8c) dump@element_stream_start elem_type={:?} count={} bytes[0..{}]={}",
                elem_type,
                n,
                std::cmp::min(64, chunk1.len()),
                hex_dump_prefix(chunk1, 64)
            );
        }
    }

    // 3) Decode elements
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(n);

    if elem_type == "blob" {
        // Fast path: attempt generic decode of Vec<Vec<u8>> without committing to consumption.
        // Note: this depends on cuprate's decoder behavior. If it fails, we fall back to manual parsing.
        if r.has_remaining() {
            let save = r.chunk();
            let mut tmp: &[u8] = save;
            if let Ok(v) = read_epee_value_limited::<Vec<Vec<u8>>, _>(
                &mut tmp,
                epee_limits(32, MAX_EPEE_TXS_PER_BLOCK),
            ) {
                let consumed = save.len().saturating_sub(tmp.len());
                r.advance(consumed);
                return Ok(v);
            }
        }

        for _ in 0..n {
            if !r.has_remaining() {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "read_txs_typed_array_0x8c(blob): EOF reading element",
                ));
            }

            let chunk = r.chunk();
            if chunk.is_empty() {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "read_txs_typed_array_0x8c(blob): unable to peek element bytes",
                ));
            }

            // Accept both marker-present and markerless blob encodings; be tolerant to avoid desync.

            // Case A: [marker][varint_len][bytes...]
            if chunk.len() >= 2 {
                if let Some((len, used)) = peek_epee_varint_u64(&chunk[1..]) {
                    let rem_after_marker = r.remaining().saturating_sub(1);
                    if (used as u64) <= rem_after_marker as u64
                        && len <= rem_after_marker.saturating_sub(used) as u64
                    {
                        let _ = r.get_u8();
                        let b = read_epee_len_prefixed_bytes(
                            r,
                            "read_txs_typed_array_0x8c(blob,marker_any)",
                            MAX_EPEE_BLOB_BYTES,
                        )?;
                        out.push(b);
                        continue;
                    }
                }
            }

            // Case B: [varint_len][bytes...]
            if let Some((len, used)) = peek_epee_varint_u64(chunk) {
                let rem = r.remaining();

                if (used as u64) <= rem as u64 && len <= rem.saturating_sub(used) as u64 {
                    let b = read_epee_len_prefixed_bytes(
                        r,
                        "read_txs_typed_array_0x8c(blob,markerless)",
                        MAX_EPEE_BLOB_BYTES,
                    )?;
                    out.push(b);
                    continue;
                }

                // Tolerant path: if declared len is larger than remaining, consume what remains.
                if (used as u64) <= rem as u64 && len > rem.saturating_sub(used) as u64 {
                    r.advance(used);
                    let rem_now = r.remaining();
                    let mut b = Vec::with_capacity(rem_now);
                    b.extend_from_slice(r.copy_to_bytes(rem_now).as_ref());
                    out.push(b);
                    continue;
                }
            }

            // Tolerant fallback: consume marker if present, then treat the remaining bytes as one payload.
            if chunk.len() > 1 {
                let _ = r.get_u8();
            }
            let remaining = r.remaining();
            let b = if remaining > 0 {
                let mut v = Vec::with_capacity(remaining);
                v.extend_from_slice(r.copy_to_bytes(remaining).as_ref());
                v
            } else {
                Vec::new()
            };
            out.push(b);
        }
    } else {
        // Unknown element type: keep cursor aligned by skipping each element generically.
        for _ in 0..n {
            if !r.has_remaining() {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "read_txs_typed_array_0x8c: EOF skipping element",
                ));
            }

            let chunk = r.chunk();
            if chunk.is_empty() {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "read_txs_typed_array_0x8c: unable to peek element marker",
                ));
            }

            let m = chunk[0];
            let _ = r.get_u8();
            skip_epee_value_with_known_marker(r, m)?;
            out.push(Vec::new());
        }
    }

    Ok(out)
}

/// Try to decode a `BlockCompleteEntry` object from a blob payload.
///
/// Some daemons appear to encode `blocks` as a typed array whose elements are *blobs*, where each blob
/// is itself a portable_storage object payload for `block_complete_entry`.
///
/// Returns:
/// - `Ok(Some(entry))` if the blob payload decodes as a `BlockCompleteEntry`
/// - `Ok(None)` if it does not look like a valid entry (so caller can treat payload as raw bytes)
/// - `Err(e)` only for hard format errors we want to surface
pub(crate) fn try_decode_block_complete_entry_from_blob_payload(
    payload: &[u8],
) -> cuprate_epee_encoding::error::Result<Option<crate::support::bulk_models::BlockCompleteEntry>> {
    if payload.is_empty() {
        return Ok(None);
    }

    // Attempt to decode as an object payload:
    // [field_count varint] then repeated [field_name][field_value]
    let mut r: &[u8] = payload;

    let fields = match skip_epee_varint_u64(&mut r) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    // Defensive: reject obviously insane field counts (avoid huge loops on garbage data).
    if fields > 1000 {
        return Ok(None);
    }

    let mut builder = crate::support::bulk_models::BlockCompleteEntryBuilder::default();

    for _ in 0..fields {
        let name = match read_epee_field_name(&mut r) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        match <crate::support::bulk_models::BlockCompleteEntryBuilder as cuprate_epee_encoding::EpeeObjectBuilder<
            crate::support::bulk_models::BlockCompleteEntry,
        >>::add_field(&mut builder, &name, &mut r)
        {
            Ok(true) => {}
            Ok(false) => {
                // Unknown field: we must still skip its value. The builder didn't consume it,
                // so consume it here by reading the marker and skipping the value.
                if !r.has_remaining() {
                    return Ok(None);
                }
                let marker = r.get_u8();
                skip_epee_value_with_known_marker(&mut r, marker)?;
            }
            Err(_) => return Ok(None),
        }
    }

    match <crate::support::bulk_models::BlockCompleteEntryBuilder as cuprate_epee_encoding::EpeeObjectBuilder<
        crate::support::bulk_models::BlockCompleteEntry,
    >>::finish(builder)
    {
        Ok(entry) => Ok(Some(entry)),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn deep_unknown_objects_and_oversized_work_are_rejected() {
        // Same 400 KB shape that previously aborted the process with stack overflow.
        let mut nested = Vec::new();
        for _ in 0..100_000 {
            nested.extend_from_slice(&[0x0c, 0x04, 1, b'x']);
        }
        nested.extend_from_slice(&[0x08, 0]);
        assert!(super::skip_epee_value(&mut nested.as_slice()).is_err());
        let mut oversized_array = vec![0x8c];
        cuprate_epee_encoding::write_varint(super::MAX_EPEE_SKIP_VALUES + 1, &mut oversized_array)
            .unwrap();
        assert!(super::skip_epee_value(&mut oversized_array.as_slice()).is_err());
        let mut shallow = Vec::new();
        for _ in 0..32 {
            shallow.extend_from_slice(&[0x0c, 0x04, 1, b'x']);
        }
        shallow.extend_from_slice(&[0x08, 0]);
        assert!(super::skip_epee_value(&mut shallow.as_slice()).is_ok());
    }

    use super::{
        checked_epee_sequence_len, read_epee_len_prefixed_bytes, read_txs_typed_array_0x8c,
        skip_epee_value, MAX_EPEE_BLOB_BYTES, MAX_EPEE_TXS_PER_BLOCK,
    };

    fn encoded_varint(value: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        cuprate_epee_encoding::write_varint(value, &mut bytes).expect("test varint should encode");
        bytes
    }

    #[test]
    fn skips_fixed_width_scalars_using_portable_storage_markers() {
        let mut u64_value: &[u8] = &[0x05, 0, 0, 0, 0, 0, 0, 0, 0];
        skip_epee_value(&mut u64_value).expect("u64 value should be skipped");
        assert!(u64_value.is_empty());

        let mut bool_value: &[u8] = &[0x0b, 1];
        skip_epee_value(&mut bool_value).expect("bool value should be skipped");
        assert!(bool_value.is_empty());
    }

    #[test]
    fn skips_objects_and_typed_object_sequences() {
        // A one-field object containing `block_weight` as a u64. Portable-storage
        // small varints are stored as value << 2, so one field/element is 0x04.
        let object = [
            0x0c, 0x04, 0x0c, b'b', b'l', b'o', b'c', b'k', b'_', b'w', b'e', b'i', b'g', b'h',
            b't', 0x05, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut object_value: &[u8] = &object;
        skip_epee_value(&mut object_value).expect("object should be skipped");
        assert!(object_value.is_empty());

        let mut sequence = Vec::with_capacity(object.len() + 1);
        sequence.push(0x8c); // typed sequence of objects
        sequence.push(0x04); // one element
        sequence.extend_from_slice(&object[1..]); // object payload omits its marker
        let mut sequence_value: &[u8] = &sequence;
        skip_epee_value(&mut sequence_value).expect("object sequence should be skipped");
        assert!(sequence_value.is_empty());
    }

    #[test]
    fn rejects_sequence_lengths_above_wallet_rpc_envelope() {
        let err = checked_epee_sequence_len(
            (MAX_EPEE_TXS_PER_BLOCK + 1) as u64,
            MAX_EPEE_TXS_PER_BLOCK,
            "test sequence",
        )
        .expect_err("oversized sequence should fail");
        assert!(err.to_string().contains("exceeds limit"));
    }

    #[test]
    fn rejects_oversized_length_prefixed_blob_before_reading_payload() {
        let encoded = encoded_varint(MAX_EPEE_BLOB_BYTES + 1);
        let mut reader = encoded.as_slice();
        let err = read_epee_len_prefixed_bytes(&mut reader, "test blob", MAX_EPEE_BLOB_BYTES)
            .expect_err("oversized blob should fail");
        assert!(err.to_string().contains("exceeds limit"));
    }

    #[test]
    fn rejects_oversized_typed_transaction_sequence_before_allocation() {
        let mut encoded = vec![0x8c];
        encoded.extend_from_slice(&encoded_varint(MAX_EPEE_TXS_PER_BLOCK + 1));
        let mut reader = encoded.as_slice();
        let err = read_txs_typed_array_0x8c(&mut reader)
            .expect_err("oversized transaction sequence should fail");
        assert!(err.to_string().contains("exceeds limit"));
    }
}
