//! Wallet2-style bulk binary (EPEE / portable_storage) request/response models.
//!
//! This module hosts the structs + `cuprate_epee_encoding` builders for monerod binary endpoints:
//! - `/get_blocks.bin` (range-based: start_height/count/prune)  + response
//! - `/get_blocks_by_height.bin` (heights/prune)               + response
//! - `COMMAND_RPC_GET_BLOCKS_FAST` (wallet2-style fast blocks) + response
//!
//! These types were extracted from the historical monolithic `src/lib.rs` to keep file sizes
//! manageable and isolate the schema/decoding concerns.
//!
//! Notes:
//! - These models are crate-internal (`pub(crate)`).
//! - Decoding helpers used for debug / unknown-field skipping live in `support::bulk_bin`.
//! - `BlockCompleteEntry` depends on `support::bulk_bin` utilities to keep cursor alignment when
//!   daemons add unknown fields.
//!
//! Important:
//! - Some fields (notably `block_ids` in `GetBlocksFastBinRequest`) must match Monero C++
//!   serialization (`KV_SERIALIZE_CONTAINER_POD_AS_BLOB`) i.e. a packed blob rather than an array.

use bytes::{Buf, BufMut};
use cuprate_epee_encoding::{write_field, EpeeObject};

use crate::support::bulk_bin::{
    bulk_bin_debug_enabled, checked_epee_sequence_len, epee_limits, hex_dump_prefix,
    is_supported_blob_marker, read_epee_field_name, read_epee_len_prefixed_bytes, read_epee_value,
    read_epee_value_limited, read_txs_typed_array_0x8c, skip_epee_value, skip_epee_varint_u64,
    try_decode_block_complete_entry_from_blob_payload, MAX_EPEE_BLOB_BYTES,
    MAX_EPEE_BLOCKS_PER_RESPONSE, MAX_EPEE_BLOCK_IDS_BYTES, MAX_EPEE_OUTPUTS_PER_TX,
    MAX_EPEE_STATUS_BYTES, MAX_EPEE_TXS_PER_BLOCK,
};

/// Wallet2-style `COMMAND_RPC_GET_BLOCKS_FAST` (`/get_blocks.bin`) request model.
///
/// This endpoint is what `wallet2`/Feather use for fast wallet sync: it returns both:
/// - `blocks` (block blobs + pruned tx blobs)
/// - `output_indices` (per-transaction output indices), eliminating the need for `/get_o_indexes.bin`
///
/// We implement only the subset we need for scanning.
///
/// NOTE: Monerod supports both `/get_blocks.bin` and `/getblocks.bin`.
/// This crate may call one or the other depending on how the rest of the transport is wired.
/// The request *body schema* is what distinguishes this request from range-based `get_blocks.bin`.
#[derive(Clone, Debug)]
pub(crate) struct GetBlocksFastBinRequest {
    /// `COMMAND_RPC_GET_BLOCKS_FAST::request_t::requested_info`
    pub(crate) requested_info: u8,

    /// IMPORTANT: In Monero C++ this is serialized with `KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)`.
    /// That means it's encoded as a single blob of bytes (32 * N) rather than a normal EPEE array.
    /// We represent it as a packed blob to match daemon expectations and avoid HTTP 400.
    pub(crate) block_ids: Vec<u8>,

    pub(crate) start_height: u64,
    pub(crate) prune: bool,
    pub(crate) no_miner_tx: bool,
    pub(crate) pool_info_since: u64,
    pub(crate) max_block_count: u64,
}

#[derive(Default)]
pub(crate) struct GetBlocksFastBinRequestBuilder {
    requested_info: Option<u8>,
    block_ids: Option<Vec<u8>>,
    start_height: Option<u64>,
    prune: Option<bool>,
    no_miner_tx: Option<bool>,
    pool_info_since: Option<u64>,
    max_block_count: Option<u64>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksFastBinRequest>
    for GetBlocksFastBinRequestBuilder
{
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "requested_info" => {
                self.requested_info = Some(read_epee_value(r)?);
            }
            "block_ids" => {
                // Packed POD blob (32 * N bytes)
                self.block_ids = Some(read_epee_value_limited(
                    r,
                    epee_limits(0, MAX_EPEE_BLOCK_IDS_BYTES),
                )?);
            }
            "start_height" => {
                self.start_height = Some(read_epee_value(r)?);
            }
            "prune" => {
                self.prune = Some(read_epee_value(r)?);
            }
            "no_miner_tx" => {
                self.no_miner_tx = Some(read_epee_value(r)?);
            }
            "pool_info_since" => {
                self.pool_info_since = Some(read_epee_value(r)?);
            }
            "max_block_count" => {
                self.max_block_count = Some(read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksFastBinRequest> {
        Ok(GetBlocksFastBinRequest {
            requested_info: self.requested_info.unwrap_or(0),
            block_ids: self.block_ids.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field block_ids missing")
            })?,
            start_height: self.start_height.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field start_height missing")
            })?,
            prune: self.prune.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field prune missing")
            })?,
            no_miner_tx: self.no_miner_tx.unwrap_or(false),
            pool_info_since: self.pool_info_since.unwrap_or(0),
            max_block_count: self.max_block_count.unwrap_or(0),
        })
    }
}

impl EpeeObject for GetBlocksFastBinRequest {
    type Builder = GetBlocksFastBinRequestBuilder;

    fn number_of_fields(&self) -> u64 {
        7
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.requested_info, "requested_info", w)?;
        // Packed POD blob (32 * N bytes), matching KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)
        write_field(self.block_ids, "block_ids", w)?;
        write_field(self.start_height, "start_height", w)?;
        write_field(self.prune, "prune", w)?;
        write_field(self.no_miner_tx, "no_miner_tx", w)?;
        write_field(self.pool_info_since, "pool_info_since", w)?;
        write_field(self.max_block_count, "max_block_count", w)?;
        Ok(())
    }
}

/// Per-tx output indices (for `get_o_indexes` avoidance).
#[derive(Clone, Debug)]
pub(crate) struct TxOutputIndices {
    pub(crate) indices: Vec<u64>,
}

#[derive(Default)]
pub(crate) struct TxOutputIndicesBuilder {
    indices: Option<Vec<u64>>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<TxOutputIndices> for TxOutputIndicesBuilder {
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "indices" => {
                self.indices = Some(read_epee_value_limited(
                    r,
                    epee_limits(8, MAX_EPEE_OUTPUTS_PER_TX),
                )?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<TxOutputIndices> {
        Ok(TxOutputIndices {
            indices: self.indices.unwrap_or_default(),
        })
    }
}

impl EpeeObject for TxOutputIndices {
    type Builder = TxOutputIndicesBuilder;

    fn number_of_fields(&self) -> u64 {
        1
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.indices, "indices", w)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BlockOutputIndices {
    pub(crate) indices: Vec<TxOutputIndices>,
}

#[derive(Default)]
pub(crate) struct BlockOutputIndicesBuilder {
    indices: Option<Vec<TxOutputIndices>>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<BlockOutputIndices> for BlockOutputIndicesBuilder {
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "indices" => {
                self.indices = Some(read_epee_value_limited(
                    r,
                    epee_limits(0, MAX_EPEE_TXS_PER_BLOCK),
                )?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<BlockOutputIndices> {
        Ok(BlockOutputIndices {
            indices: self.indices.unwrap_or_default(),
        })
    }
}

impl EpeeObject for BlockOutputIndices {
    type Builder = BlockOutputIndicesBuilder;

    fn number_of_fields(&self) -> u64 {
        1
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.indices, "indices", w)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GetBlocksFastBinResponse {
    pub(crate) blocks: Vec<BlockCompleteEntry>,
    pub(crate) start_height: u64,
    pub(crate) current_height: u64,
    pub(crate) output_indices: Vec<BlockOutputIndices>,
    pub(crate) daemon_time: Option<u64>,
    pub(crate) pool_info_extent: Option<u8>,
    pub(crate) status: Option<String>,
    pub(crate) untrusted: Option<bool>,
}

#[derive(Default)]
pub(crate) struct GetBlocksFastBinResponseBuilder {
    blocks: Option<Vec<BlockCompleteEntry>>,
    start_height: Option<u64>,
    current_height: Option<u64>,
    output_indices: Option<Vec<BlockOutputIndices>>,
    daemon_time: Option<u64>,
    pool_info_extent: Option<u8>,
    status: Option<String>,
    untrusted: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksFastBinResponse>
    for GetBlocksFastBinResponseBuilder
{
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        // Targeted schema debugging for `/getblocks.bin` response decoding.
        if bulk_bin_debug_enabled() {
            walletcore_diagnostic!("🧩 getblocks.bin response: decoding field={:?}", name);
        }

        match name {
            "blocks" => {
                // Prefer generic schema-driven decode.
                if r.has_remaining() {
                    let save = r.chunk();
                    let mut tmp: &[u8] = save;
                    match read_epee_value_limited::<Vec<BlockCompleteEntry>, _>(
                        &mut tmp,
                        epee_limits(32, MAX_EPEE_BLOCKS_PER_RESPONSE),
                    ) {
                        Ok(v) => {
                            let consumed = save.len().saturating_sub(tmp.len());
                            r.advance(consumed);
                            if bulk_bin_debug_enabled() {
                                walletcore_diagnostic!(
                                    "🧩 getblocks.bin blocks: generic decode ok (count={})",
                                    v.len()
                                );
                            }
                            self.blocks = Some(v);
                            return Ok(true);
                        }
                        Err(e) => {
                            if bulk_bin_debug_enabled() {
                                walletcore_diagnostic!(
                                    "🧩 getblocks.bin blocks: generic decode failed; falling back to manual parser: {}",
                                    e
                                );
                            }
                        }
                    }
                }

                // ---- Manual instrumentation / legacy fallback path ----
                if !r.has_remaining() {
                    return Err(cuprate_epee_encoding::error::Error::Format(
                        "getblocks.bin decode failed in field 'blocks': EOF (missing container marker)",
                    ));
                }

                let container_marker = r.get_u8();

                // Determine element count and (optional) typed-array element type name.
                let (n, typed_elem_type): (u64, Option<String>) = match container_marker {
                    // Plain array: [0x0d][elem_marker][len][elements...]
                    0x0d => {
                        if !r.has_remaining() {
                            return Err(cuprate_epee_encoding::error::Error::Format(
                                "getblocks.bin decode failed in field 'blocks': EOF (missing element marker)",
                            ));
                        }
                        let elem_marker = r.get_u8();
                        if elem_marker != 0x0c {
                            return Err(cuprate_epee_encoding::error::Error::Format("getblocks.bin decode failed in field 'blocks': unexpected element marker (expected object marker 0x0c)"));
                        }

                        let n = skip_epee_varint_u64(r).map_err(|_| { cuprate_epee_encoding::error::Error::Format("getblocks.bin decode failed in field 'blocks': failed to read array length") })?;

                        (n, None)
                    }

                    // Sequence of objects: [0x8c][len][object][object]...
                    0x8c => {
                        let n = skip_epee_varint_u64(r).map_err(|_| { cuprate_epee_encoding::error::Error::Format("getblocks.bin decode failed in field 'blocks': failed to read typed-array length") })?;

                        (n, None)
                    }

                    _ => {
                        return Err(cuprate_epee_encoding::error::Error::Format("getblocks.bin decode failed in field 'blocks': unexpected container marker (expected 0x0d or 0x8c)"));
                    }
                };

                if bulk_bin_debug_enabled() {
                    if typed_elem_type.is_none() {
                        walletcore_diagnostic!(
                            "🧩 getblocks.bin blocks container: object_seq marker=0x{container_marker:02x} len={}",
                            n
                        );
                    }
                }

                // Decode elements (manual best-effort).
                let n = checked_epee_sequence_len(
                    n,
                    MAX_EPEE_BLOCKS_PER_RESPONSE,
                    "getblocks.bin blocks",
                )?;
                let savepoint: &[u8] = r.chunk();

                // --- Attempt 1: decode as `BlockCompleteEntry` objects ---
                let mut reader_obj: &[u8] = savepoint;
                let mut obj_out: Vec<BlockCompleteEntry> = Vec::with_capacity(n);
                let mut object_decode_ok = true;

                for i in 0..n {
                    if bulk_bin_debug_enabled() {
                        walletcore_diagnostic!(
                            "🧩 getblocks.bin blocks[{}]: object-decode start (remaining={})",
                            i,
                            reader_obj.len()
                        );
                        if !reader_obj.is_empty() {
                            let hex = hex_dump_prefix(reader_obj, 32);
                            walletcore_diagnostic!(
                                "🧩 getblocks.bin blocks[{}]: object-decode peek bytes[0..{}]={}",
                                i,
                                std::cmp::min(32, reader_obj.len()),
                                hex
                            );
                        }
                    }

                    let fields = match skip_epee_varint_u64(&mut reader_obj) {
                        Ok(v) => v,
                        Err(e) => {
                            object_decode_ok = false;
                            if bulk_bin_debug_enabled() {
                                walletcore_diagnostic!(
                                    "🧩 getblocks.bin blocks[{}]: object-decode failed reading field_count: {}",
                                    i, e
                                );
                            }
                            break;
                        }
                    };

                    let mut builder = BlockCompleteEntryBuilder::default();
                    for _ in 0..fields {
                        let name = match read_epee_field_name(&mut reader_obj) {
                            Ok(v) => v,
                            Err(e) => {
                                object_decode_ok = false;
                                if bulk_bin_debug_enabled() {
                                    walletcore_diagnostic!(
                                        "🧩 getblocks.bin blocks[{}]: object-decode failed reading field name: {}",
                                        i, e
                                    );
                                }
                                break;
                            }
                        };

                        match builder.add_field(&name, &mut reader_obj) {
                            Ok(true) => {}
                            Ok(false) => {
                                if let Err(e) = skip_epee_value(&mut reader_obj) {
                                    object_decode_ok = false;
                                    if bulk_bin_debug_enabled() {
                                        walletcore_diagnostic!(
                                            "🧩 getblocks.bin blocks[{}]: object-decode skip unknown field {:?} failed: {}",
                                            i, name, e
                                        );
                                    }
                                    break;
                                }
                            }
                            Err(e) => {
                                object_decode_ok = false;
                                if bulk_bin_debug_enabled() {
                                    walletcore_diagnostic!(
                                        "🧩 getblocks.bin blocks[{}]: object-decode add_field({:?}) failed: {}",
                                        i, name, e
                                    );
                                }
                                break;
                            }
                        }
                    }

                    if !object_decode_ok {
                        break;
                    }

                    let entry = match builder.finish() {
                        Ok(v) => v,
                        Err(e) => {
                            object_decode_ok = false;
                            if bulk_bin_debug_enabled() {
                                walletcore_diagnostic!(
                                    "🧩 getblocks.bin blocks[{}]: object-decode finish failed: {}",
                                    i,
                                    e
                                );
                            }
                            break;
                        }
                    };

                    if bulk_bin_debug_enabled() {
                        walletcore_diagnostic!(
                            "🧩 getblocks.bin blocks[{}]: object-decode ok (block_bytes={} tx_blobs={} pruned={})",
                            i,
                            entry.block.len(),
                            entry.txs.len(),
                            entry.pruned
                        );
                    }

                    obj_out.push(entry);
                }

                if object_decode_ok && obj_out.len() == n {
                    let consumed = savepoint.len().saturating_sub(reader_obj.len());
                    r.advance(consumed);
                    self.blocks = Some(obj_out);
                    return Ok(true);
                }

                if bulk_bin_debug_enabled() {
                    walletcore_diagnostic!(
                        "🧩 getblocks.bin blocks: object-decode failed; attempting blob fallback from savepoint (remaining={})",
                        savepoint.len()
                    );
                }

                // --- Attempt 2: decode as length-prefixed blob bytes ---
                let mut reader_blob: &[u8] = savepoint;
                let mut out: Vec<BlockCompleteEntry> = Vec::with_capacity(n);

                for _ in 0..n {
                    if reader_blob.is_empty() {
                        return Err(cuprate_epee_encoding::error::Error::Format("getblocks.bin decode failed in field 'blocks': block entry EOF (missing element bytes)"));
                    }

                    if !reader_blob.is_empty() && is_supported_blob_marker(reader_blob[0]) {
                        reader_blob = &reader_blob[1..];
                    }

                    let blob_payload = read_epee_len_prefixed_bytes(
                        &mut reader_blob,
                        "getblocks.bin blocks(blob_payload/shared_marker)",
                        MAX_EPEE_BLOB_BYTES,
                    )?;

                    if let Some(entry) =
                        try_decode_block_complete_entry_from_blob_payload(&blob_payload)?
                    {
                        out.push(entry);
                    } else {
                        out.push(BlockCompleteEntry {
                            block: blob_payload,
                            txs: Vec::new(),
                            pruned: true,
                        });
                    }
                }

                let consumed = savepoint.len().saturating_sub(reader_blob.len());
                r.advance(consumed);

                self.blocks = Some(out);
                return Ok(true);
            }

            "start_height" => {
                self.start_height = Some(read_epee_value(r).map_err(|_| {
                    cuprate_epee_encoding::error::Error::Format(
                        "getblocks.bin decode failed in field 'start_height'",
                    )
                })?);
            }
            "current_height" => {
                self.current_height = Some(read_epee_value(r).map_err(|_| {
                    cuprate_epee_encoding::error::Error::Format(
                        "getblocks.bin decode failed in field 'current_height'",
                    )
                })?);
            }
            "output_indices" => {
                self.output_indices = Some(
                    read_epee_value_limited(r, epee_limits(0, MAX_EPEE_BLOCKS_PER_RESPONSE))
                        .map_err(|_| {
                            cuprate_epee_encoding::error::Error::Format(
                                "getblocks.bin decode failed in field 'output_indices'",
                            )
                        })?,
                );
            }
            "daemon_time" => {
                self.daemon_time = Some(read_epee_value(r).map_err(|_| {
                    cuprate_epee_encoding::error::Error::Format(
                        "getblocks.bin decode failed in field 'daemon_time'",
                    )
                })?);
            }
            "pool_info_extent" => {
                self.pool_info_extent = Some(read_epee_value(r).map_err(|_| {
                    cuprate_epee_encoding::error::Error::Format(
                        "getblocks.bin decode failed in field 'pool_info_extent'",
                    )
                })?);
            }
            "status" => {
                self.status = Some(
                    read_epee_value_limited(r, epee_limits(0, MAX_EPEE_STATUS_BYTES)).map_err(
                        |_| {
                            cuprate_epee_encoding::error::Error::Format(
                                "getblocks.bin decode failed in field 'status'",
                            )
                        },
                    )?,
                );
            }
            "untrusted" => {
                self.untrusted = Some(read_epee_value(r).map_err(|_| {
                    cuprate_epee_encoding::error::Error::Format(
                        "getblocks.bin decode failed in field 'untrusted'",
                    )
                })?);
            }

            _ => return Ok(false),
        }

        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksFastBinResponse> {
        Ok(GetBlocksFastBinResponse {
            blocks: self.blocks.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'blocks'")
            })?,
            start_height: self.start_height.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'start_height'")
            })?,
            current_height: self.current_height.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'current_height'")
            })?,
            output_indices: self.output_indices.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'output_indices'")
            })?,
            daemon_time: self.daemon_time,
            pool_info_extent: self.pool_info_extent,
            status: self.status,
            untrusted: self.untrusted,
        })
    }
}

impl EpeeObject for GetBlocksFastBinResponse {
    type Builder = GetBlocksFastBinResponseBuilder;

    fn number_of_fields(&self) -> u64 {
        8
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.blocks, "blocks", w)?;
        write_field(self.start_height, "start_height", w)?;
        write_field(self.current_height, "current_height", w)?;
        write_field(self.output_indices, "output_indices", w)?;
        if let Some(daemon_time) = self.daemon_time {
            write_field(daemon_time, "daemon_time", w)?;
        }
        if let Some(pool_info_extent) = self.pool_info_extent {
            write_field(pool_info_extent, "pool_info_extent", w)?;
        }
        if let Some(status) = self.status {
            write_field(status, "status", w)?;
        }
        if let Some(untrusted) = self.untrusted {
            write_field(untrusted, "untrusted", w)?;
        }
        Ok(())
    }
}

/// Request for monerod `/get_blocks_by_height.bin` (portable_storage / EPEE encoded).
#[derive(Clone, Debug)]
pub(crate) struct GetBlocksByHeightBinRequest {
    pub(crate) heights: Vec<u64>,
    pub(crate) prune: bool,
}

#[derive(Default)]
pub(crate) struct GetBlocksByHeightBinRequestBuilder {
    heights: Option<Vec<u64>>,
    prune: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksByHeightBinRequest>
    for GetBlocksByHeightBinRequestBuilder
{
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "heights" => {
                self.heights = Some(read_epee_value_limited(
                    r,
                    epee_limits(8, MAX_EPEE_BLOCKS_PER_RESPONSE),
                )?);
            }
            "prune" => {
                self.prune = Some(read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksByHeightBinRequest> {
        Ok(GetBlocksByHeightBinRequest {
            heights: self.heights.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field heights missing")
            })?,
            prune: self.prune.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field prune missing")
            })?,
        })
    }
}

impl EpeeObject for GetBlocksByHeightBinRequest {
    type Builder = GetBlocksByHeightBinRequestBuilder;

    fn number_of_fields(&self) -> u64 {
        2
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.heights, "heights", w)?;
        write_field(self.prune, "prune", w)?;
        Ok(())
    }
}

/// Range request for monerod `/get_blocks.bin` (portable_storage / EPEE encoded).
///
/// Supported:
/// - start_height: u64
/// - count: u64
/// - prune: bool
#[derive(Clone, Debug)]
pub(crate) struct GetBlocksBinRequest {
    pub(crate) start_height: u64,
    pub(crate) count: u64,
    pub(crate) prune: bool,
}

#[derive(Default)]
pub(crate) struct GetBlocksBinRequestBuilder {
    start_height: Option<u64>,
    count: Option<u64>,
    prune: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksBinRequest> for GetBlocksBinRequestBuilder {
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "start_height" => {
                self.start_height = Some(read_epee_value(r)?);
            }
            "count" => {
                self.count = Some(read_epee_value(r)?);
            }
            "prune" => {
                self.prune = Some(read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksBinRequest> {
        Ok(GetBlocksBinRequest {
            start_height: self.start_height.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field start_height missing")
            })?,
            count: self.count.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field count missing")
            })?,
            prune: self.prune.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field prune missing")
            })?,
        })
    }
}

impl EpeeObject for GetBlocksBinRequest {
    type Builder = GetBlocksBinRequestBuilder;

    fn number_of_fields(&self) -> u64 {
        3
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.start_height, "start_height", w)?;
        write_field(self.count, "count", w)?;
        write_field(self.prune, "prune", w)?;
        Ok(())
    }
}

/// Shared tx entry for binary block responses.
///
/// Used by `BlockCompleteEntry` decoding when daemons provide tx blobs explicitly as objects.
#[derive(Clone, Debug)]
pub(crate) struct TxBlobEntry {
    pub(crate) blob: Vec<u8>,
    pub(crate) prunable_hash: Option<[u8; 32]>,
}

#[derive(Default)]
pub(crate) struct TxBlobEntryBuilder {
    blob: Option<Vec<u8>>,
    prunable_hash: Option<[u8; 32]>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<TxBlobEntry> for TxBlobEntryBuilder {
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "blob" => {
                self.blob = Some(read_epee_value_limited(
                    r,
                    epee_limits(0, MAX_EPEE_BLOB_BYTES),
                )?);
            }
            "prunable_hash" => {
                self.prunable_hash = Some(read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<TxBlobEntry> {
        Ok(TxBlobEntry {
            blob: self.blob.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field blob missing")
            })?,
            prunable_hash: self.prunable_hash,
        })
    }
}

impl EpeeObject for TxBlobEntry {
    type Builder = TxBlobEntryBuilder;

    fn number_of_fields(&self) -> u64 {
        let mut n = 1; // blob
        if self.prunable_hash.is_some() {
            n += 1;
        }
        n
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.blob, "blob", w)?;
        if let Some(hash) = self.prunable_hash {
            write_field(hash, "prunable_hash", w)?;
        }
        Ok(())
    }
}

/// Shared block entry for `/get_blocks_by_height.bin` and (typically) `/get_blocks.bin`.
#[derive(Clone, Debug)]
pub(crate) struct BlockCompleteEntry {
    pub(crate) block: Vec<u8>,
    /// Some daemons (or prune modes) omit tx blobs in certain responses.
    /// When omitted, we treat it as an empty list.
    pub(crate) txs: Vec<TxBlobEntry>,
    /// Daemons include whether the entry is pruned.
    pub(crate) pruned: bool,
}

#[derive(Default)]
pub(crate) struct BlockCompleteEntryBuilder {
    block: Option<Vec<u8>>,
    txs: Option<Vec<TxBlobEntry>>,
    pruned: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<BlockCompleteEntry> for BlockCompleteEntryBuilder {
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "block" => {
                if bulk_bin_debug_enabled() {
                    let rem_before = r.remaining();
                    walletcore_diagnostic!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='block' remaining_before={}",
                        rem_before
                    );
                }

                self.block = Some(read_epee_value_limited(
                    r,
                    epee_limits(0, MAX_EPEE_BLOB_BYTES),
                )?);

                if bulk_bin_debug_enabled() {
                    let rem_after = r.remaining();
                    walletcore_diagnostic!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='block' remaining_after={}",
                        rem_after
                    );
                }
            }

            "txs" => {
                if bulk_bin_debug_enabled() {
                    let rem_before = r.remaining();
                    let chunk = r.chunk();

                    let peek_marker = if rem_before > 0 && !chunk.is_empty() {
                        format!("0x{:02x}", chunk[0])
                    } else if rem_before > 0 {
                        "(unavailable)".to_string()
                    } else {
                        "(eof)".to_string()
                    };

                    if rem_before > 0 && !chunk.is_empty() && chunk[0] == 0x8c {
                        let dump_len = std::cmp::min(16, chunk.len());
                        walletcore_diagnostic!(
                            "🧩 get_blocks(.bin) block_complete_entry: field='txs' marker=0x8c leading_bytes[0..{}]={}",
                            dump_len,
                            hex_dump_prefix(&chunk[..dump_len], dump_len)
                        );
                    }

                    walletcore_diagnostic!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='txs' remaining_before={} next_marker={}",
                        rem_before, peek_marker
                    );
                }

                // Some daemons encode `txs` with a typed-array marker (observed 0x8c + element type name "blob").
                // Parse it keyed by embedded element type name; fall back to generic decoder otherwise.
                let tx_entries: Vec<TxBlobEntry> = {
                    if r.has_remaining() {
                        let save = r.chunk();
                        let mut tmp: &[u8] = save;
                        match read_epee_value_limited::<Vec<TxBlobEntry>, _>(
                            &mut tmp,
                            epee_limits(32, MAX_EPEE_TXS_PER_BLOCK),
                        ) {
                            Ok(v) => {
                                let consumed = save.len().saturating_sub(tmp.len());
                                r.advance(consumed);
                                Ok(v)
                            }
                            Err(e) => Err(e),
                        }
                    } else {
                        Err(cuprate_epee_encoding::error::Error::Format(
                            "get_blocks(.bin) block_complete_entry: txs: empty buffer",
                        ))
                    }
                }
                .or_else(|_| {
                    if r.has_remaining() {
                        let save = r.chunk();
                        let mut tmp: &[u8] = save;
                        match read_epee_value_limited::<Vec<Vec<u8>>, _>(
                            &mut tmp,
                            epee_limits(32, MAX_EPEE_TXS_PER_BLOCK),
                        ) {
                            Ok(v) => {
                                let consumed = save.len().saturating_sub(tmp.len());
                                r.advance(consumed);
                                let tx_entries: Vec<TxBlobEntry> = v
                                    .into_iter()
                                    .map(|blob| TxBlobEntry {
                                        blob,
                                        prunable_hash: None,
                                    })
                                    .collect();
                                return Ok(tx_entries);
                            }
                            Err(_) => {}
                        }
                    }
                    Err(cuprate_epee_encoding::error::Error::Format(
                        "get_blocks(.bin) block_complete_entry: txs: fallback parse miss",
                    ))
                })
                .or_else(|_| {
                    let chunk = r.chunk();
                    if !chunk.is_empty() && chunk[0] == 0x8c {
                        read_txs_typed_array_0x8c(r).map(|v| {
                            v.into_iter()
                                .map(|blob| TxBlobEntry {
                                    blob,
                                    prunable_hash: None,
                                })
                                .collect()
                        })
                    } else {
                        read_epee_value_limited::<Vec<Vec<u8>>, _>(
                            r,
                            epee_limits(32, MAX_EPEE_TXS_PER_BLOCK),
                        )
                        .map(|v| {
                            v.into_iter()
                                .map(|blob| TxBlobEntry {
                                    blob,
                                    prunable_hash: None,
                                })
                                .collect()
                        })
                    }
                })?;

                self.txs = Some(tx_entries);

                if bulk_bin_debug_enabled() {
                    let rem_after = r.remaining();
                    let chunk = r.chunk();
                    let peek_marker = if rem_after > 0 && !chunk.is_empty() {
                        format!("0x{:02x}", chunk[0])
                    } else if rem_after > 0 {
                        "(unavailable)".to_string()
                    } else {
                        "(eof)".to_string()
                    };

                    walletcore_diagnostic!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='txs' remaining_after={} next_marker={}",
                        rem_after, peek_marker
                    );
                }
            }

            // Be permissive with common field name variants observed across daemons / implementations.
            "txs_blob" | "txs_blobs" | "txs_bytes" | "txs_byte" | "txs_data" | "transactions" => {
                if bulk_bin_debug_enabled() {
                    walletcore_diagnostic!(
                        "🧩 get_blocks(.bin) block_complete_entry: field={:?} (normalized to 'txs')",
                        name
                    );
                }
                self.txs = Some(read_epee_value_limited(
                    r,
                    epee_limits(32, MAX_EPEE_TXS_PER_BLOCK),
                )?);
            }

            "pruned" => {
                if bulk_bin_debug_enabled() {
                    let rem_before = r.remaining();
                    let peek_marker = if rem_before > 0 {
                        let chunk = r.chunk();
                        if !chunk.is_empty() {
                            format!("0x{:02x}", chunk[0])
                        } else {
                            "(unavailable)".to_string()
                        }
                    } else {
                        "(eof)".to_string()
                    };

                    walletcore_diagnostic!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='pruned' remaining_before={} next_marker={}",
                        rem_before, peek_marker
                    );
                }

                self.pruned = Some(read_epee_value(r)?);

                if bulk_bin_debug_enabled() {
                    let rem_after = r.remaining();
                    let peek_marker = if rem_after > 0 {
                        let chunk = r.chunk();
                        if !chunk.is_empty() {
                            format!("0x{:02x}", chunk[0])
                        } else {
                            "(unavailable)".to_string()
                        }
                    } else {
                        "(eof)".to_string()
                    };

                    walletcore_diagnostic!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='pruned' remaining_after={} next_marker={}",
                        rem_after, peek_marker
                    );
                }
            }

            _ => {
                // IMPORTANT: we must consume unknown values to keep the reader aligned.
                if bulk_bin_debug_enabled() {
                    let rem_before = r.remaining();
                    let peek_marker = if rem_before > 0 {
                        let chunk = r.chunk();
                        if !chunk.is_empty() {
                            format!("0x{:02x}", chunk[0])
                        } else {
                            "(unavailable)".to_string()
                        }
                    } else {
                        "(eof)".to_string()
                    };

                    walletcore_diagnostic!(
                        "🧩 get_blocks(.bin) block_complete_entry: skipping unknown field {:?} (next_marker={} remaining_before_skip={})",
                        name, peek_marker, rem_before
                    );
                }

                skip_epee_value(r)?;
            }
        }

        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<BlockCompleteEntry> {
        let block = self.block.ok_or_else(|| {
            cuprate_epee_encoding::error::Error::Format("block_complete_entry missing 'block'")
        })?;

        let txs = self.txs.unwrap_or_default();
        let pruned = self.pruned.unwrap_or(false);

        if bulk_bin_debug_enabled() {
            walletcore_diagnostic!(
                "🧩 get_blocks(.bin) block_complete_entry: decoded block_bytes={} tx_blobs={} pruned={}",
                block.len(),
                txs.len(),
                pruned
            );
        }

        Ok(BlockCompleteEntry { block, txs, pruned })
    }
}

impl EpeeObject for BlockCompleteEntry {
    type Builder = BlockCompleteEntryBuilder;

    fn number_of_fields(&self) -> u64 {
        3
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.block, "block", w)?;
        write_field(self.txs, "txs", w)?;
        write_field(self.pruned, "pruned", w)?;
        Ok(())
    }
}

/// Minimal response model for monerod `/get_blocks_by_height.bin`.
#[derive(Clone, Debug)]
pub(crate) struct GetBlocksByHeightBinResponse {
    pub(crate) blocks: Vec<BlockCompleteEntry>,
    pub(crate) status: Option<String>,
    pub(crate) untrusted: Option<bool>,
}

#[derive(Default)]
pub(crate) struct GetBlocksByHeightBinResponseBuilder {
    blocks: Option<Vec<BlockCompleteEntry>>,
    status: Option<String>,
    untrusted: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksByHeightBinResponse>
    for GetBlocksByHeightBinResponseBuilder
{
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "blocks" => {
                self.blocks = Some(read_epee_value_limited(
                    r,
                    epee_limits(32, MAX_EPEE_BLOCKS_PER_RESPONSE),
                )?);
            }
            "status" => {
                self.status = Some(read_epee_value_limited(
                    r,
                    epee_limits(0, MAX_EPEE_STATUS_BYTES),
                )?);
            }
            "untrusted" => {
                self.untrusted = Some(read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksByHeightBinResponse> {
        Ok(GetBlocksByHeightBinResponse {
            blocks: self.blocks.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'blocks'")
            })?,
            status: self.status,
            untrusted: self.untrusted,
        })
    }
}

impl EpeeObject for GetBlocksByHeightBinResponse {
    type Builder = GetBlocksByHeightBinResponseBuilder;

    fn number_of_fields(&self) -> u64 {
        3
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.blocks, "blocks", w)?;
        if let Some(status) = self.status {
            write_field(status, "status", w)?;
        }
        if let Some(untrusted) = self.untrusted {
            write_field(untrusted, "untrusted", w)?;
        }
        Ok(())
    }
}

/// Minimal response model for monerod `/get_blocks.bin` (range-based).
#[derive(Clone, Debug)]
pub(crate) struct GetBlocksBinResponse {
    pub(crate) blocks: Vec<BlockCompleteEntry>,
    pub(crate) output_indices: Option<Vec<BlockOutputIndices>>,
    pub(crate) status: Option<String>,
    pub(crate) untrusted: Option<bool>,
}

#[derive(Default)]
pub(crate) struct GetBlocksBinResponseBuilder {
    blocks: Option<Vec<BlockCompleteEntry>>,
    output_indices: Option<Vec<BlockOutputIndices>>,
    status: Option<String>,
    untrusted: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksBinResponse>
    for GetBlocksBinResponseBuilder
{
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "blocks" => {
                // Mirror the tolerant `/getblocks.bin` decoder because `/get_blocks.bin`
                // can also return typed-array/blob layouts for `blocks`.
                if r.has_remaining() {
                    let save = r.chunk();
                    let mut tmp: &[u8] = save;
                    match read_epee_value_limited::<Vec<BlockCompleteEntry>, _>(
                        &mut tmp,
                        epee_limits(32, MAX_EPEE_BLOCKS_PER_RESPONSE),
                    ) {
                        Ok(v) => {
                            let consumed = save.len().saturating_sub(tmp.len());
                            r.advance(consumed);
                            self.blocks = Some(v);
                            return Ok(true);
                        }
                        Err(_) => {}
                    }
                }

                if !r.has_remaining() {
                    return Err(cuprate_epee_encoding::error::Error::Format(
                        "get_blocks.bin decode failed in field 'blocks': EOF (missing container marker)",
                    ));
                }

                let container_marker = r.get_u8();
                let (n, typed_elem_type): (u64, Option<String>) = match container_marker {
                    0x0d => {
                        if !r.has_remaining() {
                            return Err(cuprate_epee_encoding::error::Error::Format(
                                "get_blocks.bin decode failed in field 'blocks': EOF (missing element marker)",
                            ));
                        }
                        let elem_marker = r.get_u8();
                        if elem_marker != 0x0c {
                            return Err(cuprate_epee_encoding::error::Error::Format("get_blocks.bin decode failed in field 'blocks': unexpected element marker"));
                        }
                        let n = skip_epee_varint_u64(r)?;
                        (n, None)
                    }
                    0x8c => {
                        let n = skip_epee_varint_u64(r)?;
                        (n, None)
                    }
                    _ => {
                        return Err(cuprate_epee_encoding::error::Error::Format("get_blocks.bin decode failed in field 'blocks': unexpected container marker"));
                    }
                };

                let n = checked_epee_sequence_len(
                    n,
                    MAX_EPEE_BLOCKS_PER_RESPONSE,
                    "get_blocks.bin blocks",
                )?;
                let savepoint: &[u8] = r.chunk();

                let mut reader_obj: &[u8] = savepoint;
                let mut obj_out: Vec<BlockCompleteEntry> = Vec::with_capacity(n);
                let mut object_decode_ok = true;

                for _ in 0..n {
                    let fields = match skip_epee_varint_u64(&mut reader_obj) {
                        Ok(v) => v,
                        Err(_) => {
                            object_decode_ok = false;
                            break;
                        }
                    };

                    let mut builder = BlockCompleteEntryBuilder::default();
                    for _ in 0..fields {
                        let name = match read_epee_field_name(&mut reader_obj) {
                            Ok(v) => v,
                            Err(_) => {
                                object_decode_ok = false;
                                break;
                            }
                        };

                        match builder.add_field(&name, &mut reader_obj) {
                            Ok(true) => {}
                            Ok(false) => {
                                if let Err(_) = skip_epee_value(&mut reader_obj) {
                                    object_decode_ok = false;
                                    break;
                                }
                            }
                            Err(_) => {
                                object_decode_ok = false;
                                break;
                            }
                        }
                    }

                    if !object_decode_ok {
                        break;
                    }

                    let entry = match builder.finish() {
                        Ok(v) => v,
                        Err(_) => {
                            object_decode_ok = false;
                            break;
                        }
                    };
                    obj_out.push(entry);
                }

                if object_decode_ok && obj_out.len() == n {
                    let consumed = savepoint.len().saturating_sub(reader_obj.len());
                    r.advance(consumed);
                    self.blocks = Some(obj_out);
                    return Ok(true);
                }

                let mut reader_blob: &[u8] = savepoint;
                let mut out: Vec<BlockCompleteEntry> = Vec::with_capacity(n);

                for _ in 0..n {
                    if reader_blob.is_empty() {
                        return Err(cuprate_epee_encoding::error::Error::Format(
                            "get_blocks.bin decode failed in field 'blocks': block entry EOF",
                        ));
                    }

                    if !reader_blob.is_empty() && is_supported_blob_marker(reader_blob[0]) {
                        reader_blob = &reader_blob[1..];
                    }

                    let blob_payload = read_epee_len_prefixed_bytes(
                        &mut reader_blob,
                        "get_blocks.bin blocks(blob_payload/shared_marker)",
                        MAX_EPEE_BLOB_BYTES,
                    )?;

                    if let Some(entry) =
                        try_decode_block_complete_entry_from_blob_payload(&blob_payload)?
                    {
                        out.push(entry);
                    } else {
                        out.push(BlockCompleteEntry {
                            block: blob_payload,
                            txs: Vec::new(),
                            pruned: true,
                        });
                    }
                }

                let consumed = savepoint.len().saturating_sub(reader_blob.len());
                r.advance(consumed);
                self.blocks = Some(out);
                return Ok(true);
            }
            "output_indices" => {
                self.output_indices = Some(
                    read_epee_value_limited(r, epee_limits(0, MAX_EPEE_BLOCKS_PER_RESPONSE))
                        .map_err(|_| {
                            cuprate_epee_encoding::error::Error::Format(
                                "get_blocks.bin decode failed in field 'output_indices'",
                            )
                        })?,
                );
            }
            "status" => {
                self.status = Some(read_epee_value_limited(
                    r,
                    epee_limits(0, MAX_EPEE_STATUS_BYTES),
                )?);
            }
            "untrusted" => {
                self.untrusted = Some(read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksBinResponse> {
        Ok(GetBlocksBinResponse {
            blocks: self.blocks.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'blocks'")
            })?,
            output_indices: self.output_indices,
            status: self.status,
            untrusted: self.untrusted,
        })
    }
}

impl EpeeObject for GetBlocksBinResponse {
    type Builder = GetBlocksBinResponseBuilder;

    fn number_of_fields(&self) -> u64 {
        4
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.blocks, "blocks", w)?;
        if let Some(output_indices) = self.output_indices {
            write_field(output_indices, "output_indices", w)?;
        }
        if let Some(status) = self.status {
            write_field(status, "status", w)?;
        }
        if let Some(untrusted) = self.untrusted {
            write_field(untrusted, "untrusted", w)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{GetBlocksBinResponse, GetBlocksBinResponseBuilder};
    use crate::support::bulk_bin::MAX_EPEE_BLOCKS_PER_RESPONSE;
    use cuprate_epee_encoding::EpeeObjectBuilder;
    use monero_wallet::{
        block::Block as MoneroBlock,
        transaction::{NotPruned, Transaction},
    };

    #[test]
    #[ignore = "requires /tmp/get_blocks_3630413_25.bin debug fixture"]
    fn debug_decode_saved_get_blocks_bin_sample() {
        let sample_path = "/tmp/get_blocks_3630413_25.bin";
        let sample = std::fs::read(sample_path)
            .unwrap_or_else(|e| panic!("failed to read {sample_path}: {e}"));

        let mut reader: &[u8] = sample.as_slice();
        let resp: GetBlocksBinResponse = cuprate_epee_encoding::from_bytes(&mut reader)
            .unwrap_or_else(|e| panic!("response decode failed: {e}"));

        walletcore_diagnostic!(
            "decoded blocks={} trailing={} status={:?} untrusted={:?}",
            resp.blocks.len(),
            reader.len(),
            resp.status,
            resp.untrusted
        );
        assert!(!resp.blocks.is_empty(), "expected at least one block");

        let first = &resp.blocks[0];
        walletcore_diagnostic!(
            "first block bytes={} txs={} pruned={}",
            first.block.len(),
            first.txs.len(),
            first.pruned
        );

        let mut block_reader: &[u8] = first.block.as_slice();
        let block = MoneroBlock::read(&mut block_reader)
            .unwrap_or_else(|e| panic!("first block decode failed: {e}"));
        walletcore_diagnostic!(
            "first block tx_hashes={} trailing_block_bytes={}",
            block.transactions.len(),
            block_reader.len()
        );

        if let Some(first_tx) = first.txs.first() {
            let mut tx_reader: &[u8] = first_tx.blob.as_slice();
            let tx = Transaction::<NotPruned>::read(&mut tx_reader)
                .unwrap_or_else(|e| panic!("first tx decode failed: {e}"));
            walletcore_diagnostic!(
                "first tx trailing_bytes={} prunable_hash_present={} computed_prunable_hash_present={}",
                tx_reader.len(),
                first_tx.prunable_hash.is_some(),
                tx.prunable_hash().is_some()
            );
        }
    }

    #[test]
    fn range_blocks_fallback_rejects_oversized_sequence_before_allocation() {
        let mut encoded = vec![0x8c];
        cuprate_epee_encoding::write_varint(MAX_EPEE_BLOCKS_PER_RESPONSE + 1, &mut encoded)
            .expect("test varint should encode");

        let mut reader = encoded.as_slice();
        let err = GetBlocksBinResponseBuilder::default()
            .add_field("blocks", &mut reader)
            .expect_err("oversized block sequence should fail");
        assert!(err.to_string().contains("exceeds limit"));
    }
}
