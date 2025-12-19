//! Fetch and save a monerod `/get_blocks_by_height.bin` response for schema inspection.
//!
//! Usage example:
//!   cargo run --release --bin fetch_blocks_by_height_bin -- \
//!     --url http://192.168.4.137:18081 \
//!     --heights 3568035,3568036 \
//!     --out resp.bin
//!
//! Notes:
//! - The `.bin` endpoints use Monero "portable_storage" (EPEE) binary encoding.
//! - This tool builds the request using `cuprate_epee_encoding` (real encoder) and dumps raw response bytes.
//! - It decodes the response using `cuprate_epee_encoding` to print named fields + counts (best-effort).
//!
//! If you want to test restricted RPC too, try `--url http://HOST:18089`.

use std::{env, fs, io::Read, path::PathBuf, time::Instant};

use cuprate_epee_encoding::{to_bytes, write_field, EpeeObject};
use monero_epee::{Epee, EpeeError};

fn usage_and_exit(msg: Option<&str>) -> ! {
    if let Some(m) = msg {
        eprintln!("error: {m}\n");
    }
    eprintln!(
        "Usage:
  fetch_blocks_by_height_bin --url <http://host:port> --heights <h1,h2,...> --out <file>

Example:
  cargo run --release --bin fetch_blocks_by_height_bin -- \\
    --url http://192.168.4.137:18081 \\
    --heights 3568035,3568036 \\
    --out resp.bin
"
    );
    std::process::exit(2);
}

fn parse_arg(args: &[String], name: &str) -> Option<String> {
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == name {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn parse_heights(csv: &str) -> Result<Vec<u64>, String> {
    let mut out = Vec::new();
    for part in csv.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let h: u64 = p.parse().map_err(|_| format!("invalid height '{p}'"))?;
        out.push(h);
    }
    if out.is_empty() {
        return Err("no heights provided".to_string());
    }
    Ok(out)
}

fn hex_preview(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Portable-storage request for monerod `get_blocks_by_height.bin`.
///
/// Expected fields (per docs/daemon handler):
/// - heights: array of unsigned int (we use u64)
/// - prune: bool
#[derive(Clone, Debug)]
struct GetBlocksByHeightBinRequest {
    heights: Vec<u64>,
    prune: bool,
}

#[derive(Default)]
struct GetBlocksByHeightBinRequestBuilder {
    heights: Option<Vec<u64>>,
    prune: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksByHeightBinRequest>
    for GetBlocksByHeightBinRequestBuilder
{
    fn add_field<B: bytes::Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "heights" => {
                self.heights = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "prune" => {
                self.prune = Some(cuprate_epee_encoding::read_epee_value(r)?);
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

    fn write_fields<B: bytes::BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.heights, "heights", w)?;
        write_field(self.prune, "prune", w)?;
        Ok(())
    }
}

fn decode_top_level_kinds(resp: &[u8]) -> Result<Vec<String>, EpeeError> {
    let reader: &[u8] = resp;
    let mut epee = Epee::new(reader)?;
    let entry = epee.entry()?; // root object
    let mut out = Vec::new();

    let mut fields = entry.fields()?;
    let mut idx: usize = 0;
    while let Some(item) = fields.next() {
        let (_key, value) = item?;
        out.push(format!("#{idx}: {:?}", value.kind()));
        drop(value);
        idx += 1;
    }

    Ok(out)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let url = parse_arg(&args, "--url").unwrap_or_else(|| usage_and_exit(Some("missing --url")));
    let heights_csv =
        parse_arg(&args, "--heights").unwrap_or_else(|| usage_and_exit(Some("missing --heights")));
    let out_path =
        parse_arg(&args, "--out").unwrap_or_else(|| usage_and_exit(Some("missing --out")));

    let heights = parse_heights(&heights_csv).unwrap_or_else(|e| usage_and_exit(Some(&e)));
    let out_path = PathBuf::from(out_path);

    let route = format!("{}/get_blocks_by_height.bin", url.trim_end_matches('/'));

    // Build request with real portable_storage encoder
    let req = GetBlocksByHeightBinRequest {
        heights: heights.clone(),
        prune: false,
    };

    let body = match to_bytes(req) {
        Ok(b) => b,
        Err(e) => usage_and_exit(Some(&format!(
            "failed to encode request via cuprate_epee_encoding: {e}"
        ))),
    };

    eprintln!("→ POST {route}");
    eprintln!("→ heights: {:?}", heights);
    eprintln!(
        "→ request bytes: {} hex[0..16]={}",
        body.len(),
        hex_preview(&body, 16)
    );

    let started = Instant::now();

    let resp = match ureq::post(&route)
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&body)
    {
        Ok(r) => {
            let mut reader = r.into_reader();
            let mut buf = Vec::new();
            reader
                .read_to_end(&mut buf)
                .unwrap_or_else(|e| usage_and_exit(Some(&format!("failed reading response: {e}"))));
            buf
        }
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.status_text().to_string();
            usage_and_exit(Some(&format!(
                "HTTP {code} {text} (request_hex[0..32]={})",
                hex_preview(&body, 32)
            )));
        }
        Err(ureq::Error::Transport(t)) => {
            usage_and_exit(Some(&format!("transport error: {t}")));
        }
    };

    let elapsed = started.elapsed();
    eprintln!("← response bytes: {} (in {:?})", resp.len(), elapsed);

    fs::write(&out_path, &resp).unwrap_or_else(|e| {
        usage_and_exit(Some(&format!("failed writing {}: {e}", out_path.display())))
    });
    eprintln!("✅ wrote {}", out_path.display());

    // For now, keep a simple kind-only view (order only). We'll decode named fields once we confirm
    // the correct `from_bytes`/builder usage for this cuprate_epee_encoding version.
    match decode_top_level_kinds(&resp) {
        Ok(kinds) => {
            eprintln!("Top-level portable_storage field kinds (order only):");
            for k in kinds {
                eprintln!("  - {k}");
            }
        }
        Err(err) => {
            eprintln!("⚠️ Could not decode portable_storage response with monero-epee: {err:?}");
            eprintln!("   (Raw response was written; this is still useful.)");
            eprintln!("   first 16 bytes: {}", hex_preview(&resp, 16));
        }
    }
}
