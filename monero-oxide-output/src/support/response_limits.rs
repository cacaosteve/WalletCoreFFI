//! Bound decoded HTTP bodies before allocating/decoding untrusted daemon responses.
use std::io::{self, Read};

pub(crate) const MAX_JSON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
#[cfg(any(target_os = "android", target_os = "ios"))]
pub(crate) const MAX_BINARY_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) const MAX_BINARY_RESPONSE_BYTES: usize = 128 * 1024 * 1024;

fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "daemon response exceeds byte limit; try a smaller scan batch")
}

/// Read at most limit + 1 bytes, even without a Content-Length (e.g. chunked transfer).
/// The extra byte distinguishes a complete, exactly-at-limit body from truncation.
pub(crate) fn read_limited(reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take((limit as u64).saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() > limit { return Err(too_large()); }
    Ok(bytes)
}

pub(crate) fn read_response(response: ureq::Response, limit: usize) -> io::Result<Vec<u8>> {
    // This is only an early rejection; never rely on the peer's advertised length.
    if response.header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > limit as u64)
    {
        return Err(too_large());
    }
    // ureq's reader also handles decompression. The streaming bound therefore applies
    // to the bytes consumed by the decoder, not just compressed network bytes.
    read_limited(response.into_reader(), limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn accepts_complete_body_at_limit_and_rejects_extra_byte() {
        assert_eq!(read_limited(&b"12345678"[..], 8).unwrap(), b"12345678");
        assert_eq!(read_limited(&b"123456789"[..], 8).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(read_limited(io::empty(), 0).unwrap().is_empty());
    }

    #[test]
    fn endless_body_is_stopped_after_limit_plus_one_bytes() {
        struct Endless { consumed: usize }
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                buf.fill(0);
                self.consumed += buf.len();
                Ok(buf.len())
            }
        }
        let mut body = Endless { consumed: 0 };
        assert!(read_limited(&mut body, 1024).is_err());
        assert_eq!(body.consumed, 1025);
    }

    #[test]
    fn rejects_large_advertised_length_without_reading_payload() {
        let response: ureq::Response = "HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\n".parse().unwrap();
        assert_eq!(read_response(response, 8).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn actual_chunked_http_is_bounded_without_content_length() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\n12345\r\n4\r\n6789\r\n0\r\n\r\n").unwrap();
        });
        let response = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(5))
            .build().get(&format!("http://{address}")).call().unwrap();
        assert_eq!(read_response(response, 8).unwrap_err().kind(), io::ErrorKind::InvalidData);
        server.join().unwrap();
    }
}
