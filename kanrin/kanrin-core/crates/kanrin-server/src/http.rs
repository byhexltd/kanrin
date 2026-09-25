//! Minimal HTTP/1.1 for the front door (Phase 17.1.4).
//!
//! Deliberately hand-rolled rather than delegated to a framework. Two reasons,
//! both from the divergence audit (`DESIGN-EVASION.md` §3a):
//!
//! - **Byte-exactness.** 17.1.11 requires error responses identical to the
//!   genuine origin. A framework decides header order, casing, `Date` format
//!   and default headers for you, and those choices are a fingerprint of the
//!   framework rather than of the site being claimed.
//! - **One parser for everyone.** The invariance property is structural here:
//!   there is a single `RequestHead::parse`, so an authenticated and an
//!   unauthenticated request cannot be parsed by different code, cannot be
//!   rejected by different rules, and cannot fail with different errors.
//!
//! Where an upstream origin is configured the response is not built here at
//! all — it is the origin's own bytes, forwarded verbatim (17.1.5). That is
//! strictly stronger than reproducing them, and is the difference between
//! *being* a site and imitating one.

use std::collections::HashMap;
use std::fmt::Write as _;

/// Cap on the request head. Beyond this the request is refused — as any real
/// server does — rather than buffered indefinitely.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// A parsed request line plus headers. The body is left on the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: String,
    /// Header names lowercased for lookup; values kept verbatim.
    pub headers: HashMap<String, String>,
    /// Number of bytes the head occupied, so the caller knows where the body
    /// starts in the buffer it already read.
    pub head_len: usize,
    /// The head exactly as it arrived, for verbatim forwarding upstream.
    pub raw: Vec<u8>,
}

/// Why a request could not be parsed.
///
/// Carries no detail about *which* request failed: the same variant must be
/// produced for a prober and for a client, and a richer error type invites
/// callers to respond differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The head is not complete yet — read more.
    Incomplete,
    /// Malformed beyond recovery.
    Malformed,
    /// Larger than [`MAX_HEAD_BYTES`].
    TooLarge,
}

impl RequestHead {
    /// Parse a request head from `buf`.
    ///
    /// Returns [`ParseError::Incomplete`] until the terminating blank line has
    /// arrived, so the caller can keep reading without deciding anything.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() > MAX_HEAD_BYTES {
            return Err(ParseError::TooLarge);
        }

        let head_end = find_head_end(buf).ok_or(ParseError::Incomplete)?;
        let head = &buf[..head_end];
        let text = std::str::from_utf8(head).map_err(|_| ParseError::Malformed)?;

        let mut lines = text.split("\r\n");
        let request_line = lines.next().ok_or(ParseError::Malformed)?;

        // Exactly three space-separated tokens. Being strict here is safe
        // because it is strict for everyone.
        let mut parts = request_line.split(' ');
        let method = parts.next().filter(|s| !s.is_empty()).ok_or(ParseError::Malformed)?;
        let target = parts.next().filter(|s| !s.is_empty()).ok_or(ParseError::Malformed)?;
        let version = parts.next().filter(|s| !s.is_empty()).ok_or(ParseError::Malformed)?;
        if parts.next().is_some() || !version.starts_with("HTTP/") {
            return Err(ParseError::Malformed);
        }

        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let (name, value) = line.split_once(':').ok_or(ParseError::Malformed)?;
            if name.is_empty() || name.contains(' ') {
                return Err(ParseError::Malformed);
            }
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }

        Ok(Self {
            method: method.to_string(),
            target: target.to_string(),
            version: version.to_string(),
            headers,
            head_len: head_end + 4,
            raw: buf[..head_end + 4].to_vec(),
        })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|s| s.as_str())
    }

    /// Declared body length, if any.
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")?.parse().ok()
    }

    /// Path component of the target, without the query string.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("/")
    }

    /// Whether the client asked to keep the connection open.
    ///
    /// Matters for invariance: a front door that closed after every response
    /// while the real origin keeps connections alive would be distinguishable
    /// without reading a single byte of content.
    pub fn wants_keep_alive(&self) -> bool {
        match self.header("connection") {
            Some(v) if v.eq_ignore_ascii_case("close") => false,
            Some(v) if v.eq_ignore_ascii_case("keep-alive") => true,
            _ => self.version != "HTTP/1.0",
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// A response this server generates itself, used only when no upstream origin
/// is configured.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    /// Ordered, because header order is part of what identifies a server and
    /// a map would reorder it unpredictably between responses.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, reason: &str) -> Self {
        Self {
            status,
            reason: reason.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Serialise to wire bytes.
    ///
    /// `Content-Length` is always emitted, including for empty bodies: a
    /// response without it forces the client to infer framing from the
    /// connection close, which is both unlike a modern origin and prevents
    /// keep-alive.
    pub fn encode(&self) -> Vec<u8> {
        let mut head = String::with_capacity(128 + self.headers.len() * 32);
        let _ = write!(head, "HTTP/1.1 {} {}\r\n", self.status, self.reason);
        for (name, value) in &self.headers {
            let _ = write!(head, "{name}: {value}\r\n");
        }
        let _ = write!(head, "Content-Length: {}\r\n\r\n", self.body.len());

        let mut out = head.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }

    pub fn not_found() -> Self {
        Self::new(404, "Not Found")
    }

    pub fn bad_request() -> Self {
        Self::new(400, "Bad Request")
    }
}

/// Guess a content type from a path extension.
///
/// Only the handful a static site actually serves. An unknown extension gets
/// `application/octet-stream`, which is what a default nginx does.
pub fn content_type_for(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext.to_ascii_lowercase()) {
        Some(ext) => match ext.as_str() {
            "html" | "htm" => "text/html; charset=utf-8",
            "css" => "text/css",
            "js" => "application/javascript",
            "json" => "application/json",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "svg" => "image/svg+xml",
            "ico" => "image/x-icon",
            "txt" => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        },
        None => "application/octet-stream",
    }
}

/// Percent-decode a path, returning `None` on a malformed escape.
///
/// Decoding has to happen *before* the traversal check, not after. Checking
/// the raw form lets `..%2f` through as an innocent-looking segment that the
/// filesystem later reads as a traversal — the check and the consumer must be
/// looking at the same string.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = input.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Resolve a request path to a file inside `root`, or `None` if it escapes.
///
/// Rejects rather than normalises. Normalisation only works if it agrees with
/// the filesystem's own view of the path, and on Windows — with drive-relative
/// paths, alternate separators and stream suffixes — that is a losing game.
/// Refusal is unambiguous.
pub fn resolve_path(root: &std::path::Path, request_path: &str) -> Option<std::path::PathBuf> {
    let decoded = percent_decode(request_path)?;
    let trimmed = decoded.trim_start_matches('/');
    let relative = if trimmed.is_empty() { "index.html" } else { trimmed };

    let mut out = root.to_path_buf();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        // Any `..` at all, not just an exact match: a segment that merely
        // contains one is never a legitimate static asset, and allowing it
        // relies on the filesystem agreeing with this parser about where the
        // segment boundaries are.
        if segment.contains("..") || segment.contains('\\') || segment.contains(':') {
            return None;
        }
        out.push(segment);
    }

    // A directory request serves its index, as a real static server does.
    if out.is_dir() {
        out.push("index.html");
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(raw: &str) -> Result<RequestHead, ParseError> {
        RequestHead::parse(raw.as_bytes())
    }

    #[test]
    fn test_parses_an_ordinary_request() {
        let r = head("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\n\r\n")
            .unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.target, "/index.html");
        assert_eq!(r.version, "HTTP/1.1");
        assert_eq!(r.header("host"), Some("example.com"));
        assert_eq!(r.header("user-agent"), Some("curl/8"));
    }

    #[test]
    fn test_header_lookup_is_case_insensitive() {
        // Clients vary in casing; treating them differently would make the
        // authenticator's presence depend on how the client spelled it.
        let r = head("GET / HTTP/1.1\r\nHOST: a\r\nX-Mixed-Case: v\r\n\r\n").unwrap();
        assert_eq!(r.header("host"), Some("a"));
        assert_eq!(r.header("x-mixed-case"), Some("v"));
    }

    #[test]
    fn test_incomplete_head_is_not_an_error() {
        // The caller must be able to keep reading without having decided
        // anything about the request yet.
        assert_eq!(head("GET / HTTP/1.1\r\nHost: a\r\n"), Err(ParseError::Incomplete));
        assert_eq!(head(""), Err(ParseError::Incomplete));
    }

    #[test]
    fn test_malformed_requests_are_rejected_uniformly() {
        for raw in [
            "GET\r\n\r\n",
            "GET /\r\n\r\n",
            "GET / HTTP/1.1 extra\r\n\r\n",
            "GET / NOTHTTP\r\n\r\n",
            "GET / HTTP/1.1\r\nbad header line\r\n\r\n",
            "GET / HTTP/1.1\r\nBad Name: v\r\n\r\n",
            "GET / HTTP/1.1\r\n: empty\r\n\r\n",
        ] {
            assert_eq!(head(raw), Err(ParseError::Malformed), "accepted: {raw:?}");
        }
    }

    #[test]
    fn test_oversized_head_is_refused_not_buffered() {
        let mut raw = String::from("GET / HTTP/1.1\r\n");
        while raw.len() <= MAX_HEAD_BYTES {
            raw.push_str("X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        assert_eq!(head(&raw), Err(ParseError::TooLarge));
    }

    #[test]
    fn test_head_len_locates_the_body() {
        let raw = "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let r = head(raw).unwrap();
        assert_eq!(r.content_length(), Some(5));
        assert_eq!(&raw.as_bytes()[r.head_len..], b"hello");
    }

    #[test]
    fn test_raw_head_is_preserved_for_verbatim_forwarding() {
        // 17.1.5 forwards the request to the origin unchanged; a re-serialised
        // head would reorder or re-case headers and stop being the client's.
        let raw = "GET / HTTP/1.1\r\nHost: a\r\nZ-Last: 1\r\nA-First: 2\r\n\r\n";
        let r = head(raw).unwrap();
        assert_eq!(r.raw, raw.as_bytes());
    }

    #[test]
    fn test_path_strips_the_query() {
        let r = head("GET /a/b?c=d&e=f HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(r.path(), "/a/b");
    }

    #[test]
    fn test_keep_alive_defaults_match_the_protocol_version() {
        let cases = [
            ("GET / HTTP/1.1\r\n\r\n", true),
            ("GET / HTTP/1.0\r\n\r\n", false),
            ("GET / HTTP/1.1\r\nConnection: close\r\n\r\n", false),
            ("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", true),
            ("GET / HTTP/1.1\r\nConnection: CLOSE\r\n\r\n", false),
        ];
        for (raw, expected) in cases {
            assert_eq!(head(raw).unwrap().wants_keep_alive(), expected, "{raw:?}");
        }
    }

    #[test]
    fn test_response_encoding_is_deterministic_and_ordered() {
        let r = Response::new(200, "OK")
            .header("Server", "nginx")
            .header("Content-Type", "text/html")
            .body(b"hi".to_vec());

        let encoded = String::from_utf8(r.encode()).unwrap();
        assert_eq!(
            encoded,
            "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nhi"
        );
        // Byte-for-byte stable across calls — 17.1.11 depends on this.
        assert_eq!(r.encode(), r.encode());
    }

    #[test]
    fn test_empty_responses_still_carry_a_content_length() {
        // Without it the client must infer framing from connection close,
        // which no modern origin does and which breaks keep-alive.
        let encoded = String::from_utf8(Response::not_found().encode()).unwrap();
        assert!(encoded.contains("Content-Length: 0\r\n"));
        assert!(encoded.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn test_path_traversal_is_refused() {
        let root = std::path::Path::new("/srv/www");
        for attack in [
            "/../etc/passwd",
            "/a/../../etc/passwd",
            "/..",
            // Percent-encoded separators: harmless-looking until the path is
            // decoded, which is why decoding happens before the check.
            "/a/..%2fetc/passwd",
            "/%2e%2e/etc/passwd",
            "/%2E%2E%2Fetc",
            "/C:/windows",
            "/a\\..\\b",
            "/....//etc",
        ] {
            assert!(
                resolve_path(root, attack).is_none(),
                "{attack:?} was not refused"
            );
        }
    }

    #[test]
    fn test_malformed_percent_escapes_are_refused() {
        let root = std::path::Path::new("/srv/www");
        for bad in ["/a%", "/a%2", "/a%zz", "/a%2g"] {
            assert!(resolve_path(root, bad).is_none(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn test_legitimate_percent_encoding_still_resolves() {
        // Refusing every escape would be safe but would diverge from a real
        // origin, which serves files with spaces in their names.
        let root = std::path::Path::new("/srv/www");
        assert_eq!(
            resolve_path(root, "/my%20file.txt").unwrap(),
            root.join("my file.txt")
        );
    }

    #[test]
    fn test_root_serves_the_index() {
        let root = std::path::Path::new("/srv/www");
        assert_eq!(resolve_path(root, "/").unwrap(), root.join("index.html"));
        assert_eq!(resolve_path(root, "").unwrap(), root.join("index.html"));
    }

    #[test]
    fn test_ordinary_paths_resolve_under_the_root() {
        let root = std::path::Path::new("/srv/www");
        assert_eq!(
            resolve_path(root, "/assets/app.css").unwrap(),
            root.join("assets").join("app.css")
        );
    }

    #[test]
    fn test_content_types_cover_a_static_site() {
        assert_eq!(content_type_for("/a/index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type_for("/style.CSS"), "text/css");
        assert_eq!(content_type_for("/logo.png"), "image/png");
        assert_eq!(content_type_for("/noextension"), "application/octet-stream");
        assert_eq!(content_type_for("/weird.xyz"), "application/octet-stream");
    }
}
