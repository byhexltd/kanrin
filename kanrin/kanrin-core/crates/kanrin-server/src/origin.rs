//! Where the front door's content comes from (Phase 17.1.3 – 17.1.5).
//!
//! Two sources, in order of strength:
//!
//! - **Upstream** (17.1.5). The request is forwarded to a real origin
//!   verbatim and its response is streamed back verbatim. The bytes are not
//!   *like* the origin's, they *are* the origin's — header order, casing,
//!   `Date` format, `Server` banner, error pages and all. This is the only
//!   form that satisfies 17.1.11 without maintaining a growing list of
//!   things to imitate.
//! - **Static** (17.1.4). Files from disk, for deployments with no upstream
//!   to borrow. Weaker, because now the header set is ours and has to be
//!   chosen to match something.
//!
//! Both are reached by the same call from the same place, for every client
//! (17.1.3). There is no "content for probers" and no "content for clients",
//! because there is only one content path.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::http::{self, RequestHead, Response};

/// How long to wait on an upstream before giving up.
///
/// Short: a front door that hangs when its upstream is slow is a front door
/// that behaves differently under load than the origin it claims to be.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on a buffered upstream response.
const MAX_UPSTREAM_BYTES: usize = 8 * 1024 * 1024;

/// Where the front door gets its content.
#[derive(Debug, Clone)]
pub enum Origin {
    /// Forward to a real server and return its bytes unchanged.
    Upstream { addr: String },
    /// Serve files from a directory.
    Static { root: PathBuf, server_banner: String },
    /// Nothing configured. Still answers — silence is `D1`.
    Empty,
}

impl Origin {
    /// Produce the response bytes for `head`.
    ///
    /// Infallible by construction: every path returns bytes. An upstream that
    /// is down yields a plausible `502`, because a front door that goes silent
    /// when its backend does is distinguishable from one that does not.
    pub async fn respond(&self, head: &RequestHead, body: &[u8]) -> Vec<u8> {
        match self {
            Self::Upstream { addr } => match fetch_upstream(addr, head, body).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::debug!(error = %e, "upstream unreachable");
                    Response::new(502, "Bad Gateway").encode()
                }
            },
            Self::Static { root, server_banner } => serve_static(root, head, server_banner).await,
            Self::Empty => Response::new(404, "Not Found")
                .header("Server", "nginx")
                .header("Content-Type", "text/html")
                .encode(),
        }
    }
}

/// Forward a request to the upstream origin and return its raw response.
///
/// The request head goes out exactly as it arrived (`RequestHead::raw`).
/// Re-serialising it would reorder and re-case headers, and the upstream's
/// response can depend on both — at which point the response would no longer
/// be the one that origin would really have given this client.
async fn fetch_upstream(addr: &str, head: &RequestHead, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let fetch = async {
        let mut upstream = TcpStream::connect(addr).await?;
        upstream.write_all(&head.raw).await?;
        if !body.is_empty() {
            upstream.write_all(body).await?;
        }
        upstream.flush().await?;

        let mut response = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = upstream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
            if response.len() >= MAX_UPSTREAM_BYTES {
                break;
            }
            // Stop once a complete, length-delimited response has arrived,
            // rather than waiting for the upstream to close — which it will
            // not do on a keep-alive connection.
            if let Some(total) = complete_response_len(&response) {
                response.truncate(total);
                break;
            }
        }
        Ok::<_, anyhow::Error>(response)
    };

    match tokio::time::timeout(UPSTREAM_TIMEOUT, fetch).await {
        Ok(result) => result,
        Err(_) => anyhow::bail!("upstream timed out"),
    }
}

/// Total length of a complete response, if `buf` holds one.
///
/// Only handles the `Content-Length` case; a chunked or connection-delimited
/// response falls through and is bounded by the read loop instead.
fn complete_response_len(buf: &[u8]) -> Option<usize> {
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = std::str::from_utf8(&buf[..head_end]).ok()?;

    let length: usize = head
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })?;

    (buf.len() >= head_end + length).then_some(head_end + length)
}

/// Serve a file from disk.
async fn serve_static(root: &std::path::Path, head: &RequestHead, banner: &str) -> Vec<u8> {
    let not_found = || {
        Response::not_found()
            .header("Server", banner)
            .header("Content-Type", "text/html")
            .encode()
    };

    // A path that escapes the root is *not found*, not *forbidden*: a distinct
    // 403 would confirm that the path exists and that this is a real
    // filesystem behind a real server with something worth protecting.
    let Some(path) = http::resolve_path(root, head.path()) else {
        return not_found();
    };

    match tokio::fs::read(&path).await {
        // Typed from the *resolved* path, not the requested one: `/` resolves
        // to `index.html`, and typing it from the request would serve the
        // site's front page as `application/octet-stream` — which browsers
        // download instead of rendering, and which no real server does.
        Ok(contents) => Response::new(200, "OK")
            .header("Server", banner)
            .header("Content-Type", http::content_type_for(&path.to_string_lossy()))
            .body(contents)
            .encode(),
        Err(_) => not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn request(target: &str) -> RequestHead {
        let raw = format!("GET {target} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        RequestHead::parse(raw.as_bytes()).unwrap()
    }

    /// A stub origin that records what it received and replies with a fixed,
    /// deliberately idiosyncratic response.
    async fn stub_origin(reply: &'static str) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = vec![0u8; 4096];
            let n = socket.read(&mut received).await.unwrap();
            received.truncate(n);
            socket.write_all(reply.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
            received
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn test_upstream_response_is_returned_byte_for_byte() {
        // The point of 17.1.5: odd header order, unusual casing and a
        // non-standard banner all survive, because nothing re-serialises it.
        let reply = "HTTP/1.1 418 I'm a teapot\r\nx-Odd-Case: 1\r\nServer: Apache/2.2\r\n\
                     Content-Length: 5\r\n\r\nbrew!";
        let (addr, handle) = stub_origin(reply).await;

        let origin = Origin::Upstream { addr };
        let response = origin.respond(&request("/"), b"").await;

        assert_eq!(response, reply.as_bytes());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_the_clients_request_reaches_the_origin_unchanged() {
        let (addr, handle) = stub_origin("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;

        let raw = "GET /p?q=1 HTTP/1.1\r\nHost: example.com\r\nZ-Last: 1\r\nA-First: 2\r\n\r\n";
        let head = RequestHead::parse(raw.as_bytes()).unwrap();
        Origin::Upstream { addr }.respond(&head, b"").await;

        let received = handle.await.unwrap();
        assert_eq!(
            received, raw.as_bytes(),
            "header order or casing was rewritten on the way upstream"
        );
    }

    #[tokio::test]
    async fn test_a_dead_upstream_still_answers() {
        // D1: silence is the thing being eliminated. A backend outage must
        // look like a backend outage, not like a closed port.
        let origin = Origin::Upstream {
            // Reserved-for-documentation address; nothing listens.
            addr: "192.0.2.1:9".to_string(),
        };
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            origin.respond(&request("/"), b""),
        )
        .await
        .expect("must not hang");

        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 502 "));
    }

    #[tokio::test]
    async fn test_static_serves_files_and_the_index() {
        let dir = std::env::temp_dir().join(format!("kanrin-origin-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("index.html"), b"<h1>hello</h1>").await.unwrap();

        let origin = Origin::Static {
            root: dir.clone(),
            server_banner: "nginx".into(),
        };

        let response = String::from_utf8(origin.respond(&request("/"), b"").await).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(
            response.contains("Content-Type: text/html; charset=utf-8\r\n"),
            "`/` must be typed from the file it resolves to, not from the request path"
        );
        assert!(response.ends_with("<h1>hello</h1>"));

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn test_a_traversal_attempt_looks_exactly_like_a_missing_file() {
        // A distinct 403 would confirm there is a real filesystem here with
        // something worth protecting.
        let dir = std::env::temp_dir().join(format!("kanrin-trav-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let origin = Origin::Static {
            root: dir.clone(),
            server_banner: "nginx".into(),
        };

        let missing = origin.respond(&request("/definitely-not-here"), b"").await;
        let traversal = origin.respond(&request("/../../etc/passwd"), b"").await;
        assert_eq!(missing, traversal, "the two cases must be indistinguishable");

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn test_an_unconfigured_origin_still_answers() {
        let response = Origin::Empty.respond(&request("/"), b"").await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 404 "));
        assert!(!response.is_empty());
    }

    #[test]
    fn test_complete_response_detection() {
        assert_eq!(complete_response_len(b"HTTP/1.1 200 OK\r\n"), None);
        assert_eq!(
            complete_response_len(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh"),
            None,
            "a partial body is not a complete response"
        );
        let complete = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        assert_eq!(complete_response_len(complete), Some(complete.len()));
        // Trailing bytes belong to the next response, not this one.
        assert_eq!(
            complete_response_len(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiEXTRA"),
            Some(complete.len())
        );
        // Casing varies between origins.
        assert!(
            complete_response_len(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").is_some()
        );
        // Chunked has no length; the read loop bounds it instead.
        assert_eq!(
            complete_response_len(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
            None
        );
    }
}
