//! The single code path every connection takes (Phase 17.1.2, 17.1.6, 17.1.7).
//!
//! This module exists to close `D1`–`D7` from the divergence audit
//! (`DESIGN-EVASION.md` §3a). The rule it enforces is narrow and absolute:
//!
//! > Every connection that completes TLS is served as HTTP, by the same code,
//! > in the same order, with the same timing — and *then*, if the request
//! > happened to carry a valid authenticator, the connection is upgraded.
//!
//! The ordering is the whole point. Reality (**T3**) was broken because
//! authentication selected *which stack answered*; a prober could tell the
//! branches apart without ever holding a key. Here authentication selects
//! nothing about the answer. It is a property *discovered* about a request
//! that was going to be served identically either way, and it changes only
//! what happens after the response has already gone out.
//!
//! What a prober can therefore learn by probing: that this is a web server.

use std::time::{Duration, Instant};

use kanrin_protocol::crypto;

use crate::http::RequestHead;

/// Header carrying the tunnel authenticator.
///
/// A cookie rather than a bespoke header: an unrecognised header name is
/// itself a small anomaly, while an opaque cookie on a request is the single
/// most ordinary thing on the web.
pub const AUTH_COOKIE: &str = "sid";

/// Minimum time from accepting a request to emitting its response.
///
/// Not a rate limit — a *floor*. `D4`: the authenticated path does real work
/// (registry insert, forwarder registration) that the unauthenticated path
/// does not, and that difference is measurable from off-path. Holding every
/// response until the floor hides the difference underneath it, provided the
/// floor exceeds the work. 25 ms is comfortably above both and well inside
/// the noise of any real origin's response time.
pub const RESPONSE_FLOOR: Duration = Duration::from_millis(25);

/// Jitter added on top of the floor, so responses do not all land on exactly
/// the same delay — a suspiciously constant response time is its own signal.
pub const RESPONSE_JITTER: Duration = Duration::from_millis(15);

/// What the front door concluded about a request, *after* deciding how to
/// answer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// An ordinary web request. Serve it and keep going.
    Web,
    /// The request carried a valid authenticator. Serve it exactly as if it
    /// had not, then hand the connection to the tunnel.
    Tunnel,
}

/// Build the request a client sends to enter the tunnel.
///
/// Shaped as an unremarkable page load — the authenticator rides in a cookie
/// beside whatever else a browser would send. What makes this work is not
/// that the request is clever, but that the server answers it the same way it
/// answers any other, so there is nothing for a prober to compare against.
pub fn admission_request(host: &str, target: &str, token: &str) -> Vec<u8> {
    format!(
        "GET {target} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Accept-Language: en-US,en;q=0.9\r\n\
         Accept-Encoding: gzip, deflate, br\r\n\
         Cookie: {AUTH_COOKIE}={token}\r\n\
         Connection: keep-alive\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Validates tunnel authenticators presented on ordinary-looking requests.
///
/// The token is `HMAC-SHA256(password_key, timestamp || nonce)`, sent as
/// `timestamp:nonce:mac` — all base16, so it reads as an ordinary opaque
/// session cookie.
pub struct Admitter {
    key: [u8; 32],
    /// Accepted clock skew. Bounds how long a captured cookie stays usable.
    max_age: Duration,
    /// Nonces already spent inside the window, so a captured cookie cannot be
    /// replayed even within it.
    seen: parking_lot::Mutex<Vec<(u64, [u8; 16])>>,
}

impl Admitter {
    pub fn new(password: &str) -> Self {
        let mut key = [0u8; 32];
        let derived = crypto::mac_sha256(&[0u8; 32], &[b"kanrin-frontdoor", password.as_bytes()]);
        key.copy_from_slice(&derived);
        Self {
            key,
            max_age: Duration::from_secs(120),
            seen: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Mint an authenticator. Used by the client, and by tests.
    pub fn mint(&self, now_secs: u64) -> String {
        let nonce: [u8; 16] = crypto::random_bytes();
        let mac = self.compute(now_secs, &nonce);
        format!("{now_secs:x}:{}:{}", hex(&nonce), hex(&mac))
    }

    fn compute(&self, timestamp: u64, nonce: &[u8; 16]) -> [u8; 32] {
        crypto::mac_sha256(&self.key, &[b"kanrin-admit", &timestamp.to_be_bytes(), nonce])
    }

    /// Decide whether a request carries a valid authenticator.
    ///
    /// Every failure returns [`Admission::Web`] — never an error. There is no
    /// "rejected" state to observe, because a rejected authenticator and an
    /// absent one must lead to the same bytes on the wire.
    pub fn admit(&self, head: &RequestHead, now_secs: u64) -> Admission {
        let Some(token) = cookie_value(head.header("cookie").unwrap_or(""), AUTH_COOKIE) else {
            return Admission::Web;
        };

        let mut parts = token.split(':');
        let (Some(ts), Some(nonce), Some(mac), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Admission::Web;
        };

        let (Ok(timestamp), Some(nonce), Some(mac)) = (
            u64::from_str_radix(ts, 16),
            unhex::<16>(nonce),
            unhex::<32>(mac),
        ) else {
            return Admission::Web;
        };

        if now_secs.abs_diff(timestamp) > self.max_age.as_secs() {
            return Admission::Web;
        }

        if !crypto::constant_time_eq(&self.compute(timestamp, &nonce), &mac) {
            return Admission::Web;
        }

        // Valid, but single-use: otherwise anyone who captured the cookie
        // could open their own tunnel with it inside the window.
        let mut seen = self.seen.lock();
        seen.retain(|(t, _)| now_secs.abs_diff(*t) <= self.max_age.as_secs());
        if seen.iter().any(|(_, n)| n == &nonce) {
            return Admission::Web;
        }
        seen.push((timestamp, nonce));

        Admission::Tunnel
    }
}

/// Extract one cookie's value from a `Cookie:` header.
fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.trim() == name).then(|| v.trim())
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Holds a response until the timing floor has elapsed (17.1.7).
///
/// Started when the request is accepted, awaited just before the response is
/// written, so the delay absorbs whatever work happened in between rather
/// than being added to it.
pub struct ResponseTimer {
    started: Instant,
    target: Duration,
}

impl ResponseTimer {
    pub fn start() -> Self {
        Self::with_floor(RESPONSE_FLOOR, RESPONSE_JITTER)
    }

    pub fn with_floor(floor: Duration, jitter: Duration) -> Self {
        let extra = if jitter.is_zero() {
            Duration::ZERO
        } else {
            Duration::from_nanos(rand::random::<u64>() % jitter.as_nanos().max(1) as u64)
        };
        Self {
            started: Instant::now(),
            target: floor + extra,
        }
    }

    /// How long is still owed. Zero once the floor has passed.
    pub fn remaining(&self) -> Duration {
        self.target.saturating_sub(self.started.elapsed())
    }

    pub async fn wait(&self) {
        let remaining = self.remaining();
        if !remaining.is_zero() {
            tokio::time::sleep(remaining).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn request_with_cookie(cookie: &str) -> RequestHead {
        let raw = format!("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: {cookie}\r\n\r\n");
        RequestHead::parse(raw.as_bytes()).unwrap()
    }

    fn plain_request() -> RequestHead {
        RequestHead::parse(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap()
    }

    #[test]
    fn test_a_valid_authenticator_admits() {
        let a = Admitter::new("correct horse");
        let token = a.mint(NOW);
        assert_eq!(a.admit(&request_with_cookie(&format!("sid={token}")), NOW), Admission::Tunnel);
    }

    #[test]
    fn test_an_ordinary_request_is_just_web() {
        let a = Admitter::new("correct horse");
        assert_eq!(a.admit(&plain_request(), NOW), Admission::Web);
    }

    #[test]
    fn test_the_authenticator_survives_ordinary_cookie_jars() {
        // Real browsers send several cookies in one header; requiring ours to
        // be alone would make the request unlike any real one.
        let a = Admitter::new("pw");
        let token = a.mint(NOW);
        let jar = format!("_ga=GA1.2.1; sid={token}; theme=dark");
        assert_eq!(a.admit(&request_with_cookie(&jar), NOW), Admission::Tunnel);
    }

    #[test]
    fn test_every_kind_of_bad_token_is_indistinguishable_from_no_token() {
        // The core invariance property: there is no "rejected" outcome, so a
        // prober cannot learn anything by varying the cookie.
        let a = Admitter::new("pw");
        let valid = a.mint(NOW);

        let mut tampered = valid.clone();
        tampered.pop();
        tampered.push('0');

        for cookie in [
            "sid=".to_string(),
            "sid=garbage".to_string(),
            "sid=zz:zz:zz".to_string(),
            format!("sid={tampered}"),
            format!("sid={valid}:extra"),
            format!("othercookie={valid}"),
            format!("sid={}", hex(&[0u8; 48])),
        ] {
            assert_eq!(
                a.admit(&request_with_cookie(&cookie), NOW),
                Admission::Web,
                "leaked information for {cookie:?}"
            );
        }
    }

    #[test]
    fn test_a_token_minted_under_another_password_does_not_admit() {
        let mine = Admitter::new("mine");
        let theirs = Admitter::new("theirs");
        let token = theirs.mint(NOW);
        assert_eq!(mine.admit(&request_with_cookie(&format!("sid={token}")), NOW), Admission::Web);
    }

    #[test]
    fn test_stale_tokens_expire() {
        let a = Admitter::new("pw");
        let token = a.mint(NOW);
        let later = NOW + a.max_age.as_secs() + 1;
        assert_eq!(a.admit(&request_with_cookie(&format!("sid={token}")), later), Admission::Web);
    }

    #[test]
    fn test_future_dated_tokens_are_bounded_too() {
        // Skew in both directions, or a token minted far in the future would
        // be usable indefinitely.
        let a = Admitter::new("pw");
        let token = a.mint(NOW + 10_000);
        assert_eq!(a.admit(&request_with_cookie(&format!("sid={token}")), NOW), Admission::Web);
    }

    #[test]
    fn test_a_captured_token_cannot_be_replayed() {
        let a = Admitter::new("pw");
        let cookie = format!("sid={}", a.mint(NOW));
        assert_eq!(a.admit(&request_with_cookie(&cookie), NOW), Admission::Tunnel);
        assert_eq!(
            a.admit(&request_with_cookie(&cookie), NOW),
            Admission::Web,
            "a replayed token must be as inert as a wrong one"
        );
    }

    #[test]
    fn test_the_replay_cache_does_not_grow_without_bound() {
        let a = Admitter::new("pw");
        for i in 0..100 {
            let token = a.mint(NOW + i);
            a.admit(&request_with_cookie(&format!("sid={token}")), NOW + i);
        }
        // Entries outside the window are dropped as new ones arrive.
        let far_future = NOW + 100_000;
        let token = a.mint(far_future);
        a.admit(&request_with_cookie(&format!("sid={token}")), far_future);
        assert_eq!(a.seen.lock().len(), 1);
    }

    #[test]
    fn test_cookie_parsing_handles_the_shapes_browsers_send() {
        assert_eq!(cookie_value("sid=abc", "sid"), Some("abc"));
        assert_eq!(cookie_value("a=1; sid=abc; b=2", "sid"), Some("abc"));
        assert_eq!(cookie_value("a=1;sid=abc", "sid"), Some("abc"));
        assert_eq!(cookie_value("a=1", "sid"), None);
        assert_eq!(cookie_value("", "sid"), None);
        assert_eq!(cookie_value("sidx=abc", "sid"), None);
    }

    #[test]
    fn test_the_admission_request_is_shaped_like_a_page_load() {
        let a = Admitter::new("pw");
        let raw = admission_request("example.com", "/", &a.mint(NOW));
        let head = RequestHead::parse(&raw).expect("must parse as ordinary HTTP");

        assert_eq!(head.method, "GET");
        assert_eq!(head.version, "HTTP/1.1");
        assert!(head.header("user-agent").unwrap().contains("Mozilla/5.0"));
        assert!(head.header("accept").unwrap().starts_with("text/html"));
        assert!(head.wants_keep_alive(), "a browser would keep the connection");
        assert_eq!(a.admit(&head, NOW), Admission::Tunnel);
    }

    #[test]
    fn test_the_admission_request_carries_no_custom_header() {
        // An unrecognised header name is a small anomaly all by itself; the
        // authenticator must hide among things browsers already send.
        let a = Admitter::new("pw");
        let raw = admission_request("example.com", "/", &a.mint(NOW));
        let head = RequestHead::parse(&raw).unwrap();

        for name in head.headers.keys() {
            assert!(
                !name.starts_with("x-") && !name.contains("kanrin"),
                "bespoke header leaked: {name}"
            );
        }
    }

    #[test]
    fn test_hex_roundtrip() {
        let bytes: [u8; 16] = crypto::random_bytes();
        assert_eq!(unhex::<16>(&hex(&bytes)), Some(bytes));
        assert_eq!(unhex::<16>("short"), None);
        assert_eq!(unhex::<16>(&"g".repeat(32)), None);
    }

    #[tokio::test]
    async fn test_the_timer_absorbs_work_rather_than_adding_to_it() {
        // A response that took 40 ms to produce must not then wait another
        // 25 ms; the floor is a floor, not a tax.
        let timer = ResponseTimer::with_floor(Duration::from_millis(25), Duration::ZERO);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(timer.remaining(), Duration::ZERO);

        let started = Instant::now();
        timer.wait().await;
        assert!(started.elapsed() < Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_a_fast_response_is_held_to_the_floor() {
        let timer = ResponseTimer::with_floor(Duration::from_millis(30), Duration::ZERO);
        let started = Instant::now();
        timer.wait().await;
        assert!(
            started.elapsed() >= Duration::from_millis(25),
            "a cheap response leaked its cheapness"
        );
    }

    #[test]
    fn test_jitter_spreads_the_delay() {
        // A perfectly constant response time is itself a signature.
        let targets: std::collections::HashSet<Duration> = (0..50)
            .map(|_| {
                ResponseTimer::with_floor(Duration::from_millis(25), Duration::from_millis(15))
                    .target
            })
            .collect();
        assert!(targets.len() > 10, "jitter produced only {} values", targets.len());
        assert!(targets.iter().all(|t| *t >= Duration::from_millis(25)));
        assert!(targets.iter().all(|t| *t < Duration::from_millis(40)));
    }
}
