//! HTTP fetcher backed by `wreq` (BoringSSL) with JA3 / HTTP-2 emulation.
//!
//! One `wreq::Client` is created per `(proxy, fingerprint)` pair and reused for
//! a bounded number of requests, mirroring the previous reqwest-based pool.
//! Selecting the fingerprint happens in `main` so that a whole redirect chain
//! keeps the same TLS identity.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::fingerprint::{self, Selected};
use crate::follow::{HopFetcher, HopResponse};

const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Shared tokio runtime driving the async `wreq` clients from sync worker threads.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(4)
            .thread_name("rust_click-wreq")
            .build()
            .expect("build tokio runtime")
    })
}

/// A single-hop fetcher holding an impersonating client.
pub struct WreqFetcher {
    client: wreq::Client,
    pub fingerprint: String,
}

impl WreqFetcher {
    pub fn new(proxy: &str, selected: &Selected) -> Result<Self, String> {
        let client = fingerprint::build_client(selected, proxy)?;
        Ok(Self {
            client,
            fingerprint: selected.key(),
        })
    }

    fn from_client(client: wreq::Client, fingerprint: String) -> Self {
        Self { client, fingerprint }
    }
}

struct ClientEntry {
    proxy: String,
    fingerprint: String,
    client: wreq::Client,
    requests: u64,
}

struct ClientPoolState {
    entries: VecDeque<ClientEntry>,
}

/// Process-wide client pool shared by every sender worker.
///
/// The pool key is `(proxy, fingerprint)` so proxy session identity and TLS
/// identity are both preserved across the redirect chain. The pool stays bounded
/// even when callers rotate proxy sessions.
pub struct WreqFetcherPool {
    state: Mutex<ClientPoolState>,
    max_clients: usize,
    max_requests_per_client: u64,
}

impl WreqFetcherPool {
    pub fn pool_from_env() -> Self {
        // 1024 retained `wreq`/BoringSSL clients was the memory ceiling that
        // got the sidecar OOMKilled; 64 keeps the same reuse behaviour with a
        // bounded footprint (a rotating per-request proxy session means the
        // pool rarely hits anyway).
        Self::new(
            env_positive_usize("RUST_CLIENT_POOL_SIZE", 64),
            env_positive_u64("RUST_MAX_REUSED", 32),
        )
    }

    pub fn new(max_clients: usize, max_requests_per_client: u64) -> Self {
        Self {
            state: Mutex::new(ClientPoolState {
                entries: VecDeque::new(),
            }),
            max_clients: max_clients.max(1),
            max_requests_per_client: max_requests_per_client.max(1),
        }
    }

    /// Get a fetcher for `proxy`, reusing the pooled client of the same
    /// `(proxy, fingerprint)` when it has requests left.
    pub fn fetcher(&self, proxy: &str, selected: &Selected) -> Result<WreqFetcher, String> {
        let fingerprint_key = selected.key();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "client pool lock poisoned".to_string())?;

        if let Some(index) = state
            .entries
            .iter()
            .position(|entry| entry.proxy == proxy && entry.fingerprint == fingerprint_key)
        {
            if state.entries[index].requests < self.max_requests_per_client {
                let mut entry = state
                    .entries
                    .remove(index)
                    .expect("client entry index came from the same deque");
                entry.requests += 1;
                let client = entry.client.clone();
                let fingerprint = entry.fingerprint.clone();
                state.entries.push_back(entry);
                return Ok(WreqFetcher::from_client(client, fingerprint));
            }
            state.entries.remove(index);
        }

        let client = fingerprint::build_client(selected, proxy)?;
        if state.entries.len() >= self.max_clients {
            state.entries.pop_front();
        }
        state.entries.push_back(ClientEntry {
            proxy: proxy.to_string(),
            fingerprint: fingerprint_key.clone(),
            client: client.clone(),
            requests: 1,
        });
        Ok(WreqFetcher::from_client(client, fingerprint_key))
    }

    /// Number of pooled clients (test helper).
    pub fn pooled(&self) -> usize {
        self.state.lock().map(|s| s.entries.len()).unwrap_or(0)
    }
}

fn env_positive_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_positive_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

impl HopFetcher for WreqFetcher {
    fn fetch(
        &self,
        url: &str,
        ua: &str,
        headers: &HashMap<String, String>,
        timeout_ms: u64,
    ) -> Result<HopResponse, String> {
        let timeout = if timeout_ms == 0 {
            DEFAULT_TIMEOUT_MS
        } else {
            timeout_ms
        };

        let client = self.client.clone();
        let url = url.to_string();
        // Build the exact header list once, so what we log is what we send.
        let request_headers = build_request_headers(&url, ua, headers);
        let af_request = is_af_url(&url);
        let log_enabled = http_log_enabled();
        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

        if log_enabled {
            log_http_request(request_id, &url, &request_headers, af_request);
        }

        let started = std::time::Instant::now();
        let async_url = url.clone();
        let async_headers = request_headers.clone();

        // A panic here (e.g. the wreq connection-pool assertion) would unwind
        // into the caller and poison tiny_http's internal task pool, after which
        // every worker panics at task_pool.rs and the sidecar stops serving.
        // Contain it and report a normal error so jump_svc can fall back.
        let outcome = catch_unwind(AssertUnwindSafe(move || {
            runtime().block_on(async move {
                let mut rb = client
                    .get(async_url.as_str())
                    .timeout(Duration::from_millis(timeout));
                for (name, value) in &async_headers {
                    rb = rb.header(name.as_str(), value.as_str());
                }

                let resp = rb.send().await.map_err(|e| e.to_string())?;

                let status_code = resp.status().as_u16();
                let server_ip = resp
                    .remote_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_default();

                let mut hmap = HashMap::with_capacity(resp.headers().len());
                for (k, v) in resp.headers().iter() {
                    hmap.insert(
                        k.as_str().to_lowercase(),
                        v.to_str().unwrap_or("").to_string(),
                    );
                }

                // Drain the body so the connection can be reused on the next hop.
                let body = resp.bytes().await.map_err(|e| e.to_string())?;
                Ok::<_, String>((status_code, hmap, server_ip, body))
            })
        }));

        match outcome {
            Ok(Ok((status_code, hmap, server_ip, body))) => {
                if log_enabled {
                    log_http_response(
                        request_id,
                        &url,
                        status_code,
                        &hmap,
                        &server_ip,
                        &body,
                        started.elapsed().as_millis(),
                    );
                }
                Ok(HopResponse {
                    status_code,
                    headers: hmap,
                    server_ip,
                })
            }
            Ok(Err(err)) => {
                if log_enabled {
                    log_http_failure(request_id, &url, &err, started.elapsed().as_millis());
                }
                Err(err)
            }
            Err(payload) => {
                let message = panic_message(payload);
                if log_enabled {
                    log_http_failure(
                        request_id,
                        &url,
                        &format!("panic: {message}"),
                        started.elapsed().as_millis(),
                    );
                }
                Err(format!("request panicked: {message}"))
            }
        }
    }
}

/// Monotonic id correlating request/response log lines.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// AF click hosts: the landing/OneLink domains used by AppsFlyer.
fn is_af_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "appsflyer.com"
        || host.ends_with(".appsflyer.com")
        || host == "onelink.me"
        || host.ends_with(".onelink.me")
}

fn is_af_url(raw: &str) -> bool {
    url::Url::parse(raw)
        .ok()
        .and_then(|parsed| parsed.host_str().map(is_af_host))
        .unwrap_or(false)
}

/// Headers a real browser sends when a user taps an AF click link (top-level
/// navigation). Only added when the task did not supply them.
const AF_NAVIGATION_HEADERS: [(&str, &str); 3] = [
    ("sec-fetch-dest", "document"),
    ("sec-fetch-site", "cross-site"),
    ("sec-fetch-mode", "navigate"),
];

/// Build the exact header list sent on the wire.
///
/// Explicit task headers win over the `ua` argument (same precedence as the
/// previous `rb.header()` order). AF navigation headers are applied last and
/// override task-supplied `sec-fetch-*` values for AF URLs.
fn build_request_headers(
    url: &str,
    ua: &str,
    headers: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(headers.len() + 4);
    if !ua.is_empty() {
        out.push(("User-Agent".to_string(), ua.to_string()));
    }
    for (name, value) in headers {
        out.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        out.push((name.clone(), value.clone()));
    }
    if is_af_url(url) {
        // AF click URLs must always look like a cross-site top-level
        // navigation. The queued task ships its own sec-fetch-* values
        // (upstream sends `sec-fetch-site: none`), so these deliberately
        // override the task headers instead of only filling gaps.
        for (name, value) in AF_NAVIGATION_HEADERS {
            out.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
            out.push((name.to_string(), value.to_string()));
        }
    }
    out
}

/// Full request/response logging is on by default (the operators asked for it);
/// set `RUST_HTTP_LOG=0` to silence it.
fn http_log_enabled() -> bool {
    match std::env::var("RUST_HTTP_LOG") {
        Ok(value) => {
            let value = value.trim().to_ascii_lowercase();
            !(value == "0" || value == "false" || value == "off" || value == "no")
        }
        Err(_) => true,
    }
}

fn body_preview_max() -> usize {
    std::env::var("RUST_HTTP_LOG_BODY_MAX")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(1024)
}

fn headers_to_json(headers: &[(String, String)]) -> serde_json::Value {
    let mut map = serde_json::Map::with_capacity(headers.len());
    for (name, value) in headers {
        map.insert(name.clone(), serde_json::Value::String(value.clone()));
    }
    serde_json::Value::Object(map)
}

fn response_headers_to_json(headers: &HashMap<String, String>) -> serde_json::Value {
    let mut map = serde_json::Map::with_capacity(headers.len());
    for (name, value) in headers {
        map.insert(name.clone(), serde_json::Value::String(value.clone()));
    }
    serde_json::Value::Object(map)
}

fn log_http_request(id: u64, url: &str, headers: &[(String, String)], af: bool) {
    println!(
        "{}",
        serde_json::json!({
            "event": "rust_http_request",
            "id": id,
            "method": "GET",
            "url": url,
            "af": af,
            "headers": headers_to_json(headers),
        })
    );
}

fn log_http_response(
    id: u64,
    url: &str,
    status: u16,
    headers: &HashMap<String, String>,
    server_ip: &str,
    body: &[u8],
    elapsed_ms: u128,
) {
    let kept = body.len().min(body_preview_max());
    println!(
        "{}",
        serde_json::json!({
            "event": "rust_http_response",
            "id": id,
            "url": url,
            "status": status,
            "server_ip": server_ip,
            "headers": response_headers_to_json(headers),
            "body_bytes": body.len(),
            "body_truncated": body.len() > kept,
            "body_preview": String::from_utf8_lossy(&body[..kept]),
            "elapsed_ms": elapsed_ms,
        })
    );
}

fn log_http_failure(id: u64, url: &str, error: &str, elapsed_ms: u128) {
    println!(
        "{}",
        serde_json::json!({
            "event": "rust_http_failure",
            "id": id,
            "url": url,
            "error": error,
            "elapsed_ms": elapsed_ms,
        })
    );
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::WreqFetcherPool;
    use crate::fingerprint::{Registry, Selected};
    use wreq_util::Emulation;

    fn chrome() -> Selected {
        Selected::Community(Emulation::Chrome100)
    }

    #[test]
    fn pool_reuses_then_rotates_a_client() {
        let pool = WreqFetcherPool::new(2, 2);
        let selected = chrome();

        let _ = pool.fetcher("", &selected).expect("first client");
        let _ = pool.fetcher("", &selected).expect("reused client");
        assert_eq!(pool.pooled(), 1);

        let _ = pool.fetcher("", &selected).expect("rotated client");
        assert_eq!(pool.pooled(), 1);
    }

    #[test]
    fn pool_keeps_distinct_proxy_sessions_separate() {
        let pool = WreqFetcherPool::new(4, 32);
        let selected = chrome();

        let _ = pool
            .fetcher("http://proxy.example:8080/session-a", &selected)
            .unwrap();
        let _ = pool
            .fetcher("http://proxy.example:8080/session-b", &selected)
            .unwrap();

        assert_eq!(pool.pooled(), 2);
    }

    #[test]
    fn pool_keeps_distinct_fingerprints_separate() {
        let pool = WreqFetcherPool::new(4, 32);
        let registry = Registry::from_embedded();
        let top = registry.profiles()[0].id.clone();
        let other = registry.profiles()[1].id.clone();

        let a = registry.select_by_id(&top).unwrap();
        let b = registry.select_by_id(&other).unwrap();

        let _ = pool.fetcher("", &a).unwrap();
        let _ = pool.fetcher("", &b).unwrap();

        assert_eq!(pool.pooled(), 2);
    }

    fn hdrs(url: &str, ua: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut map = std::collections::HashMap::new();
        for (k, v) in extra {
            map.insert((*k).to_string(), (*v).to_string());
        }
        super::build_request_headers(url, ua, &map)
    }

    fn value_of<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn af_urls_get_browser_navigation_headers() {
        for url in [
            "https://app.appsflyer.com/1636235979?af_ip=1.2.3.4",
            "https://dramabox.onelink.me/abc",
            "https://x.onelink.me/abc",
        ] {
            let out = hdrs(url, "UA", &[]);
            assert_eq!(value_of(&out, "sec-fetch-dest"), Some("document"), "{url}");
            assert_eq!(value_of(&out, "sec-fetch-site"), Some("cross-site"), "{url}");
            assert_eq!(value_of(&out, "sec-fetch-mode"), Some("navigate"), "{url}");
        }
    }

    #[test]
    fn non_af_urls_do_not_get_navigation_headers() {
        for url in [
            "https://example.com/x",
            "https://click.sng.link/abc",
            "https://notappsflyer.com.evil.test/x",
        ] {
            let out = hdrs(url, "UA", &[]);
            assert!(value_of(&out, "sec-fetch-dest").is_none(), "{url}");
            assert!(value_of(&out, "sec-fetch-mode").is_none(), "{url}");
        }
    }

    #[test]
    fn af_navigation_headers_override_task_values() {
        // 线上队列会带 sec-fetch-site: none，AF 请求必须强制成 cross-site。
        let out = hdrs(
            "https://x.onelink.me/abc",
            "UA",
            &[
                ("sec-fetch-site", "none"),
                ("sec-fetch-mode", "no-cors"),
                ("sec-fetch-dest", "empty"),
            ],
        );
        assert_eq!(value_of(&out, "sec-fetch-site"), Some("cross-site"));
        assert_eq!(value_of(&out, "sec-fetch-mode"), Some("navigate"));
        assert_eq!(value_of(&out, "sec-fetch-dest"), Some("document"));
        for name in ["sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"] {
            assert_eq!(out.iter().filter(|(k, _)| k == name).count(), 1, "{name}");
        }
    }

    #[test]
    fn non_af_urls_keep_task_supplied_sec_fetch_values() {
        let out = hdrs(
            "https://example.com/x",
            "UA",
            &[("sec-fetch-site", "none"), ("sec-fetch-mode", "no-cors")],
        );
        assert_eq!(value_of(&out, "sec-fetch-site"), Some("none"));
        assert_eq!(value_of(&out, "sec-fetch-mode"), Some("no-cors"));
        assert!(value_of(&out, "sec-fetch-dest").is_none());
    }

    #[test]
    fn ua_argument_is_overridden_by_explicit_user_agent_header() {
        let out = hdrs("https://example.com/x", "fallback-ua", &[("user-agent", "task-ua")]);
        let agents: Vec<&str> = out
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(agents, vec!["task-ua"]);
    }
}
