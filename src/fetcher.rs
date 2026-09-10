//! HTTP fetcher backed by `wreq` (BoringSSL) with JA3 / HTTP-2 emulation.
//!
//! One `wreq::Client` is created per `(proxy, fingerprint)` pair and reused for
//! a bounded number of requests, mirroring the previous reqwest-based pool.
//! Selecting the fingerprint happens in `main` so that a whole redirect chain
//! keeps the same TLS identity.

use std::collections::HashMap;
use std::collections::VecDeque;
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
        Self::new(
            env_positive_usize("RUST_CLIENT_POOL_SIZE", 1024),
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
        let ua = ua.to_string();
        let headers = headers.clone();

        runtime().block_on(async move {
            let mut rb = client
                .get(url.as_str())
                .timeout(Duration::from_millis(timeout));
            if !ua.is_empty() {
                rb = rb.header("User-Agent", ua.as_str());
            }
            for (k, v) in headers {
                rb = rb.header(k.as_str(), v.as_str());
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
            let _ = resp.bytes().await.map_err(|e| e.to_string())?;

            Ok(HopResponse {
                status_code,
                headers: hmap,
                server_ip,
            })
        })
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
}
