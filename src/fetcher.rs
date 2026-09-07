use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::redirect::Policy;

use rust_click::follow::{HopFetcher, HopResponse};

const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// 用 reqwest 原生 HTTP 栈发送单跳请求（关闭自动重定向，由 follow_redirects 手动跟）。
/// 整条链复用同一个 client（含 proxy 设置）。
pub struct ReqwestFetcher {
    client: Client,
}

struct ClientEntry {
    proxy: String,
    client: Client,
    requests: u64,
}

struct ClientPoolState {
    entries: VecDeque<ClientEntry>,
}

/// Process-wide client pool shared by every sender worker.
///
/// The proxy URL is part of the key so proxy session identity is preserved. A
/// caller that generates a unique proxy session for every request will still
/// rotate clients, but the pool remains bounded and direct requests can reuse
/// their transport.
pub struct ReqwestFetcherPool {
    state: Mutex<ClientPoolState>,
    max_clients: usize,
    max_requests_per_client: u64,
}

impl ReqwestFetcher {
    pub fn new(proxy: &str) -> Result<Self, String> {
        let mut builder = Client::builder().redirect(Policy::none());
        if !proxy.is_empty() {
            let p = reqwest::Proxy::all(proxy).map_err(|e| e.to_string())?;
            builder = builder.proxy(p);
        }
        let client = builder.build().map_err(|e| e.to_string())?;
        Ok(Self { client })
    }

    fn from_client(client: Client) -> Self {
        Self { client }
    }
}

impl ReqwestFetcherPool {
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

    pub fn fetcher(&self, proxy: &str) -> Result<ReqwestFetcher, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "client pool lock poisoned".to_string())?;

        if let Some(index) = state.entries.iter().position(|entry| entry.proxy == proxy) {
            if state.entries[index].requests < self.max_requests_per_client {
                let mut entry = state
                    .entries
                    .remove(index)
                    .expect("client entry index came from the same deque");
                entry.requests += 1;
                let client = entry.client.clone();
                state.entries.push_back(entry);
                return Ok(ReqwestFetcher::from_client(client));
            }
            state.entries.remove(index);
        }

        let client = ReqwestFetcher::new(proxy)?.client;
        if state.entries.len() >= self.max_clients {
            state.entries.pop_front();
        }
        state.entries.push_back(ClientEntry {
            proxy: proxy.to_string(),
            client: client.clone(),
            requests: 1,
        });
        Ok(ReqwestFetcher::from_client(client))
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

impl HopFetcher for ReqwestFetcher {
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

        let mut rb = self.client.get(url).timeout(Duration::from_millis(timeout));
        if !ua.is_empty() {
            rb = rb.header("User-Agent", ua);
        }
        for (k, v) in headers {
            rb = rb.header(k.as_str(), v.as_str());
        }

        let mut resp = rb.send().map_err(|e| e.to_string())?;

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

        // Drain the body without retaining it so reqwest can reuse the
        // underlying keep-alive connection on the next hop/request.
        io::copy(&mut resp, &mut io::sink()).map_err(|e| e.to_string())?;

        Ok(HopResponse {
            status_code,
            headers: hmap,
            server_ip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ReqwestFetcherPool;

    #[test]
    fn pool_reuses_then_rotates_a_client() {
        let pool = ReqwestFetcherPool::new(2, 2);

        let _ = pool.fetcher("").expect("first client");
        let _ = pool.fetcher("").expect("reused client");
        assert_eq!(pool.state.lock().unwrap().entries[0].requests, 2);

        let _ = pool.fetcher("").expect("rotated client");
        assert_eq!(pool.state.lock().unwrap().entries[0].requests, 1);
    }

    #[test]
    fn pool_keeps_distinct_proxy_sessions_separate() {
        let pool = ReqwestFetcherPool::new(2, 32);

        let _ = pool.fetcher("http://proxy.example:8080/session-a").unwrap();
        let _ = pool.fetcher("http://proxy.example:8080/session-b").unwrap();

        let state = pool.state.lock().unwrap();
        assert_eq!(state.entries.len(), 2);
        assert_eq!(state.entries[0].proxy, "http://proxy.example:8080/session-a");
        assert_eq!(state.entries[1].proxy, "http://proxy.example:8080/session-b");
    }
}
