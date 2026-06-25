use std::collections::HashMap;
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

        let mut rb = self
            .client
            .get(url)
            .timeout(Duration::from_millis(timeout));
        if !ua.is_empty() {
            rb = rb.header("User-Agent", ua);
        }
        for (k, v) in headers {
            rb = rb.header(k.as_str(), v.as_str());
        }

        let resp = rb.send().map_err(|e| e.to_string())?;

        let status_code = resp.status().as_u16();
        let server_ip = resp
            .remote_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();

        let mut hmap = HashMap::with_capacity(resp.headers().len());
        for (k, v) in resp.headers().iter() {
            hmap.insert(k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string());
        }

        Ok(HopResponse {
            status_code,
            headers: hmap,
            server_ip,
        })
    }
}
