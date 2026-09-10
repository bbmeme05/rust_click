use std::collections::HashMap;

use crate::contract::{Hop, SendRequest, SendResponse};

const DEFAULT_MAX_REDIRECTS: u32 = 5;

/// 单跳响应：由 HopFetcher 产出，与具体 HTTP 库解耦。
pub struct HopResponse {
    pub status_code: u16,
    /// 响应头，key 必须已转小写。
    pub headers: HashMap<String, String>,
    pub server_ip: String,
}

/// HopFetcher 抽象「对一个 URL 发一次 GET」，便于把跟随逻辑与网络实现分离测试。
pub trait HopFetcher {
    fn fetch(
        &self,
        url: &str,
        ua: &str,
        headers: &HashMap<String, String>,
        timeout_ms: u64,
    ) -> Result<HopResponse, String>;
}

/// 纯逻辑：用给定 fetcher 跟随重定向，产出语言无关的跳转链。
/// 停止规则仅为通用规则：非 3xx 停 / 超过 max_redirects 停 / 下一跳非 http(s) scheme 停。
/// 不做任何 IsBlocked / IsMarket / 第三方判定。
pub fn follow_redirects<F: HopFetcher>(fetcher: &F, req: &SendRequest) -> SendResponse {
    let max = if req.max_redirects == 0 {
        DEFAULT_MAX_REDIRECTS
    } else {
        req.max_redirects
    };

    let mut hops: Vec<Hop> = Vec::new();
    let mut error = String::new();
    let mut location = req.url.clone();
    let mut i: u32 = 0;

    while i < max && !location.is_empty() {
        let parsed = match url::Url::parse(&location) {
            Ok(u) => u,
            Err(e) => {
                error = e.to_string();
                break;
            }
        };

        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            // 非 http(s) scheme（market:// intent:// 等）：记录后停，不发请求。
            hops.push(Hop {
                url: location.clone(),
                status_code: 0,
                headers: HashMap::new(),
                server_ip: String::new(),
            });
            location.clear();
            break;
        }

        let resp = match fetcher.fetch(&location, &req.ua, &req.headers, req.timeout_ms) {
            Ok(r) => r,
            Err(e) => {
                error = e;
                break;
            }
        };

        let status = resp.status_code;
        hops.push(Hop {
            url: location.clone(),
            status_code: status,
            headers: resp.headers.clone(),
            server_ip: resp.server_ip,
        });

        if (300..400).contains(&status) {
            let mut next = resp.headers.get("location").cloned().unwrap_or_default();
            if next.starts_with('/') {
                next = format!(
                    "{}://{}{}",
                    parsed.scheme(),
                    parsed.host_str().unwrap_or(""),
                    next
                );
            }
            location = next;
        } else {
            location.clear();
        }

        i += 1;
    }

    if i == max && !location.is_empty() {
        error = "too many redirects".to_string();
    }

    SendResponse { hops, error }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::cell::RefCell;

    struct SeqFetcher {
        resps: RefCell<Vec<HopResponse>>,
        calls: Cell<usize>,
    }

    impl SeqFetcher {
        fn new(resps: Vec<HopResponse>) -> Self {
            Self {
                resps: RefCell::new(resps),
                calls: Cell::new(0),
            }
        }
    }

    impl HopFetcher for SeqFetcher {
        fn fetch(
            &self,
            _url: &str,
            _ua: &str,
            _headers: &HashMap<String, String>,
            _timeout_ms: u64,
        ) -> Result<HopResponse, String> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.resps.borrow_mut().remove(0))
        }
    }

    fn req(url: &str, max_redirects: u32) -> SendRequest {
        SendRequest {
            url: url.to_string(),
            ua: "UA".to_string(),
            headers: HashMap::new(),
            country: String::new(),
            timeout_ms: 5000,
            max_redirects,
            proxy: String::new(),
            fingerprint: String::new(),
        }
    }

    fn hop_resp(status: u16, location: Option<&str>) -> HopResponse {
        let mut headers = HashMap::new();
        if let Some(loc) = location {
            headers.insert("location".to_string(), loc.to_string());
        }
        HopResponse {
            status_code: status,
            headers,
            server_ip: String::new(),
        }
    }

    #[test]
    fn builds_chain_following_redirect() {
        let fetcher = SeqFetcher::new(vec![
            hop_resp(302, Some("/next")),
            hop_resp(200, None),
        ]);

        let out = follow_redirects(&fetcher, &req("https://example.com/start", 5));

        assert_eq!(out.error, "");
        assert_eq!(out.hops.len(), 2);
        assert_eq!(out.hops[0].url, "https://example.com/start");
        assert_eq!(out.hops[0].status_code, 302);
        assert_eq!(out.hops[1].url, "https://example.com/next");
        assert_eq!(out.hops[1].status_code, 200);
    }

    #[test]
    fn stops_on_non_http_scheme_without_sending() {
        let fetcher = SeqFetcher::new(vec![]);

        let out = follow_redirects(&fetcher, &req("market://details?id=com.foo", 5));

        assert_eq!(fetcher.calls.get(), 0);
        assert_eq!(out.hops.len(), 1);
        assert_eq!(out.hops[0].url, "market://details?id=com.foo");
        assert_eq!(out.hops[0].status_code, 0);
    }

    #[test]
    fn too_many_redirects_sets_error() {
        let fetcher = SeqFetcher::new(vec![
            hop_resp(302, Some("https://a.com/")),
            hop_resp(302, Some("https://a.com/")),
        ]);

        let out = follow_redirects(&fetcher, &req("https://a.com/", 2));

        assert_eq!(out.error, "too many redirects");
        assert_eq!(out.hops.len(), 2);
    }
}
