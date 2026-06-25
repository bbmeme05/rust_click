use crate::contract::{SendRequest, SendResponse};
use crate::follow::{follow_redirects, HopFetcher};

/// 处理一次 /send：解析请求 JSON → 跟随重定向 → 序列化响应 JSON。
/// 解析失败时返回 hops 为空、error 非空的合法响应体。
pub fn handle_send_json<F: HopFetcher>(body: &[u8], fetcher: &F) -> String {
    let req: SendRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid request: {}", e)),
    };

    let resp = follow_redirects(fetcher, &req);
    serde_json::to_string(&resp).unwrap_or_else(|e| error_json(&e.to_string()))
}

pub fn error_json(msg: &str) -> String {
    let resp = SendResponse {
        hops: Vec::new(),
        error: msg.to_string(),
    };
    // 固定结构序列化不会失败；兜底返回手写 JSON。
    serde_json::to_string(&resp)
        .unwrap_or_else(|_| format!("{{\"hops\":[],\"error\":\"{}\"}}", msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::SendResponse;
    use crate::follow::HopResponse;
    use std::collections::HashMap;

    struct OkFetcher;

    impl HopFetcher for OkFetcher {
        fn fetch(
            &self,
            _url: &str,
            _ua: &str,
            _headers: &HashMap<String, String>,
            _timeout_ms: u64,
        ) -> Result<HopResponse, String> {
            Ok(HopResponse {
                status_code: 200,
                headers: HashMap::new(),
                server_ip: String::new(),
            })
        }
    }

    #[test]
    fn valid_request_returns_chain_json() {
        let body = br#"{"url":"https://a.com","ua":"UA","timeout_ms":5000,"max_redirects":5}"#;

        let out = handle_send_json(body, &OkFetcher);

        let parsed: SendResponse = serde_json::from_str(&out).expect("valid json");
        assert_eq!(parsed.error, "");
        assert_eq!(parsed.hops.len(), 1);
        assert_eq!(parsed.hops[0].url, "https://a.com");
        assert_eq!(parsed.hops[0].status_code, 200);
    }

    #[test]
    fn invalid_json_returns_error_response() {
        let out = handle_send_json(b"not json", &OkFetcher);

        let parsed: SendResponse = serde_json::from_str(&out).expect("valid json");
        assert!(parsed.hops.is_empty());
        assert!(!parsed.error.is_empty());
    }
}
