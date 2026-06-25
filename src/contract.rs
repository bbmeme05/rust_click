use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// jump_svc → sender 的请求体（语言无关契约，见 jump_svc/docs/senders.md）。
#[derive(Debug, Clone, Deserialize)]
pub struct SendRequest {
    pub url: String,
    #[serde(default)]
    pub ua: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(default)]
    pub max_redirects: u32,
    #[serde(default)]
    pub proxy: String,
}

/// 跳转链中的一跳。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hop {
    pub url: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub server_ip: String,
}

/// sender → jump_svc 的回传体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResponse {
    pub hops: Vec<Hop>,
    pub error: String,
}
