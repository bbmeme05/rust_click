mod fetcher;

use std::sync::Arc;
use std::thread;

use tiny_http::{Header, Method, Response, Server};

use rust_click::contract::SendRequest;
use rust_click::handler::{error_json, handle_send_json};

use crate::fetcher::ReqwestFetcherPool;

fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "18001".to_string());
    let workers: usize = std::env::var("WORKERS")
        .ok()
        .and_then(|w| w.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(64);
    let addr = format!("0.0.0.0:{}", port);

    let server = Arc::new(Server::http(&addr).expect("bind server"));
    let fetcher_pool = Arc::new(ReqwestFetcherPool::pool_from_env());
    println!(
        "rust_click sender listening on {} ({} workers)",
        addr, workers
    );

    let mut guards = Vec::with_capacity(workers);
    for _ in 0..workers {
        let server = server.clone();
        let fetcher_pool = fetcher_pool.clone();
        guards.push(thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &fetcher_pool);
            }
        }));
    }
    for g in guards {
        let _ = g.join();
    }
}

fn handle(mut req: tiny_http::Request, fetcher_pool: &ReqwestFetcherPool) {
    if req.method() != &Method::Post || req.url() != "/send" {
        let _ = req.respond(Response::empty(404));
        return;
    }

    let mut body = Vec::new();
    if req.as_reader().read_to_end(&mut body).is_err() {
        let _ = respond_json(req, &error_json("read body failed"), 500);
        return;
    }

    // 先解析一次拿 proxy 以构建 client；解析失败时 handle_send_json 会再次解析并回传 error。
    let proxy = serde_json::from_slice::<SendRequest>(&body)
        .map(|r| r.proxy)
        .unwrap_or_default();

    let fetcher = match fetcher_pool.fetcher(&proxy) {
        Ok(f) => f,
        Err(e) => {
            let _ = respond_json(
                req,
                &error_json(&format!("build client failed: {}", e)),
                500,
            );
            return;
        }
    };

    let out = handle_send_json(&body, &fetcher);
    let _ = respond_json(req, &out, 200);
}

fn respond_json(req: tiny_http::Request, body: &str, status: u16) -> std::io::Result<()> {
    let header =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("valid header");
    let resp = Response::from_string(body)
        .with_status_code(status)
        .with_header(header);
    req.respond(resp)
}
