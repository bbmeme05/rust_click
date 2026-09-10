use std::sync::Arc;
use std::thread;

use tiny_http::{Header, Method, Response, Server};

use rust_click::contract::SendRequest;
use rust_click::fetcher::WreqFetcherPool;
use rust_click::fingerprint::Registry;
use rust_click::handler::{error_json, handle_send_parsed};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--list") {
        list_profiles();
        return;
    }

    if let Some(index) = args.iter().position(|a| a == "--verify") {
        let url = args.get(index + 1).map(String::as_str);
        let only = args.get(index + 2).map(String::as_str);
        if let Err(err) = rust_click::verify::run(url, only) {
            eprintln!("verify failed: {err}");
            std::process::exit(1);
        }
        return;
    }

    run_server();
}

fn list_profiles() {
    let registry = Registry::from_embedded();
    println!("{} collected fingerprint profile(s)", registry.len());
    println!(
        "{:<6} {:>6}  {:<46} {:<20} {}",
        "id", "count", "ja4", "curves", "chrome"
    );
    for profile in registry.profiles() {
        println!(
            "{:<6} {:>6}  {:<46} {:<20} {}",
            profile.id,
            profile.count,
            profile.ja4,
            profile
                .tls
                .curves
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("-"),
            profile.chrome
        );
    }
}

fn run_server() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "18001".to_string());
    let workers: usize = std::env::var("WORKERS")
        .ok()
        .and_then(|w| w.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(64);
    let addr = format!("0.0.0.0:{}", port);

    let server = Arc::new(Server::http(&addr).expect("bind server"));
    let fetcher_pool = Arc::new(WreqFetcherPool::pool_from_env());
    let registry = Arc::new(Registry::from_embedded());
    println!(
        "rust_click sender listening on {} ({} workers, {} fingerprint profiles)",
        addr,
        workers,
        registry.len()
    );

    let mut guards = Vec::with_capacity(workers);
    for _ in 0..workers {
        let server = server.clone();
        let fetcher_pool = fetcher_pool.clone();
        let registry = registry.clone();
        guards.push(thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &fetcher_pool, &registry);
            }
        }));
    }
    for guard in guards {
        let _ = guard.join();
    }
}

fn handle(mut req: tiny_http::Request, fetcher_pool: &WreqFetcherPool, registry: &Registry) {
    if req.method() != &Method::Post || req.url() != "/send" {
        let _ = req.respond(Response::empty(404));
        return;
    }

    let mut body = Vec::new();
    if req.as_reader().read_to_end(&mut body).is_err() {
        let _ = respond_json(req, &error_json("read body failed"), 500);
        return;
    }

    let parsed: SendRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(err) => {
            let _ = respond_json(req, &error_json(&format!("invalid request: {}", err)), 200);
            return;
        }
    };

    // Pick the TLS identity once and keep it for the whole redirect chain.
    let selected = if parsed.fingerprint.is_empty() {
        registry.select(&parsed.ua)
    } else {
        registry
            .select_by_id(&parsed.fingerprint)
            .unwrap_or_else(|| registry.select(&parsed.ua))
    };

    let fetcher = match fetcher_pool.fetcher(&parsed.proxy, &selected) {
        Ok(fetcher) => fetcher,
        Err(err) => {
            let _ = respond_json(
                req,
                &error_json(&format!("build client failed: {}", err)),
                500,
            );
            return;
        }
    };

    if std::env::var("RUST_FINGERPRINT_LOG").is_ok() {
        println!("fingerprint={} ua={}", selected.describe(), parsed.ua);
    }

    let out = handle_send_parsed(&parsed, &fetcher);
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
