//! `--verify` self-check: replay each collected profile against a JA3/JA4 echo
//! service and compare what the server actually observed with the stored profile.
//!
//! Because Chrome permutes TLS extension order, the raw JA3 string is expected to
//! differ on every connection; the comparison therefore uses
//! [`fingerprint::normalize_ja3`] (cipher/extension *sets*) plus JA4.

use crate::fetcher::runtime;
use crate::fingerprint::{self, Registry, Selected};

const DEFAULT_ECHO_URL: &str = "https://tls.peet.ws/api/all";

/// Entry point for `rust_click --verify [url] [profile_id]`.
pub fn run(url: Option<&str>, only: Option<&str>) -> Result<(), String> {
    let url = url.unwrap_or(DEFAULT_ECHO_URL);
    let registry = Registry::from_embedded();

    let profiles: Vec<_> = match only {
        Some(id) => vec![registry
            .get(id)
            .cloned()
            .ok_or_else(|| format!("unknown profile id {id:?})"))?],
        None => registry.profiles().to_vec(),
    };

    println!(
        "verifying {} collected profile(s) against {url}",
        profiles.len()
    );

    let mut matched = 0usize;
    let mut failed = 0usize;
    for profile in &profiles {
        let selected = Selected::Collected(profile.clone());
        let client = match fingerprint::build_client(&selected, "") {
            Ok(client) => client,
            Err(err) => {
                println!("--- {} build failed: {err}", profile.id);
                failed += 1;
                continue;
            }
        };
        let body = runtime().block_on(async {
            client
                .get(url)
                .timeout(std::time::Duration::from_secs(20))
                .send()
                .await
                .map_err(|e| e.to_string())?
                .text()
                .await
                .map_err(|e| e.to_string())
        });
        let body = match body {
            Ok(body) => body,
            Err(err) => {
                println!("--- {} request failed: {err}", profile.id);
                failed += 1;
                continue;
            }
        };

        let value: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        let observed_ja3 = json_str(&value, &["tls", "ja3"]).unwrap_or("-");
        let observed_ja4 = json_str(&value, &["tls", "ja4"]).unwrap_or("-");
        let observed_akamai = json_str(&value, &["http2", "akamai_fingerprint"]).unwrap_or("-");

        let ja4_match = observed_ja4 == profile.ja4;
        let ja3_shape_match = fingerprint::normalize_ja3(observed_ja3)
            == fingerprint::normalize_ja3(&profile.ja3);
        let h2_match = !profile.h2.is_empty() && observed_akamai == profile.h2;
        if ja4_match || ja3_shape_match {
            matched += 1;
        }

        println!(
            "--- {} chrome={} count={} ja4_match={} ja3_shape_match={} h2_match={}",
            profile.id, profile.chrome, profile.count, ja4_match, ja3_shape_match, h2_match
        );
        println!("    expected ja4 : {}", profile.ja4);
        println!("    observed ja4 : {}", observed_ja4);
        println!("    observed ja3 : {}", observed_ja3);
        println!("    observed h2  : {}", observed_akamai);
        println!("    expected h2  : {}", profile.h2);
    }

    println!(
        "\nmatched {matched}/{} ({} failed to reach the echo service)",
        profiles.len(),
        failed
    );
    Ok(())
}

fn json_str<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    let text = current.as_str()?;
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::json_str;

    #[test]
    fn json_str_walks_nested_paths() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"tls":{"ja3":"771,1,2,3,4"},"http2":{"akamai_fingerprint":""}}"#)
                .unwrap();
        assert_eq!(json_str(&value, &["tls", "ja3"]), Some("771,1,2,3,4"));
        assert_eq!(json_str(&value, &["http2", "akamai_fingerprint"]), None);
        assert_eq!(json_str(&value, &["missing", "ja3"]), None);
    }
}
