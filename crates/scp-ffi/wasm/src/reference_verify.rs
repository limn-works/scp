//! Reference attestation verification via browser Fetch API (§3.5.2).
//!
//! Verifies Reference-class attestations (`SignedPost`, `DnsRecord`) by fetching
//! external URLs from the browser. This is WASM-only code that uses
//! `web_sys::fetch` — it does NOT depend on `scp-core`.
//!
//! - **`SignedPost`**: fetches the post URL and checks that the response body
//!   contains both the DID string and the nonce.
//! - **`DnsRecord`**: queries Cloudflare DNS-over-HTTPS for TXT records at
//!   `_scp-verify.<domain>` and checks that one contains the DID string.
//!
//! Both methods return `{ "verified": bool, "error"?: string }` as JSON.
//!
//! # CORS limitations
//!
//! Browser fetch is subject to CORS policy. `SignedPost` verification may fail
//! if the target platform does not allow cross-origin requests. DNS-over-HTTPS
//! via Cloudflare supports CORS. All fetch failures are reported gracefully
//! in the `error` field rather than throwing.
//!
//! See spec §3.5.2 for the verification protocol.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, future_to_promise};

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Parsed attestation input for reference verification.
#[derive(serde::Deserialize)]
struct ReferenceAttestationInput {
    /// The DID that issued this attestation.
    issuer_did: String,
    /// The verification method: `"signed_post"` or `"dns_record"`.
    method: String,
    /// Method-specific proof data (JSON string or nested object).
    proof: serde_json::Value,
}

/// Proof fields for `SignedPost` verification.
#[derive(serde::Deserialize)]
struct SignedPostProof {
    /// URL of the post to fetch.
    post_url: String,
    /// Nonce that must appear in the post body alongside the DID.
    nonce: String,
}

/// Proof fields for `DnsRecord` verification.
#[derive(serde::Deserialize)]
struct DnsRecordProof {
    /// Domain to check (e.g., `"example.com"`).
    domain: String,
    /// Record name prefix (e.g., `"_scp-verify"`). If absent, defaults to
    /// `"_scp-verify"`.
    #[serde(default = "default_record_name")]
    record_name: String,
}

fn default_record_name() -> String {
    "_scp-verify".to_owned()
}

/// Cloudflare DNS-over-HTTPS JSON response shape.
#[derive(serde::Deserialize)]
struct DohResponse {
    /// DNS answer records.
    #[serde(default)]
    #[allow(clippy::struct_field_names)]
    #[serde(rename = "Answer")]
    answer: Vec<DohAnswer>,
}

/// A single DNS answer record from the DNS-over-HTTPS JSON response.
#[derive(serde::Deserialize)]
struct DohAnswer {
    /// Record data (e.g., the TXT record content).
    data: String,
}

// ---------------------------------------------------------------------------
// Result helper
// ---------------------------------------------------------------------------

/// Builds a JSON result string: `{ "verified": bool, "error"?: string }`.
fn result_json(verified: bool, error: Option<&str>) -> String {
    error.map_or_else(
        || {
            serde_json::json!({
                "verified": verified,
            })
            .to_string()
        },
        |e| {
            serde_json::json!({
                "verified": verified,
                "error": e,
            })
            .to_string()
        },
    )
}

// ---------------------------------------------------------------------------
// fetch_url — browser Fetch API wrapper
// ---------------------------------------------------------------------------

/// Fetches a URL using the browser Fetch API and returns the response text.
///
/// Uses `RequestMode::Cors` by default. Returns the response body as a string,
/// or an error message if the fetch fails (network error, CORS block, non-2xx
/// status).
#[allow(clippy::future_not_send)] // WASM futures use Rc (JsFuture), inherently !Send
async fn fetch_url(url: &str) -> Result<String, String> {
    let opts = web_sys::RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(web_sys::RequestMode::Cors);

    let request = web_sys::Request::new_with_str_and_init(url, &opts)
        .map_err(|e| format!("failed to create request for {url}: {e:?}"))?;

    let window = web_sys::window().ok_or_else(|| "no global window object".to_owned())?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("fetch failed for {url}: {e:?}"))?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| "fetch response is not a Response object".to_owned())?;

    if !resp.ok() {
        return Err(format!("fetch returned HTTP {} for {url}", resp.status()));
    }

    let text_promise = resp
        .text()
        .map_err(|e| format!("failed to read response text: {e:?}"))?;
    let text_value = JsFuture::from(text_promise)
        .await
        .map_err(|e| format!("failed to await response text: {e:?}"))?;

    text_value
        .as_string()
        .ok_or_else(|| "response text is not a string".to_owned())
}

/// Fetches a URL with custom headers using the browser Fetch API.
///
/// Same as [`fetch_url`] but allows setting request headers (needed for
/// DNS-over-HTTPS `Accept: application/dns-json`).
#[allow(clippy::future_not_send)] // WASM futures use Rc (JsFuture), inherently !Send
async fn fetch_url_with_headers(url: &str, headers: &[(&str, &str)]) -> Result<String, String> {
    let opts = web_sys::RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(web_sys::RequestMode::Cors);

    let request = web_sys::Request::new_with_str_and_init(url, &opts)
        .map_err(|e| format!("failed to create request for {url}: {e:?}"))?;

    let req_headers = request.headers();
    for (key, value) in headers {
        req_headers
            .set(key, value)
            .map_err(|e| format!("failed to set header {key}: {e:?}"))?;
    }

    let window = web_sys::window().ok_or_else(|| "no global window object".to_owned())?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("fetch failed for {url}: {e:?}"))?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| "fetch response is not a Response object".to_owned())?;

    if !resp.ok() {
        return Err(format!("fetch returned HTTP {} for {url}", resp.status()));
    }

    let text_promise = resp
        .text()
        .map_err(|e| format!("failed to read response text: {e:?}"))?;
    let text_value = JsFuture::from(text_promise)
        .await
        .map_err(|e| format!("failed to await response text: {e:?}"))?;

    text_value
        .as_string()
        .ok_or_else(|| "response text is not a string".to_owned())
}

// ---------------------------------------------------------------------------
// SignedPost verification
// ---------------------------------------------------------------------------

/// Verifies a `SignedPost` attestation by fetching the post URL and checking
/// that the response body contains both the DID and the nonce.
#[allow(clippy::future_not_send)] // WASM futures use Rc (JsFuture), inherently !Send
async fn verify_signed_post(issuer_did: &str, proof: &serde_json::Value) -> (bool, Option<String>) {
    // Parse proof — handle both string-encoded JSON and direct object.
    let signed_post: SignedPostProof = match proof {
        serde_json::Value::String(s) => match serde_json::from_str(s) {
            Ok(p) => p,
            Err(e) => {
                return (
                    false,
                    Some(format!("failed to parse signed_post proof string: {e}")),
                );
            }
        },
        other => match serde_json::from_value(other.clone()) {
            Ok(p) => p,
            Err(e) => {
                return (
                    false,
                    Some(format!("failed to parse signed_post proof object: {e}")),
                );
            }
        },
    };

    if signed_post.post_url.is_empty() {
        return (false, Some("post_url must not be empty".to_owned()));
    }
    if signed_post.nonce.is_empty() {
        return (false, Some("nonce must not be empty".to_owned()));
    }

    // Validate URL scheme — only HTTPS allowed for security.
    if !signed_post.post_url.starts_with("https://") {
        return (false, Some("post_url must use HTTPS scheme".to_owned()));
    }

    match fetch_url(&signed_post.post_url).await {
        Ok(body) => {
            let has_did = body.contains(issuer_did);
            let has_nonce = body.contains(&signed_post.nonce);

            if has_did && has_nonce {
                (true, None)
            } else {
                let mut missing = Vec::new();
                if !has_did {
                    missing.push("DID");
                }
                if !has_nonce {
                    missing.push("nonce");
                }
                (
                    false,
                    Some(format!("post body missing: {}", missing.join(", "))),
                )
            }
        }
        Err(e) => (false, Some(e)),
    }
}

// ---------------------------------------------------------------------------
// DNS verification
// ---------------------------------------------------------------------------

/// Cloudflare DNS-over-HTTPS endpoint.
const DOH_ENDPOINT: &str = "https://cloudflare-dns.com/dns-query";

/// Verifies a `DnsRecord` attestation by querying Cloudflare DNS-over-HTTPS
/// for TXT records at `_scp-verify.<domain>` and checking that one contains
/// the DID.
#[allow(clippy::future_not_send)] // WASM futures use Rc (JsFuture), inherently !Send
async fn verify_dns_record(issuer_did: &str, proof: &serde_json::Value) -> (bool, Option<String>) {
    // Parse proof — handle both string-encoded JSON and direct object.
    let dns_proof: DnsRecordProof = match proof {
        serde_json::Value::String(s) => match serde_json::from_str(s) {
            Ok(p) => p,
            Err(e) => {
                return (
                    false,
                    Some(format!("failed to parse dns_record proof string: {e}")),
                );
            }
        },
        other => match serde_json::from_value(other.clone()) {
            Ok(p) => p,
            Err(e) => {
                return (
                    false,
                    Some(format!("failed to parse dns_record proof object: {e}")),
                );
            }
        },
    };

    if dns_proof.domain.is_empty() {
        return (false, Some("domain must not be empty".to_owned()));
    }

    // Validate domain doesn't contain path traversal or injection characters.
    if dns_proof.domain.contains('/')
        || dns_proof.domain.contains('\\')
        || dns_proof.domain.contains(' ')
        || dns_proof.domain.contains('?')
        || dns_proof.domain.contains('#')
    {
        return (false, Some("domain contains invalid characters".to_owned()));
    }

    let query_name = format!("{}.{}", dns_proof.record_name, dns_proof.domain);
    let url = format!("{DOH_ENDPOINT}?name={query_name}&type=TXT");

    match fetch_url_with_headers(&url, &[("Accept", "application/dns-json")]).await {
        Ok(body) => {
            let doh_response: DohResponse = match serde_json::from_str(&body) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        false,
                        Some(format!("failed to parse DNS-over-HTTPS response: {e}")),
                    );
                }
            };

            // Check if any TXT record contains the DID.
            let found = doh_response
                .answer
                .iter()
                .any(|record| record.data.contains(issuer_did));

            if found {
                (true, None)
            } else {
                (
                    false,
                    Some(format!("no TXT record at {query_name} contains the DID")),
                )
            }
        }
        Err(e) => (false, Some(e)),
    }
}

// ---------------------------------------------------------------------------
// Public API: verify_reference_attestation
// ---------------------------------------------------------------------------

/// Verifies a Reference-class identity attestation (`SignedPost` or `DnsRecord`)
/// by fetching external resources via the browser Fetch API (§3.5.2).
///
/// # Input
///
/// `attestation_json` must be a JSON string with the following shape:
///
/// ```json
/// {
///   "issuer_did": "did:dht:z6Mk...",
///   "method": "signed_post",
///   "proof": { "post_url": "https://...", "nonce": "abc123", "posted_at": 1234567890 }
/// }
/// ```
///
/// or for DNS:
///
/// ```json
/// {
///   "issuer_did": "did:dht:z6Mk...",
///   "method": "dns_record",
///   "proof": { "domain": "example.com", "record_name": "_scp-verify" }
/// }
/// ```
///
/// The `proof` field may be either a JSON object or a JSON-encoded string.
///
/// # Output
///
/// Returns a JSON string: `{ "verified": true }` on success, or
/// `{ "verified": false, "error": "..." }` on failure. Fetch failures
/// (CORS, network, non-2xx) are reported in the `error` field — the
/// promise itself only rejects on malformed input.
///
/// # Supported methods
///
/// - `"signed_post"` — fetches the post URL over HTTPS, checks body contains
///   both the DID and the nonce.
/// - `"dns_record"` — queries Cloudflare DNS-over-HTTPS (`https://cloudflare-dns.com/dns-query`)
///   for TXT records at `{record_name}.{domain}`, checks one contains the DID.
///
/// Other methods (e.g., `"oauth"`, `"challenge_response"`) are Cryptographic-class
/// and are not verifiable via fetch — the promise rejects with `SCP-TRUST-8010`.
///
/// # JS usage
///
/// ```js
/// const resultJson = await verify_reference_attestation(JSON.stringify({
///     issuer_did: "did:dht:z6MkAlice",
///     method: "signed_post",
///     proof: { post_url: "https://x.com/alice/status/123", nonce: "abc123" }
/// }));
/// const result = JSON.parse(resultJson);
/// console.log(result.verified); // true or false
/// console.log(result.error);    // undefined or error string
/// ```
#[wasm_bindgen]
pub fn verify_reference_attestation(attestation_json: String) -> Promise {
    future_to_promise(async move {
        if attestation_json.is_empty() {
            return Err(ScpWasmError::validation(
                "attestation JSON must not be empty",
            ));
        }

        let input: ReferenceAttestationInput =
            serde_json::from_str(&attestation_json).map_err(|e| {
                ScpWasmError::validation(&format!(
                    "failed to parse reference attestation JSON: {e}"
                ))
            })?;

        if input.issuer_did.is_empty() {
            return Err(ScpWasmError::validation("issuer_did must not be empty"));
        }
        if !input.issuer_did.starts_with("did:") {
            return Err(ScpWasmError::validation(
                "issuer_did must start with 'did:'",
            ));
        }

        let (verified, error) = match input.method.as_str() {
            "signed_post" => verify_signed_post(&input.issuer_did, &input.proof).await,
            "dns_record" => verify_dns_record(&input.issuer_did, &input.proof).await,
            "oauth" | "challenge_response" => {
                return Err(ScpWasmError::Trust {
                    message: format!(
                        "method '{}' is Cryptographic-class and cannot be verified \
                             via fetch — use WebCrypto in the TypeScript wrapper layer",
                        input.method
                    ),
                    code: "SCP-TRUST-8010".to_owned(),
                }
                .into_js()
                .into());
            }
            other => {
                return Err(ScpWasmError::validation(&format!(
                    "unknown verification method: '{other}'"
                )));
            }
        };

        Ok(JsValue::from_str(&result_json(verified, error.as_deref())))
    })
}
