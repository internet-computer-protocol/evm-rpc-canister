//! This module contains definitions for communicating with an Ethereum API using the [JSON RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/)
//! interface.

use crate::accounting::get_http_request_cost;
use crate::logs::{DEBUG, TRACE_HTTP};
use crate::memory::next_request_id;
use crate::providers::resolve_rpc_service;
use crate::rpc_client::eth_rpc_error::{sanitize_send_raw_transaction_result, Parser};
use crate::rpc_client::json::responses::{Block, FeeHistory, LogEntry, TransactionReceipt};
use crate::rpc_client::numeric::{TransactionCount, Wei};
use crate::types::MetricRpcMethod;
use candid::candid_method;
use evm_rpc_types::{HttpOutcallError, JsonRpcError, ProviderError, RpcApi, RpcError, RpcService};
use ic_canister_log::log;
use ic_cdk::api::call::RejectionCode;
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext,
};
use ic_cdk_macros::query;
use minicbor::{Decode, Encode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;
use std::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};

#[cfg(test)]
mod tests;

// This constant is our approximation of the expected header size.
// The HTTP standard doesn't define any limit, and many implementations limit
// the headers size to 8 KiB. We chose a lower limit because headers observed on most providers
// fit in the constant defined below, and if there is a spike, then the payload size adjustment
// should take care of that.
pub const HEADER_SIZE_LIMIT: u64 = 2 * 1024;

// This constant comes from the IC specification:
// > If provided, the value must not exceed 2MiB
const HTTP_MAX_SIZE: u64 = 2 * 1024 * 1024;

pub const MAX_PAYLOAD_SIZE: u64 = HTTP_MAX_SIZE - HEADER_SIZE_LIMIT;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Hash(#[serde(with = "ic_ethereum_types::serde_data")] pub [u8; 32]);

impl Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl LowerHex for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl UpperHex for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode_upper(self.0))
    }
}

impl std::str::FromStr for Hash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err("Ethereum hash doesn't start with 0x".to_string());
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&s[2..], &mut bytes)
            .map_err(|e| format!("failed to decode hash from hex: {}", e))?;
        Ok(Self(bytes))
    }
}

impl HttpResponsePayload for Hash {}

impl HttpResponsePayload for Wei {}

/// An envelope for all JSON-RPC requests.
#[derive(Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    jsonrpc: String,
    method: String,
    id: u64,
    pub params: T,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcReply<T> {
    pub id: u64,
    pub jsonrpc: String,
    #[serde(flatten)]
    pub result: JsonRpcResult<T>,
}

/// An envelope for all JSON-RPC replies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JsonRpcResult<T> {
    #[serde(rename = "result")]
    Result(T),
    #[serde(rename = "error")]
    Error { code: i64, message: String },
}

impl<T> JsonRpcResult<T> {
    pub fn unwrap(self) -> T {
        match self {
            Self::Result(t) => t,
            Self::Error { code, message } => panic!(
                "expected JSON RPC call to succeed, got an error: error_code = {code}, message = {message}"
            ),
        }
    }
}

impl<T> From<JsonRpcResult<T>> for Result<T, RpcError> {
    fn from(result: JsonRpcResult<T>) -> Self {
        match result {
            JsonRpcResult::Result(r) => Ok(r),
            JsonRpcResult::Error { code, message } => Err(JsonRpcError { code, message }.into()),
        }
    }
}

/// Describes a payload transformation to execute before passing the HTTP response to consensus.
/// The purpose of these transformations is to ensure that the response encoding is deterministic
/// (the field order is the same).
#[derive(Debug, Decode, Encode)]
pub enum ResponseTransform {
    #[n(0)]
    Block,
    #[n(1)]
    LogEntries,
    #[n(2)]
    TransactionReceipt,
    #[n(3)]
    FeeHistory,
    #[n(4)]
    SendRawTransaction,
}

impl ResponseTransform {
    fn apply(&self, body_bytes: &mut Vec<u8>) {
        fn redact_response<T>(body: &mut Vec<u8>)
        where
            T: Serialize + DeserializeOwned,
        {
            let response: JsonRpcReply<T> = match serde_json::from_slice(body) {
                Ok(response) => response,
                Err(_) => return,
            };
            *body = serde_json::to_string(&response)
                .expect("BUG: failed to serialize response")
                .into_bytes();
        }

        fn redact_collection_response<T>(body: &mut Vec<u8>)
        where
            T: Serialize + DeserializeOwned,
        {
            let mut response: JsonRpcReply<Vec<T>> = match serde_json::from_slice(body) {
                Ok(response) => response,
                Err(_) => return,
            };

            if let JsonRpcResult::Result(ref mut result) = response.result {
                sort_by_hash(result);
            }

            *body = serde_json::to_string(&response)
                .expect("BUG: failed to serialize response")
                .into_bytes();
        }

        match self {
            Self::Block => redact_response::<Block>(body_bytes),
            Self::LogEntries => redact_collection_response::<LogEntry>(body_bytes),
            Self::TransactionReceipt => redact_response::<TransactionReceipt>(body_bytes),
            Self::FeeHistory => redact_response::<FeeHistory>(body_bytes),
            Self::SendRawTransaction => {
                sanitize_send_raw_transaction_result(body_bytes, Parser::new())
            }
        }
    }
}

#[query]
#[candid_method(query)]
fn cleanup_response(mut args: TransformArgs) -> HttpResponse {
    args.response.headers.clear();
    ic_cdk::println!(
        "RAW RESPONSE BEFORE TRANSFORM:\nstatus: {:?}\nbody:{:?}",
        args.response.status,
        String::from_utf8_lossy(&args.response.body).to_string()
    );
    let status_ok = args.response.status >= 200u16 && args.response.status < 300u16;
    if status_ok && !args.context.is_empty() {
        let maybe_transform: Result<ResponseTransform, _> = minicbor::decode(&args.context[..]);
        if let Ok(transform) = maybe_transform {
            transform.apply(&mut args.response.body);
        }
    }
    ic_cdk::println!(
        "RAW RESPONSE AFTER TRANSFORM:\nstatus: {:?}\nbody:{:?}",
        args.response.status,
        String::from_utf8_lossy(&args.response.body).to_string()
    );
    args.response
}

pub fn is_response_too_large(code: &RejectionCode, message: &str) -> bool {
    code == &RejectionCode::SysFatal
        && (message.contains("size limit") || message.contains("length limit"))
}

pub fn are_errors_consistent<T: PartialEq>(
    left: &Result<T, RpcError>,
    right: &Result<T, RpcError>,
) -> bool {
    match (left, right) {
        (Ok(_), _) | (_, Ok(_)) => true,
        _ => left == right,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResponseSizeEstimate(u64);

impl ResponseSizeEstimate {
    pub fn new(num_bytes: u64) -> Self {
        assert!(num_bytes > 0);
        assert!(num_bytes <= MAX_PAYLOAD_SIZE);
        Self(num_bytes)
    }

    /// Describes the expected (90th percentile) number of bytes in the HTTP response body.
    /// This number should be less than `MAX_PAYLOAD_SIZE`.
    pub fn get(self) -> u64 {
        self.0
    }

    /// Returns a higher estimate for the payload size.
    pub fn adjust(self) -> Self {
        Self(self.0.max(1024).saturating_mul(2).min(MAX_PAYLOAD_SIZE))
    }
}

impl fmt::Display for ResponseSizeEstimate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait HttpResponsePayload {
    fn response_transform() -> Option<ResponseTransform> {
        None
    }
}

impl<T: HttpResponsePayload> HttpResponsePayload for Option<T> {}

impl HttpResponsePayload for TransactionCount {}

/// Calls a JSON-RPC method on an Ethereum node at the specified URL.
pub async fn call<I, O>(
    provider: &RpcService,
    method: impl Into<String>,
    params: I,
    mut response_size_estimate: ResponseSizeEstimate,
) -> Result<O, RpcError>
where
    I: Serialize,
    O: DeserializeOwned + HttpResponsePayload,
{
    let eth_method = method.into();
    let mut rpc_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        params,
        method: eth_method.clone(),
        id: 1,
    };
    let api = resolve_api(provider)?;
    let url = &api.url;
    let mut headers = vec![HttpHeader {
        name: "Content-Type".to_string(),
        value: "application/json".to_string(),
    }];
    if let Some(vec) = api.headers {
        headers.extend(vec);
    }
    let mut retries = 0;
    loop {
        rpc_request.id = next_request_id();
        let payload = serde_json::to_string(&rpc_request).unwrap();
        log!(
            TRACE_HTTP,
            "Calling url (retries={retries}): {url}, with payload: {payload}"
        );

        let effective_size_estimate = response_size_estimate.get();
        let transform_op = O::response_transform()
            .as_ref()
            .map(|t| {
                let mut buf = vec![];
                minicbor::encode(t, &mut buf).unwrap();
                buf
            })
            .unwrap_or_default();

        let request = CanisterHttpRequestArgument {
            url: url.clone(),
            max_response_bytes: Some(effective_size_estimate),
            method: HttpMethod::POST,
            headers: headers.clone(),
            body: Some(payload.as_bytes().to_vec()),
            transform: Some(TransformContext::from_name(
                "cleanup_response".to_owned(),
                transform_op,
            )),
        };

        let response = match http_request(provider, &eth_method, request, effective_size_estimate)
            .await
        {
            Err(RpcError::HttpOutcallError(HttpOutcallError::IcError { code, message }))
                if is_response_too_large(&code, &message) =>
            {
                let new_estimate = response_size_estimate.adjust();
                if response_size_estimate == new_estimate {
                    return Err(HttpOutcallError::IcError { code, message }.into());
                }
                log!(DEBUG, "The {eth_method} response didn't fit into {response_size_estimate} bytes, retrying with {new_estimate}");
                response_size_estimate = new_estimate;
                retries += 1;
                continue;
            }
            result => result?,
        };

        log!(
            TRACE_HTTP,
            "Got response (with {} bytes): {} from url: {} with status: {}",
            response.body.len(),
            String::from_utf8_lossy(&response.body),
            url,
            response.status
        );

        // JSON-RPC responses over HTTP should have a 2xx status code,
        // even if the contained JsonRpcResult is an error.
        // If the server is not available, it will sometimes (wrongly) return HTML that will fail parsing as JSON.
        let http_status_code = http_status_code(&response);
        if !is_successful_http_code(&http_status_code) {
            return Err(HttpOutcallError::InvalidHttpJsonRpcResponse {
                status: http_status_code,
                body: String::from_utf8_lossy(&response.body).to_string(),
                parsing_error: None,
            }
            .into());
        }

        let reply: JsonRpcReply<O> = serde_json::from_slice(&response.body).map_err(|e| {
            HttpOutcallError::InvalidHttpJsonRpcResponse {
                status: http_status_code,
                body: String::from_utf8_lossy(&response.body).to_string(),
                parsing_error: Some(e.to_string()),
            }
        })?;

        return reply.result.into();
    }
}

fn resolve_api(service: &RpcService) -> Result<RpcApi, ProviderError> {
    Ok(resolve_rpc_service(service.clone())?.api())
}

async fn http_request(
    service: &RpcService,
    method: &str,
    request: CanisterHttpRequestArgument,
    effective_response_size_estimate: u64,
) -> Result<HttpResponse, RpcError> {
    let service = resolve_rpc_service(service.clone())?;
    let cycles_cost = get_http_request_cost(
        request
            .body
            .as_ref()
            .map(|bytes| bytes.len() as u64)
            .unwrap_or_default(),
        effective_response_size_estimate,
    );
    let rpc_method = MetricRpcMethod(method.to_string());
    crate::http::http_request(rpc_method, service, request, cycles_cost).await
}

fn http_status_code(response: &HttpResponse) -> u16 {
    use num_traits::cast::ToPrimitive;
    // HTTP status code are always 3 decimal digits, hence at most 999.
    // See https://httpwg.org/specs/rfc9110.html#status.code.extensibility
    response.status.0.to_u16().expect("valid HTTP status code")
}

fn is_successful_http_code(status: &u16) -> bool {
    const OK: u16 = 200;
    const REDIRECTION: u16 = 300;
    (OK..REDIRECTION).contains(status)
}

fn sort_by_hash<T: Serialize + DeserializeOwned>(to_sort: &mut [T]) {
    use ic_crypto_sha3::Keccak256;
    to_sort.sort_by(|a, b| {
        let a_hash = Keccak256::hash(serde_json::to_vec(a).expect("BUG: failed to serialize"));
        let b_hash = Keccak256::hash(serde_json::to_vec(b).expect("BUG: failed to serialize"));
        a_hash.cmp(&b_hash)
    });
}
