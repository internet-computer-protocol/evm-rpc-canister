use crate::utils::{from_hex, to_hex};
use async_trait::async_trait;
use ethers_core::abi::{Contract, FunctionExt, Token};
use ethers_providers::{JsonRpcClient, ProviderError};
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::cell::RefCell;
use std::fmt::Debug;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest<'a, T> {
    pub id: u64,
    pub jsonrpc: &'static str,
    pub method: &'a str,
    pub params: T,
}

impl<'a, T> JsonRpcRequest<'a, T> {
    pub fn new(method: &'a str, params: T) -> Self {
        Self {
            id: next_id(),
            jsonrpc: "2.0",
            method,
            params,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EthCall {
    to: String,
    data: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    result: Option<String>,
    error: Option<JsonRpcError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonRpcError {
    code: isize,
    message: String,
}

fn next_id() -> u64 {
    thread_local! {
        static NEXT_ID: RefCell<u64> = RefCell::default();
    }
    NEXT_ID.with(|next_id| {
        let mut next_id = next_id.borrow_mut();
        let id = *next_id;
        *next_id = next_id.wrapping_add(1);
        id
    })
}

pub fn get_provider(
    url: &str,
    max_response_bytes: Option<u64>,
) -> ethers_providers::Provider<HttpOutcallClient> {
    ethers_providers::Provider::new(HttpOutcallClient::new(url, max_response_bytes))
}

#[derive(Debug)]
pub struct HttpOutcallClient<'a> {
    pub url: &'a str,
    pub max_response_bytes: Option<u64>,
}

impl<'a> HttpOutcallClient<'a> {
    pub fn new(url: &'a str, max_response_bytes: Option<u64>) -> Self {
        Self {
            url,
            max_response_bytes,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> JsonRpcClient for HttpOutcallClient<'a> {
    type Error = ProviderError;

    async fn request<T, R>(&self, method: &str, params: T) -> Result<R, Self::Error>
    where
        T: Debug + Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        let cycles = 0; // TODO
        let result = request(
            self.url,
            &JsonRpcRequest::new(method, params),
            cycles,
            self.max_response_bytes,
        )
        .await
        .map_err(|e| ProviderError::CustomError(format!("{:?}", e)))?;
        Ok(serde_json::from_slice(&result)?)
    }
}

pub async fn request<'a, T: Serialize>(
    url: &str,
    request: &JsonRpcRequest<'a, T>,
    cycles: u128,
    max_response_bytes: Option<u64>,
) -> Result<Vec<u8>, ProviderError> {
    let json_rpc_payload =
        serde_json::to_string(request).expect("Error while encoding JSON-RPC request");

    let parsed_url = url::Url::parse(&url).expect("Service URL parse error");
    let host = parsed_url
        .host_str()
        .expect("Invalid JSON-RPC host")
        .to_string();

    let request_headers = vec![
        HttpHeader {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        },
        HttpHeader {
            name: "Host".to_string(),
            value: host.to_string(),
        },
    ];
    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        max_response_bytes,
        method: HttpMethod::POST,
        headers: request_headers,
        body: Some(json_rpc_payload.as_bytes().to_vec()),
        transform: Some(TransformContext::from_name(
            "__transform_eth_rpc".to_string(),
            vec![],
        )),
    };

    let response = match http_request(request, cycles).await {
        Ok((r,)) => r,
        Err((r, m)) => panic!("{:?} {:?}", r, m),
    };
    let json: JsonRpcResponse =
        serde_json::from_str(std::str::from_utf8(&response.body).expect("utf8"))
            .expect("JSON was not well-formatted");
    if let Some(err) = json.error {
        return Err(ProviderError::CustomError(format!(
            "JSON-RPC error code {}: {}",
            err.code, err.message
        )));
    }
    from_hex(
        &json
            .result
            .ok_or_else(|| ProviderError::CustomError("missing result".to_string()))?,
    )
    .ok_or_else(|| ProviderError::CustomError("unexpected result hex".to_string()))
}

/// Asynchronously calls a function on an Ethereum smart contract.
///
/// This function allows you to interact with an Ethereum smart contract by sending a transaction that invokes a specific function on the contract.
/// The provided `rpc_url` is the URL of a JSON-RPC provider, which is used to send the transaction to the Ethereum network.
/// * The `contract_address` parameter is a hexadecimal string representing the address of the target smart contract on the Ethereum blockchain.
/// * The `abi` parameter is the contract's ABI (Application Binary Interface) for decoding and encoding function calls.
/// * The `function_name` is the name of the function to be called on the contract.
/// * The `args` parameter is an array of `Token` values representing the function's input arguments.
///
/// The function returns a `Vec<Token>` representing the output values returned by the called function.
///
/// ### Example
///
/// ```rust
/// use ic_eth::core::abi::{Token, Contract};
/// use ic_eth::{include_abi, call_contract};
///
/// let service_url = "https://cloudflare-eth.com/v1/mainnet";
/// let contract_address = "0x123456789abcdefABCDEF123456789abcdefaBcde".to_string();
/// let abi = include_abi!("../abi/erc20.json");
/// let function_name = "transfer";
/// let args = vec![Token::Address(contract_address.parse().unwrap()), Token::Uint(100.into())];
/// let cycles = 60_000_000;
/// let max_response_bytes = Some(1000);
///
/// let result = call_contract(service_url, contract_address, &abi, function_name, &args, cycles, max_response_bytes).await;
/// println!("Function call result: {:?}", result);
/// ```
pub async fn call_contract(
    service_url: &str,
    contract_address: String,
    abi: &Contract,
    function_name: &str,
    args: &[Token],
    cycles: u128,
    max_response_bytes: Option<u64>,
) -> Result<Vec<Token>, ProviderError> {
    let f = match abi.functions_by_name(function_name).map(|v| &v[..]) {
        Ok([f]) => f,
        Ok(fs) => panic!(
            "Found {} function overloads. Please pass one of the following: {}",
            fs.len(),
            fs.iter()
                .map(|f| format!("{:?}", f.abi_signature()))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Err(_) => abi
            .functions()
            .find(|f| function_name == f.abi_signature())
            .expect("Function not found"),
    };
    let data = f
        .encode_input(args)
        .expect("Error while encoding input args");
    let json_request = JsonRpcRequest::new(
        "eth_call",
        (
            EthCall {
                to: contract_address,
                data: to_hex(&data),
            },
            "latest",
        ),
    );
    let result = request(service_url, &json_request, cycles, max_response_bytes).await?;
    f.decode_output(&result)
        .map_err(|e| ProviderError::CustomError(format!("{}", e)))
}
