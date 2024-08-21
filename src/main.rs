use candid::candid_method;
use cketh_common::eth_rpc::{Block, FeeHistory, LogEntry, RpcError};

use cketh_common::eth_rpc_client::providers::RpcService;
use cketh_common::eth_rpc_client::RpcConfig;
use evm_rpc::accounting::{get_cost_with_collateral, get_http_request_cost};
use evm_rpc::candid_rpc::CandidRpcClient;
use evm_rpc::http::get_http_response_body;
use evm_rpc::memory::{
    get_nodes_in_subnet, insert_api_key, is_api_key_principal, set_api_key_principals,
    set_nodes_in_subnet,
};
use evm_rpc::metrics::encode_metrics;
use evm_rpc::providers::{resolve_rpc_service, PROVIDERS, SERVICE_PROVIDER_MAP};
use evm_rpc::types::{ApiKey, Provider, ProviderId};
use ic_canisters_http_types::{
    HttpRequest as AssetHttpRequest, HttpResponse as AssetHttpResponse, HttpResponseBuilder,
};
use ic_cdk::api::is_controller;
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use ic_cdk::{query, update};
use ic_nervous_system_common::serve_metrics;

use evm_rpc::{
    http::{json_rpc_request, transform_http_request},
    memory::UNSTABLE_METRICS,
    types::{candid_types, InitArgs, MetricRpcMethod, Metrics, MultiRpcResult, RpcServices},
};

pub fn require_api_key_principal_or_controller() -> Result<(), String> {
    let caller = ic_cdk::caller();
    if is_api_key_principal(&caller) || is_controller(&caller) {
        Ok(())
    } else {
        Err("You are not authorized".to_string())
    }
}

#[update(name = "eth_getLogs")]
#[candid_method(rename = "eth_getLogs")]
pub async fn eth_get_logs(
    source: RpcServices,
    config: Option<RpcConfig>,
    args: candid_types::GetLogsArgs,
) -> MultiRpcResult<Vec<LogEntry>> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_get_logs(args).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_getBlockByNumber")]
#[candid_method(rename = "eth_getBlockByNumber")]
pub async fn eth_get_block_by_number(
    source: RpcServices,
    config: Option<RpcConfig>,
    block: candid_types::BlockTag,
) -> MultiRpcResult<Block> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_get_block_by_number(block).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_getTransactionReceipt")]
#[candid_method(rename = "eth_getTransactionReceipt")]
pub async fn eth_get_transaction_receipt(
    source: RpcServices,
    config: Option<RpcConfig>,
    hash: String,
) -> MultiRpcResult<Option<candid_types::TransactionReceipt>> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_get_transaction_receipt(hash).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_getTransactionCount")]
#[candid_method(rename = "eth_getTransactionCount")]
pub async fn eth_get_transaction_count(
    source: RpcServices,
    config: Option<RpcConfig>,
    args: candid_types::GetTransactionCountArgs,
) -> MultiRpcResult<candid::Nat> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_get_transaction_count(args).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_feeHistory")]
#[candid_method(rename = "eth_feeHistory")]
pub async fn eth_fee_history(
    source: RpcServices,
    config: Option<RpcConfig>,
    args: candid_types::FeeHistoryArgs,
) -> MultiRpcResult<FeeHistory> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_fee_history(args).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_sendRawTransaction")]
#[candid_method(rename = "eth_sendRawTransaction")]
pub async fn eth_send_raw_transaction(
    source: RpcServices,
    config: Option<RpcConfig>,
    raw_signed_transaction_hex: String,
) -> MultiRpcResult<candid_types::SendRawTransactionStatus> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => {
            source
                .eth_send_raw_transaction(raw_signed_transaction_hex)
                .await
        }
        Err(err) => Err(err).into(),
    }
}

#[update]
#[candid_method]
async fn request(
    service: RpcService,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<String, RpcError> {
    let response = json_rpc_request(
        resolve_rpc_service(service)?,
        MetricRpcMethod("request".to_string()),
        &json_rpc_payload,
        max_response_bytes,
    )
    .await?;
    get_http_response_body(response)
}

#[query(name = "requestCost")]
#[candid_method(query, rename = "requestCost")]
fn request_cost(
    _service: RpcService,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<u128, RpcError> {
    Ok(get_cost_with_collateral(get_http_request_cost(
        json_rpc_payload.len() as u64,
        max_response_bytes,
    )))
}

#[query(name = "getProviders")]
#[candid_method(query, rename = "getProviders")]
fn get_providers() -> Vec<Provider> {
    PROVIDERS.with(|providers| providers.clone())
}

#[query(name = "getServiceProviderMap")]
#[candid_method(query, rename = "getServiceProviderMap")]
fn get_service_provider_map() -> Vec<(RpcService, ProviderId)> {
    SERVICE_PROVIDER_MAP.with(|map| {
        map.iter()
            .filter_map(|(k, v)| Some((k.clone(), *v)))
            .collect()
    })
}

#[query(name = "getNodesInSubnet")]
#[candid_method(query, rename = "getNodesInSubnet")]
async fn get_nodes_in_subnet_() -> u32 {
    get_nodes_in_subnet()
}

#[update(name = "insertApiKeys")]
#[candid_method(rename = "insertApiKeys")]
async fn insert_api_keys(api_keys: Vec<(ProviderId, String)>) {
    for (provider_id, api_key) in api_keys {
        insert_api_key(provider_id, ApiKey(api_key));
    }
}

#[query(name = "__transform_json_rpc")]
fn transform(args: TransformArgs) -> HttpResponse {
    transform_http_request(args)
}

#[ic_cdk::init]
fn init(args: InitArgs) {
    post_upgrade(args);
}

#[ic_cdk::post_upgrade]
fn post_upgrade(args: InitArgs) {
    set_nodes_in_subnet(args.nodes_in_subnet);
    if let Some(principals) = args.api_key_principals {
        set_api_key_principals(principals);
    }
}

#[query]
fn http_request(request: AssetHttpRequest) -> AssetHttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(encode_metrics),
        "/logs" => {
            use cketh_common::logs::{Log, Priority, Sort};
            use std::str::FromStr;

            let max_skip_timestamp = match request.raw_query_param("time") {
                Some(arg) => match u64::from_str(arg) {
                    Ok(value) => value,
                    Err(_) => {
                        return HttpResponseBuilder::bad_request()
                            .with_body_and_content_length("failed to parse the 'time' parameter")
                            .build()
                    }
                },
                None => 0,
            };

            let mut log: Log = Default::default();

            match request.raw_query_param("priority").map(Priority::from_str) {
                Some(Ok(priority)) => match priority {
                    Priority::Info => log.push_logs(Priority::Info),
                    Priority::Debug => log.push_logs(Priority::Debug),
                    Priority::TraceHttp => {}
                },
                _ => {
                    log.push_logs(Priority::Info);
                    log.push_logs(Priority::Debug);
                }
            }

            log.entries
                .retain(|entry| entry.timestamp >= max_skip_timestamp);

            fn ordering_from_query_params(sort: Option<&str>, max_skip_timestamp: u64) -> Sort {
                match sort {
                    Some(ord_str) => match Sort::from_str(ord_str) {
                        Ok(order) => order,
                        Err(_) => {
                            if max_skip_timestamp == 0 {
                                Sort::Ascending
                            } else {
                                Sort::Descending
                            }
                        }
                    },
                    None => {
                        if max_skip_timestamp == 0 {
                            Sort::Ascending
                        } else {
                            Sort::Descending
                        }
                    }
                }
            }

            log.sort_logs(ordering_from_query_params(
                request.raw_query_param("sort"),
                max_skip_timestamp,
            ));

            const MAX_BODY_SIZE: usize = 3_000_000;
            HttpResponseBuilder::ok()
                .header("Content-Type", "application/json; charset=utf-8")
                .with_body_and_content_length(log.serialize_logs(MAX_BODY_SIZE))
                .build()
        }
        _ => HttpResponseBuilder::not_found().build(),
    }
}

#[query(name = "getMetrics")]
#[candid_method(query, rename = "getMetrics")]
fn get_metrics() -> Metrics {
    UNSTABLE_METRICS.with(|metrics| (*metrics.borrow()).clone())
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

#[test]
fn test_candid_interface() {
    fn source_to_str(source: &candid::utils::CandidSource) -> String {
        match source {
            candid::utils::CandidSource::File(f) => {
                std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
            }
            candid::utils::CandidSource::Text(t) => t.to_string(),
        }
    }

    fn check_service_compatible(
        new_name: &str,
        new: candid::utils::CandidSource,
        old_name: &str,
        old: candid::utils::CandidSource,
    ) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match candid::utils::service_compatible(new, old) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{} is not compatible with {}!\n\n\
            {}:\n\
            {}\n\n\
            {}:\n\
            {}\n",
                    new_name, old_name, new_name, new_str, old_name, old_str
                );
                panic!("{:?}", e);
            }
        }
    }

    candid::export_service!();
    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("candid/evm_rpc.did");

    check_service_compatible(
        "actual ledger candid interface",
        candid::utils::CandidSource::Text(&new_interface),
        "declared candid interface in evm_rpc.did file",
        candid::utils::CandidSource::File(old_interface.as_path()),
    );
}
