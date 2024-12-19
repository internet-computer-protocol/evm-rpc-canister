use candid::candid_method;
use evm_rpc::accounting::{get_cost_with_collateral, get_http_request_cost};
use evm_rpc::candid_rpc::CandidRpcClient;
use evm_rpc::constants::NODES_IN_SUBNET;
use evm_rpc::http::get_http_response_body;
use evm_rpc::logs::INFO;
use evm_rpc::memory::{insert_api_key, is_api_key_principal, is_demo_active, remove_api_key, set_api_key_principals, set_demo_active, set_log_filter, set_override_provider};
use evm_rpc::metrics::encode_metrics;
use evm_rpc::providers::{find_provider, resolve_rpc_service, PROVIDERS, SERVICE_PROVIDER_MAP};
use evm_rpc::types::{LogFilter, OverrideProvider, Provider, ProviderId, RpcAccess, RpcAuth};
use evm_rpc::{
    http::{json_rpc_request, transform_http_request},
    http_types,
    memory::UNSTABLE_METRICS,
    types::{MetricRpcMethod, Metrics},
};
use evm_rpc_types::{Hex32, MultiRpcResult, RpcResult};
use ic_canister_log::log;
use ic_cdk::api::is_controller;
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use ic_cdk::{query, update};
use ic_metrics_encoder::MetricsEncoder;

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
    source: evm_rpc_types::RpcServices,
    config: Option<evm_rpc_types::RpcConfig>,
    args: evm_rpc_types::GetLogsArgs,
) -> MultiRpcResult<Vec<evm_rpc_types::LogEntry>> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_get_logs(args).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_getBlockByNumber")]
#[candid_method(rename = "eth_getBlockByNumber")]
pub async fn eth_get_block_by_number(
    source: evm_rpc_types::RpcServices,
    config: Option<evm_rpc_types::RpcConfig>,
    block: evm_rpc_types::BlockTag,
) -> MultiRpcResult<evm_rpc_types::Block> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_get_block_by_number(block).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_getTransactionReceipt")]
#[candid_method(rename = "eth_getTransactionReceipt")]
pub async fn eth_get_transaction_receipt(
    source: evm_rpc_types::RpcServices,
    config: Option<evm_rpc_types::RpcConfig>,
    tx_hash: Hex32,
) -> MultiRpcResult<Option<evm_rpc_types::TransactionReceipt>> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_get_transaction_receipt(tx_hash).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_getTransactionCount")]
#[candid_method(rename = "eth_getTransactionCount")]
pub async fn eth_get_transaction_count(
    source: evm_rpc_types::RpcServices,
    config: Option<evm_rpc_types::RpcConfig>,
    args: evm_rpc_types::GetTransactionCountArgs,
) -> MultiRpcResult<evm_rpc_types::Nat256> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_get_transaction_count(args).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_feeHistory")]
#[candid_method(rename = "eth_feeHistory")]
pub async fn eth_fee_history(
    source: evm_rpc_types::RpcServices,
    config: Option<evm_rpc_types::RpcConfig>,
    args: evm_rpc_types::FeeHistoryArgs,
) -> MultiRpcResult<evm_rpc_types::FeeHistory> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_fee_history(args).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_sendRawTransaction")]
#[candid_method(rename = "eth_sendRawTransaction")]
pub async fn eth_send_raw_transaction(
    source: evm_rpc_types::RpcServices,
    config: Option<evm_rpc_types::RpcConfig>,
    raw_signed_transaction_hex: evm_rpc_types::Hex,
) -> MultiRpcResult<evm_rpc_types::SendRawTransactionStatus> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => {
            source
                .eth_send_raw_transaction(raw_signed_transaction_hex)
                .await
        }
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_call")]
#[candid_method(rename = "eth_call")]
pub async fn eth_call(
    source: evm_rpc_types::RpcServices,
    config: Option<evm_rpc_types::RpcConfig>,
    args: evm_rpc_types::CallArgs,
) -> MultiRpcResult<evm_rpc_types::Hex> {
    match CandidRpcClient::new(source, config) {
        Ok(source) => source.eth_call(args).await,
        Err(err) => Err(err).into(),
    }
}

#[update]
#[candid_method]
async fn request(
    service: evm_rpc_types::RpcService,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> RpcResult<String> {
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
    _service: evm_rpc_types::RpcService,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> RpcResult<u128> {
    if is_demo_active() {
        Ok(0)
    } else {
        Ok(get_cost_with_collateral(get_http_request_cost(
            json_rpc_payload.len() as u64,
            max_response_bytes,
        )))
    }
}

#[query(name = "getProviders")]
#[candid_method(query, rename = "getProviders")]
fn get_providers() -> Vec<evm_rpc_types::Provider> {
    fn into_provider(provider: Provider) -> evm_rpc_types::Provider {
        evm_rpc_types::Provider {
            provider_id: provider.provider_id,
            chain_id: provider.chain_id,
            access: match provider.access {
                RpcAccess::Authenticated { auth, public_url } => {
                    evm_rpc_types::RpcAccess::Authenticated {
                        auth: match auth {
                            RpcAuth::BearerToken { url } => evm_rpc_types::RpcAuth::BearerToken {
                                url: url.to_string(),
                            },
                            RpcAuth::UrlParameter { url_pattern } => {
                                evm_rpc_types::RpcAuth::UrlParameter {
                                    url_pattern: url_pattern.to_string(),
                                }
                            }
                        },
                        public_url: public_url.map(|s| s.to_string()),
                    }
                }
                RpcAccess::Unauthenticated { public_url } => {
                    evm_rpc_types::RpcAccess::Unauthenticated {
                        public_url: public_url.to_string(),
                    }
                }
            },
            alias: provider.alias,
        }
    }
    PROVIDERS.iter().cloned().map(into_provider).collect()
}

#[query(name = "getServiceProviderMap")]
#[candid_method(query, rename = "getServiceProviderMap")]
fn get_service_provider_map() -> Vec<(evm_rpc_types::RpcService, ProviderId)> {
    SERVICE_PROVIDER_MAP.with(|map| map.iter().map(|(k, v)| (k.clone(), *v)).collect())
}

#[query(name = "getNodesInSubnet")]
#[candid_method(query, rename = "getNodesInSubnet")]
fn get_nodes_in_subnet() -> u32 {
    NODES_IN_SUBNET
}

#[update(
    name = "updateApiKeys",
    guard = "require_api_key_principal_or_controller"
)]
#[candid_method(rename = "updateApiKeys")]
/// Inserts or removes RPC provider API keys.
///
/// For each element of `api_keys`, passing `(id, Some(key))` corresponds to inserting or updating
/// an API key, while passing `(id, None)` indicates that the key should be removed from the canister.
///
/// Panics if the list of provider IDs includes a nonexistent or "unauthenticated" (fully public) provider.
async fn update_api_keys(api_keys: Vec<(ProviderId, Option<String>)>) {
    log!(
        INFO,
        "[{}] Updating API keys for providers: {}",
        ic_cdk::caller(),
        api_keys
            .iter()
            .map(|(id, _)| id.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    for (provider_id, api_key) in api_keys {
        let provider = find_provider(|provider| provider.provider_id == provider_id)
            .unwrap_or_else(|| panic!("Provider not found: {}", provider_id));
        match provider.access {
            RpcAccess::Authenticated { .. } => {}
            RpcAccess::Unauthenticated { .. } => {
                panic!(
                    "Trying to set API key for unauthenticated provider: {}",
                    provider_id
                )
            }
        };
        match api_key {
            Some(key) => insert_api_key(provider_id, key.try_into().expect("Invalid API key")),
            None => remove_api_key(provider_id),
        }
    }
}

#[query(name = "__transform_json_rpc", hidden = true)]
fn transform(args: TransformArgs) -> HttpResponse {
    transform_http_request(args)
}

#[ic_cdk::init]
fn init(args: evm_rpc_types::InstallArgs) {
    post_upgrade(args);
}

#[ic_cdk::post_upgrade]
fn post_upgrade(args: evm_rpc_types::InstallArgs) {
    if let Some(demo) = args.demo {
        set_demo_active(demo);
    }
    if let Some(principals) = args.manage_api_keys {
        set_api_key_principals(principals);
    }
    if let Some(filter) = args.log_filter {
        set_log_filter(LogFilter::from(filter))
    }
    if let Some(override_provider)  =args.override_provider {
        set_override_provider(OverrideProvider::from(override_provider));
    }
}

#[query(hidden = true)]
fn http_request(request: http_types::HttpRequest) -> http_types::HttpResponse {
    match request.path() {
        "/metrics" => {
            let mut writer = MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

            match encode_metrics(&mut writer) {
                Ok(()) => http_types::HttpResponseBuilder::ok()
                    .header("Content-Type", "text/plain; version=0.0.4")
                    .with_body_and_content_length(writer.into_inner())
                    .build(),
                Err(err) => http_types::HttpResponseBuilder::server_error(format!(
                    "Failed to encode metrics: {}",
                    err
                ))
                .build(),
            }
        }
        "/logs" => {
            use evm_rpc::logs::{Log, Priority, Sort};
            use std::str::FromStr;

            let max_skip_timestamp = match request.raw_query_param("time") {
                Some(arg) => match u64::from_str(arg) {
                    Ok(value) => value,
                    Err(_) => {
                        return http_types::HttpResponseBuilder::bad_request()
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

            const MAX_BODY_SIZE: usize = 2_000_000;
            http_types::HttpResponseBuilder::ok()
                .header("Content-Type", "application/json; charset=utf-8")
                .with_body_and_content_length(log.serialize_logs(MAX_BODY_SIZE))
                .build()
        }
        _ => http_types::HttpResponseBuilder::not_found().build(),
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_candid_interface() {
        fn source_to_str(source: &candid_parser::utils::CandidSource) -> String {
            match source {
                candid_parser::utils::CandidSource::File(f) => {
                    std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
                }
                candid_parser::utils::CandidSource::Text(t) => t.to_string(),
            }
        }

        fn check_service_equal(
            new_name: &str,
            new: candid_parser::utils::CandidSource,
            old_name: &str,
            old: candid_parser::utils::CandidSource,
        ) {
            let new_str = source_to_str(&new);
            let old_str = source_to_str(&old);
            match candid_parser::utils::service_equal(new, old) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "{} is not equal with {}!\n\n\
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

        check_service_equal(
            "actual ledger candid interface",
            candid_parser::utils::CandidSource::Text(&new_interface),
            "declared candid interface in evm_rpc.did file",
            candid_parser::utils::CandidSource::File(old_interface.as_path()),
        );
    }
}
