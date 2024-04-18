use candid::candid_method;
use cketh_common::eth_rpc::{Block, FeeHistory, LogEntry, RpcError};

use cketh_common::eth_rpc_client::providers::RpcService;
use cketh_common::eth_rpc_client::RpcConfig;
use cketh_common::logs::INFO;
use ic_canister_log::log;
use ic_canisters_http_types::{
    HttpRequest as AssetHttpRequest, HttpResponse as AssetHttpResponse, HttpResponseBuilder,
};
use ic_cdk::api::is_controller;
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use ic_cdk::{query, update};

use evm_rpc::*;

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
) -> MultiRpcResult<Option<FeeHistory>> {
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
    let response = do_json_rpc_request(
        ic_cdk::caller(),
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
    service: RpcService,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<u128, RpcError> {
    Ok(get_rpc_cost(
        &resolve_rpc_service(service)?,
        json_rpc_payload.len() as u64,
        max_response_bytes,
    ))
}

#[query(name = "getProviders")]
#[candid_method(query, rename = "getProviders")]
fn get_providers() -> Vec<ProviderView> {
    PROVIDERS.with(|p| {
        p.borrow()
            .iter()
            .map(|(_, provider)| provider.into())
            .collect::<Vec<ProviderView>>()
    })
}

#[update(name = "registerProvider", guard = "require_register_provider")]
#[candid_method(rename = "registerProvider")]
fn register_provider(provider: RegisterProviderArgs) -> u64 {
    do_register_provider(ic_cdk::caller(), provider)
}

#[update(name = "unregisterProvider")]
#[candid_method(rename = "unregisterProvider")]
fn unregister_provider(provider_id: u64) -> bool {
    let caller = ic_cdk::caller();
    do_unregister_provider(caller, is_controller(&caller), provider_id)
}

#[update(name = "updateProvider")]
#[candid_method(rename = "updateProvider")]
fn update_provider(provider: UpdateProviderArgs) {
    let caller = ic_cdk::caller();
    do_update_provider(caller, is_controller(&caller), provider)
}

#[update(name = "manageProvider", guard = "require_manage_or_controller")]
#[candid_method(rename = "manageProvider")]
fn manage_provider(args: ManageProviderArgs) {
    log!(
        INFO,
        "[{}] Managing provider: {}",
        ic_cdk::caller(),
        args.provider_id
    );
    do_manage_provider(args)
}

#[query(name = "getServiceProviderMap", guard = "require_manage_or_controller")]
#[candid_method(query, rename = "getServiceProviderMap")]
fn get_service_provider_map() -> Vec<(RpcService, u64)> {
    SERVICE_PROVIDER_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|(k, v)| Some((k.try_into().ok()?, v)))
            .collect()
    })
}

#[query(name = "getNodesInSubnet")]
#[candid_method(query, rename = "getNodesInSubnet")]
async fn get_nodes_in_subnet() -> u32 {
    UNSTABLE_SUBNET_SIZE.with(|n| *n.borrow())
}

#[query(name = "getAccumulatedCycleCount")]
#[candid_method(query, rename = "getAccumulatedCycleCount")]
fn get_accumulated_cycle_count(provider_id: u64) -> u128 {
    let caller = ic_cdk::caller();
    do_get_accumulated_cycle_count(caller, is_controller(&caller), provider_id)
}

#[update(name = "withdrawAccumulatedCycles")]
#[candid_method(rename = "withdrawAccumulatedCycles")]
async fn withdraw_accumulated_cycles(provider_id: u64, canister_id: Principal) {
    let caller = ic_cdk::caller();
    do_withdraw_accumulated_cycles(caller, is_controller(&caller), provider_id, canister_id).await
}

#[query(name = "__transform_json_rpc")]
fn transform(args: TransformArgs) -> HttpResponse {
    do_transform_http_request(args)
}

#[ic_cdk::init]
fn init(args: InitArgs) {
    post_upgrade(args);

    for provider in get_default_providers() {
        do_register_provider(ic_cdk::caller(), provider);
    }
    for (service, hostname) in get_default_service_provider_hostnames() {
        let provider = find_provider(|p| {
            Some(p.chain_id) == get_known_chain_id(&service) && p.hostname == hostname
        })
        .unwrap_or_else(|| {
            panic!(
                "Missing default provider for service {:?} with hostname {:?}",
                service, hostname
            )
        });
        set_service_provider(&service, &provider);
    }
}

#[ic_cdk::post_upgrade]
fn post_upgrade(args: InitArgs) {
    UNSTABLE_SUBNET_SIZE.with(|m| *m.borrow_mut() = args.nodes_in_subnet);
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

#[query(name = "stableSize", guard = "require_manage_or_controller")]
fn stable_size() -> u64 {
    ic_cdk::api::stable::stable64_size() * WASM_PAGE_SIZE
}

#[query(name = "stableRead", guard = "require_manage_or_controller")]
fn stable_read(offset: u64, length: u64) -> Vec<u8> {
    let mut buffer = vec![0; length as usize];
    ic_cdk::api::stable::stable64_read(offset, &mut buffer);
    buffer
}

#[update(guard = "require_manage_or_controller")]
#[candid_method]
fn authorize(principal: Principal, auth: Auth) -> bool {
    log!(
        INFO,
        "[{}] Authorizing `{:?}` for principal: {}",
        ic_cdk::caller(),
        auth,
        principal
    );
    do_authorize(principal, auth)
}

#[query(name = "getAuthorized", guard = "require_manage_or_controller")]
#[candid_method(query, rename = "getAuthorized")]
fn get_authorized(auth: Auth) -> Vec<Principal> {
    AUTH.with(|a| {
        let mut result = Vec::new();
        for (k, v) in a.borrow().iter() {
            if v.is_authorized(auth) {
                result.push(k.0);
            }
        }
        result
    })
}

#[update(guard = "require_manage_or_controller")]
#[candid_method]
fn deauthorize(principal: Principal, auth: Auth) -> bool {
    log!(
        INFO,
        "[{}] Deauthorizing `{:?}` for principal: {}",
        ic_cdk::caller(),
        auth,
        principal
    );
    do_deauthorize(principal, auth)
}

#[query(name = "getOpenRpcAccess", guard = "require_manage_or_controller")]
#[candid_method(query, rename = "getOpenRpcAccess")]
fn get_open_rpc_access() -> bool {
    METADATA.with(|m| m.borrow().get().open_rpc_access)
}

#[update(name = "setOpenRpcAccess", guard = "require_manage_or_controller")]
#[candid_method(rename = "setOpenRpcAccess")]
fn set_open_rpc_access(open_rpc_access: bool) {
    log!(
        INFO,
        "[{}] Setting open RPC access to `{}`",
        ic_cdk::caller(),
        open_rpc_access
    );
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.open_rpc_access = open_rpc_access;
        m.borrow_mut().set(metadata).unwrap();
    });
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
