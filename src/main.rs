use candid::{candid_method, CandidType};
use cketh_common::eth_rpc::{
    Block, FeeHistory, LogEntry, ProviderError, RpcError, SendRawTransactionResult,
};

use ic_canister_log::log;
use ic_canisters_http_types::{
    HttpRequest as AssetHttpRequest, HttpResponse as AssetHttpResponse, HttpResponseBuilder,
};
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use ic_cdk::{query, update};
use ic_nervous_system_common::{serve_logs, serve_logs_v2, serve_metrics};

use evm_rpc::*;

#[update(name = "eth_getLogs")]
#[candid_method(rename = "eth_getLogs")]
pub async fn eth_get_logs(
    source: RpcSource,
    args: candid_types::GetLogsArgs,
) -> MultiRpcResult<Vec<LogEntry>> {
    match CandidRpcClient::from_source(source) {
        Ok(source) => source.eth_get_logs(args).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_getBlockByNumber")]
#[candid_method(rename = "eth_getBlockByNumber")]
pub async fn eth_get_block_by_number(
    source: RpcSource,
    block: candid_types::BlockTag,
) -> MultiRpcResult<Block> {
    match CandidRpcClient::from_source(source) {
        Ok(source) => source.eth_get_block_by_number(block).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_getTransactionReceipt")]
#[candid_method(rename = "eth_getTransactionReceipt")]
pub async fn eth_get_transaction_receipt(
    source: RpcSource,
    hash: String,
) -> MultiRpcResult<Option<candid_types::TransactionReceipt>> {
    match CandidRpcClient::from_source(source) {
        Ok(source) => source.eth_get_transaction_receipt(hash).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_getTransactionCount")]
#[candid_method(rename = "eth_getTransactionCount")]
pub async fn eth_get_transaction_count(
    source: RpcSource,
    args: candid_types::GetTransactionCountArgs,
) -> MultiRpcResult<candid::Nat> {
    match CandidRpcClient::from_source(source) {
        Ok(source) => source.eth_get_transaction_count(args).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_feeHistory")]
#[candid_method(rename = "eth_feeHistory")]
pub async fn eth_fee_history(
    source: RpcSource,
    args: candid_types::FeeHistoryArgs,
) -> MultiRpcResult<Option<FeeHistory>> {
    match CandidRpcClient::from_source(source) {
        Ok(source) => source.eth_fee_history(args).await,
        Err(err) => Err(err).into(),
    }
}

#[update(name = "eth_sendRawTransaction")]
#[candid_method(rename = "eth_sendRawTransaction")]
pub async fn eth_send_raw_transaction(
    source: RpcSource,
    raw_signed_transaction_hex: String,
) -> MultiRpcResult<SendRawTransactionResult> {
    match CandidRpcClient::from_source(source) {
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
    source: JsonRpcSource,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<String, RpcError> {
    let response = do_json_rpc_request(
        ic_cdk::caller(),
        source.resolve()?,
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
    source: JsonRpcSource,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<u128, RpcError> {
    Ok(get_json_rpc_cost(
        &source.resolve().unwrap(),
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

#[update(name = "unregisterProvider", guard = "require_register_provider")]
#[candid_method(rename = "unregisterProvider")]
fn unregister_provider(provider_id: u64) -> bool {
    do_unregister_provider(ic_cdk::caller(), provider_id)
}

#[update(name = "updateProvider", guard = "require_register_provider")]
#[candid_method(rename = "updateProvider")]
fn update_provider(provider: UpdateProviderArgs) {
    do_update_provider(ic_cdk::caller(), provider)
}

#[query(name = "getAccumulatedCycleCount", guard = "require_register_provider")]
#[candid_method(query, rename = "getAccumulatedCycleCount")]
fn get_accumulated_cycle_count(provider_id: u64) -> u128 {
    let provider = PROVIDERS.with(|p| {
        p.borrow()
            .get(&provider_id)
            .ok_or(ProviderError::ProviderNotFound)
    });
    let provider = provider.expect("Provider not found");
    if ic_cdk::caller() != provider.owner {
        ic_cdk::trap("Not owner");
    }
    provider.cycles_owed
}

#[derive(CandidType)]
struct DepositCyclesArgs {
    canister_id: Principal,
}

#[update(
    name = "withdrawAccumulatedCycles",
    guard = "require_register_provider"
)]
#[candid_method(rename = "withdrawAccumulatedCycles")]
async fn withdraw_accumulated_cycles(provider_id: u64, canister_id: Principal) {
    let provider = PROVIDERS.with(|p| {
        p.borrow()
            .get(&provider_id)
            .ok_or(ProviderError::ProviderNotFound)
    });
    let mut provider = provider.expect("Provider not found");
    if ic_cdk::caller() != provider.owner {
        ic_cdk::trap("Not owner");
    }
    let amount = provider.cycles_owed;
    if amount < MINIMUM_WITHDRAWAL_CYCLES {
        ic_cdk::trap("Too few cycles to withdraw");
    }
    PROVIDERS.with(|p| {
        provider.cycles_owed = 0;
        p.borrow_mut().insert(provider_id, provider)
    });
    match ic_cdk::api::call::call_with_payment128(
        Principal::management_canister(),
        "deposit_cycles",
        (DepositCyclesArgs { canister_id },),
        amount,
    )
    .await
    {
        Ok(()) => add_metric!(cycles_withdrawn, amount),
        e => {
            // Refund on failure to send cycles.
            log!(
                INFO,
                "Unable to send {} cycles to {} for provider {}: {:?}",
                amount,
                canister_id,
                provider_id,
                e
            );
            let provider = PROVIDERS.with(|p| {
                p.borrow()
                    .get(&provider_id)
                    .ok_or(ProviderError::ProviderNotFound)
            });
            let mut provider = provider.expect("Provider not found during refund, cycles lost.");
            PROVIDERS.with(|p| {
                provider.cycles_owed += amount;
                p.borrow_mut().insert(provider_id, provider)
            });
        }
    };
}

#[query(name = "__transform_json_rpc")]
fn transform(args: TransformArgs) -> HttpResponse {
    do_transform_http_request(args)
}

#[ic_cdk::init]
fn init(args: InitArgs) {
    UNSTABLE_SUBNET_SIZE.with(|m| *m.borrow_mut() = args.nodes_in_subnet);

    for provider in get_default_providers() {
        do_register_provider(ic_cdk::caller(), provider);
    }
}

// #[ic_cdk::post_upgrade]
// fn post_upgrade() {}

#[query]
fn http_request(request: AssetHttpRequest) -> AssetHttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(encode_metrics),
        "/logs" => serve_logs_v2(request, &INFO, &ERROR),
        "/log/info" => serve_logs(&INFO),
        "/log/error" => serve_logs(&ERROR),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

#[query(name = "getMetrics")]
#[candid_method(query, rename = "getMetrics")]
fn get_metrics() -> Metrics {
    UNSTABLE_METRICS.with(|metrics| (*metrics.borrow()).clone())
}

#[query(guard = "require_admin_or_controller")]
fn stable_size() -> u64 {
    ic_cdk::api::stable::stable64_size() * WASM_PAGE_SIZE
}

#[query(guard = "require_admin_or_controller")]
fn stable_read(offset: u64, length: u64) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.resize(length as usize, 0);
    ic_cdk::api::stable::stable64_read(offset, buffer.as_mut_slice());
    buffer
}

#[update(guard = "require_admin_or_controller")]
fn stable_write(offset: u64, buffer: Vec<u8>) {
    let size = offset + buffer.len() as u64;
    let old_size = ic_cdk::api::stable::stable64_size() * WASM_PAGE_SIZE;
    if size > old_size {
        let old_pages = old_size / WASM_PAGE_SIZE;
        let pages = (size + (WASM_PAGE_SIZE - 1)) / WASM_PAGE_SIZE;
        ic_cdk::api::stable::stable64_grow(pages - old_pages).unwrap();
    }
    ic_cdk::api::stable::stable64_write(offset, buffer.as_slice());
}

#[update(guard = "require_admin_or_controller")]
#[candid_method]
fn authorize(principal: Principal, auth: Auth) {
    do_authorize(principal, auth)
}

#[query(name = "getAuthorized", guard = "require_admin_or_controller")]
#[candid_method(query, rename = "getAuthorized")]
fn get_authorized(auth: Auth) -> Vec<String> {
    AUTH.with(|a| {
        let mut result = Vec::new();
        for (k, v) in a.borrow().iter() {
            if !v.is_authorized(auth) {
                result.push(k.0.to_string());
            }
        }
        result
    })
}

#[update(guard = "require_admin_or_controller")]
#[candid_method]
fn deauthorize(principal: Principal, auth: Auth) {
    do_deauthorize(principal, auth)
}

#[query(name = "getOpenRpcAccess", guard = "require_admin_or_controller")]
#[candid_method(query, rename = "getOpenRpcAccess")]
fn get_open_rpc_access() -> bool {
    METADATA.with(|m| m.borrow().get().open_rpc_access)
}

#[update(name = "setOpenRpcAccess", guard = "require_admin_or_controller")]
#[candid_method(rename = "setOpenRpcAccess")]
fn set_open_rpc_access(open_rpc_access: bool) {
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
