use async_trait::async_trait;
use candid::{candid_method, CandidType};
use cketh_common::eth_rpc::{
    Block, BlockSpec, FeeHistory, GetLogsParam, HttpOutcallError, JsonRpcReply, LogEntry,
    ProviderError, RpcError, SendRawTransactionResult,
};
use cketh_common::eth_rpc_client::requests::GetTransactionCountParams;
use cketh_common::eth_rpc_client::{providers::RpcNodeProvider, EthRpcClient};
use cketh_common::eth_rpc_client::{MultiCallError, RpcTransport};
use cketh_common::lifecycle::EvmNetwork;
use cketh_common::numeric::TransactionCount;
use ic_canister_log::log;
use ic_canisters_http_types::{
    HttpRequest as AssetHttpRequest, HttpResponse as AssetHttpResponse, HttpResponseBuilder,
};
use ic_cdk::api::management_canister::http_request::{HttpHeader, HttpResponse, TransformArgs};
use ic_cdk::{query, update};
use ic_nervous_system_common::{serve_logs, serve_logs_v2, serve_metrics};

use evm_rpc::*;
use serde::de::DeserializeOwned;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanisterTransport;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RpcTransport for CanisterTransport {
    fn get_subnet_size() -> u32 {
        METADATA.with(|m| m.borrow().get().nodes_in_subnet)
    }

    async fn call_json_rpc<T: DeserializeOwned>(
        service: RpcNodeProvider,
        json: &str,
        max_response_bytes: u64,
    ) -> Result<T, RpcError> {
        let response = do_http_request(
            ic_cdk::caller(),
            ResolvedSource::Url(service.url().to_string()),
            json,
            max_response_bytes,
        )
        .await
        .unwrap();
        let status = get_http_response_status(response.status.clone());
        let body = get_http_response_body(response)?;
        let json: JsonRpcReply<T> = serde_json::from_str(&body).unwrap_or_else(|e| {
            Err(HttpOutcallError::InvalidHttpJsonRpcResponse {
                status,
                body,
                parsing_error: Some(format!("JSON response parse error: {e}")),
            })
        })?;
        json.result.into()
    }
}

fn get_rpc_client(source: CandidRpcSource) -> Result<EthRpcClient<CanisterTransport>, RpcError> {
    fn validate_providers<T>(opt_vec: Option<Vec<T>>) -> Result<Option<Vec<T>>, RpcError> {
        Ok(match opt_vec {
            Some(v) if v.is_empty() => Err(ProviderError::ProviderNotFound)?,
            opt => opt,
        })
    }
    if !is_rpc_allowed(&ic_cdk::caller()) {
        // inc_metric!(eth_*_err_no_permission);
        return Err(ProviderError::NoPermission.into());
    }
    Ok(match source {
        CandidRpcSource::Ethereum { service } => EthRpcClient::new(
            EvmNetwork::Ethereum,
            validate_providers(Some(vec![service.unwrap_or(
                cketh_common::eth_rpc_client::providers::EthereumProvider::Cloudflare,
            )]))?
            .map(|p| p.into_iter().map(RpcNodeProvider::Ethereum).collect()),
        ),
        CandidRpcSource::Sepolia { service } => EthRpcClient::new(
            EvmNetwork::Sepolia,
            validate_providers(Some(vec![service.unwrap_or(
                cketh_common::eth_rpc_client::providers::SepoliaProvider::PublicNode,
            )]))?
            .map(|p| p.into_iter().map(RpcNodeProvider::Sepolia).collect()),
        ),
    })
}

fn wrap_result<T>(result: Result<T, MultiCallError<T>>) -> RpcResult<T> {
    match result {
        Ok(value) => Ok(value),
        Err(err) => match err {
            MultiCallError::ConsistentError(e) => Err(e),
            MultiCallError::InconsistentResults(_r) => {
                unreachable!()
            }
        },
    }
}

#[ic_cdk_macros::update]
#[candid_method]
pub async fn eth_get_logs(
    source: CandidRpcSource,
    args: candid_types::GetLogsArgs,
) -> RpcResult<Vec<LogEntry>> {
    let args: GetLogsParam = match args.try_into() {
        Ok(args) => args,
        Err(err) => return Err(RpcError::from(err)),
    };
    let client = get_rpc_client(source)?;
    wrap_result(client.eth_get_logs(args).await)
}

#[ic_cdk_macros::update]
#[candid_method]
pub async fn eth_get_block_by_number(
    source: CandidRpcSource,
    block: candid_types::BlockSpec,
) -> RpcResult<Block> {
    let block: BlockSpec = block.into();
    let client = get_rpc_client(source)?;
    wrap_result(client.eth_get_block_by_number(block).await)
}

#[ic_cdk_macros::update]
#[candid_method]
pub async fn eth_get_transaction_receipt(
    source: CandidRpcSource,
    hash: candid_types::Hash,
) -> RpcResult<Option<candid_types::TransactionReceipt>> {
    let client = get_rpc_client(source)?;
    wrap_result(client.eth_get_transaction_receipt(hash).await)
        .map(|option| option.map(|r| r.into()))
}

#[ic_cdk_macros::update]
#[candid_method]
pub async fn eth_get_transaction_count(
    source: CandidRpcSource,
    args: candid_types::GetTransactionCountArgs,
) -> RpcResult<TransactionCount> {
    let args: GetTransactionCountParams = match args.try_into() {
        Ok(args) => args,
        Err(err) => return Err(RpcError::from(err)),
    };
    let client = get_rpc_client(source)?;
    wrap_result(client.eth_get_transaction_count(args).await)
}

#[ic_cdk_macros::update]
#[candid_method]
pub async fn eth_fee_history(
    source: CandidRpcSource,
    args: candid_types::FeeHistoryArgs,
) -> Result<Option<FeeHistory>, RpcError> {
    let args = args.into();
    let client = get_rpc_client(source)?;
    Ok(client.eth_fee_history(args).await?.into())
}

#[ic_cdk_macros::update]
#[candid_method]
pub async fn eth_send_raw_transaction(
    source: CandidRpcSource,
    raw_signed_transaction_hex: String,
) -> Result<SendRawTransactionResult, RpcError> {
    let client = get_rpc_client(source)?;
    client
        .eth_send_raw_transaction(raw_signed_transaction_hex)
        .await
}

#[ic_cdk_macros::query]
#[candid_method(query)]
pub fn verify_signature(signed_message: SignedMessage) -> bool {
    do_verify_signature(
        &signed_message.address,
        signed_message.message.into(),
        signed_message.signature,
    )
}

#[update]
#[candid_method]
async fn request(
    source: Source,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<String, RpcError> {
    let response = do_http_request(
        ic_cdk::caller(),
        source.resolve()?,
        &json_rpc_payload,
        max_response_bytes,
    )
    .await?;
    get_http_response_body(response)
}

#[query]
#[candid_method(query)]
fn request_cost(
    source: Source,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<u128, RpcError> {
    Ok(get_request_cost(
        &source.resolve().unwrap(),
        &json_rpc_payload,
        max_response_bytes,
    ))
}

#[query]
#[candid_method(query)]
fn get_providers() -> Vec<ProviderView> {
    PROVIDERS.with(|p| {
        p.borrow()
            .iter()
            .map(|(_, e)| ProviderView {
                provider_id: e.provider_id,
                owner: e.owner,
                chain_id: e.chain_id,
                hostname: e.hostname,
                cycles_per_call: e.cycles_per_call,
                cycles_per_message_byte: e.cycles_per_message_byte,
                primary: e.primary,
            })
            .collect::<Vec<ProviderView>>()
    })
}

#[update(guard = "require_register_provider")]
#[candid_method]
fn register_provider(provider: RegisterProvider) -> u64 {
    do_register_provider(ic_cdk::caller(), provider)
}

#[update(guard = "require_register_provider")]
#[candid_method]
fn unregister_provider(provider_id: u64) -> bool {
    do_unregister_provider(ic_cdk::caller(), provider_id)
}

#[update(guard = "require_register_provider")]
#[candid_method]
fn update_provider(provider: UpdateProvider) {
    do_update_provider(ic_cdk::caller(), provider)
}

#[query(guard = "require_register_provider")]
#[candid_method(query)]
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

#[update(guard = "require_register_provider")]
#[candid_method]
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
        Ok(()) => (),
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

#[query(name = "__transform_evm_rpc")]
fn transform(args: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: args.response.status,
        body: canonicalize_json(&args.response.body).unwrap_or(args.response.body),
        // Strip headers as they contain the Date which is not necessarily the same
        // and will prevent consensus on the result.
        headers: Vec::<HttpHeader>::new(),
    }
}

#[ic_cdk::init]
fn init() {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = DEFAULT_NODES_IN_SUBNET;
        metadata.open_rpc_access = DEFAULT_OPEN_RPC_ACCESS;
        m.borrow_mut().set(metadata).unwrap();
    });

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

#[query(guard = "require_admin_or_controller")]
#[candid_method(query)]
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

#[update(guard = "require_admin_or_controller")]
#[candid_method]
fn set_open_rpc_access(open_rpc_access: bool) {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.open_rpc_access = open_rpc_access;
        m.borrow_mut().set(metadata).unwrap();
    });
}

#[query(guard = "require_admin_or_controller")]
#[candid_method(query)]
fn get_open_rpc_access() -> bool {
    METADATA.with(|m| m.borrow().get().open_rpc_access)
}

#[update(guard = "require_admin_or_controller")]
#[candid_method]
fn set_nodes_in_subnet(nodes_in_subnet: u32) {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = nodes_in_subnet;
        m.borrow_mut().set(metadata).unwrap();
    });
}

#[query(guard = "require_admin_or_controller")]
#[candid_method(query)]
fn get_nodes_in_subnet() -> u32 {
    METADATA.with(|m| m.borrow().get().nodes_in_subnet)
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
    use candid::utils::{service_compatible, CandidSource};
    use std::path::Path;

    candid::export_service!();
    let new_interface = __export_service();

    service_compatible(
        CandidSource::Text(&new_interface),
        CandidSource::File(Path::new("candid/evm_rpc.did")),
    )
    .unwrap();
}
