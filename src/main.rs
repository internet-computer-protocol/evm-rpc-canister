use candid::{candid_method, CandidType};
use ic_canister_log::log;
use ic_cdk::api::management_canister::http_request::{HttpHeader, HttpResponse, TransformArgs};
use ic_cdk::{query, update};
// use ic_canisters_http_types::{
//     HttpRequest as AssetHttpRequest, HttpResponse as AssetHttpResponse, HttpResponseBuilder,
// };
// use ic_nervous_system_common::{serve_logs, serve_logs_v2, serve_metrics};

use ic_eth_rpc::*;

#[ic_cdk_macros::query]
#[candid_method(query)]
pub fn verify_signature(eth_address: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    do_verify_signature(&eth_address, message, signature)
}

#[update]
#[candid_method]
async fn request(
    source: Source,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<Vec<u8>, EthRpcError> {
    do_http_request(source.resolve()?, &json_rpc_payload, max_response_bytes).await
}

#[query]
#[candid_method(query)]
fn request_cost(
    source: Source,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<u128, EthRpcError> {
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
                base_url: e.base_url,
                cycles_per_call: e.cycles_per_call,
                cycles_per_message_byte: e.cycles_per_message_byte,
                active: e.active,
            })
            .collect::<Vec<ProviderView>>()
    })
}

#[update(guard = "require_register_provider")]
#[candid_method]
fn register_provider(provider: RegisterProvider) -> u64 {
    do_register_provider(provider)
}

#[update(guard = "require_register_provider")]
#[candid_method]
fn unregister_provider(provider_id: u64) -> bool {
    do_unregister_provider(provider_id)
}

// #[update(guard = "require_register_provider")]
#[update(guard = "require_admin_or_controller")]
#[candid_method]
fn update_provider(provider: UpdateProvider) {
    do_update_provider(provider)
}

#[query(guard = "require_register_provider")]
#[candid_method(query)]
fn get_owed_cycles(provider_id: u64) -> u128 {
    let provider = PROVIDERS.with(|p| {
        p.borrow()
            .get(&provider_id)
            .ok_or(EthRpcError::ProviderNotFound)
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
async fn withdraw_owed_cycles(provider_id: u64, canister_id: Principal) {
    let provider = PROVIDERS.with(|p| {
        p.borrow()
            .get(&provider_id)
            .ok_or(EthRpcError::ProviderNotFound)
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
                    .ok_or(EthRpcError::ProviderNotFound)
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
    HttpResponse {
        status: args.response.status.clone(),
        body: args.response.body,
        // Strip headers as they contain the Date which is not necessarily the same
        // and will prevent consensus on the result.
        headers: Vec::<HttpHeader>::new(),
    }
}

#[ic_cdk::init]
fn init() {
    SERVICE_HOSTS_ALLOWLIST
        .with(|a| (*a.borrow_mut()) = AllowlistSet::from_iter(INITIAL_SERVICE_HOSTS_ALLOWLIST));

    stable_authorize(ic_cdk::caller());

    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = DEFAULT_NODES_IN_SUBNET;
        metadata.open_rpc_access = DEFAULT_OPEN_RPC_ACCESS;
        m.borrow_mut().set(metadata).unwrap();
    });

    for provider in get_default_providers() {
        do_register_provider(provider);
    }
}

// #[ic_cdk::post_upgrade]
// fn post_upgrade() {}

// #[query]
// fn http_request(request: AssetHttpRequest) -> AssetHttpResponse {
//     match request.path() {
//         "/metrics" => serve_metrics(encode_metrics),
//         "/logs" => serve_logs_v2(request, &INFO, &ERROR),
//         "/log/info" => serve_logs(&INFO),
//         "/log/error" => serve_logs(&ERROR),
//         _ => HttpResponseBuilder::not_found().build(),
//     }
// }

#[update(guard = "require_stable_authorized")]
fn stable_authorize(principal: Principal) {
    AUTH_STABLE.with(|a| a.borrow_mut().insert(principal));
}

#[query(guard = "require_stable_authorized")]
fn stable_size() -> u64 {
    ic_cdk::api::stable::stable64_size() * WASM_PAGE_SIZE
}

#[query(guard = "require_stable_authorized")]
fn stable_read(offset: u64, length: u64) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.resize(length as usize, 0);
    ic_cdk::api::stable::stable64_read(offset, buffer.as_mut_slice());
    buffer
}

#[update(guard = "require_stable_authorized")]
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
            if v & (auth.clone() as u32) != 0 {
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
        CandidSource::File(Path::new("candid/ic_eth.did")),
    )
    .unwrap();
}
