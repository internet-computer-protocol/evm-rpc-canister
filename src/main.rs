use candid::{candid_method, CandidType, Decode, Deserialize, Encode, Principal};
use ic_canister_log::{declare_log_buffer, log};
use ic_canisters_http_types::{
    HttpRequest as AssetHttpRequest, HttpResponse as AssetHttpResponse, HttpResponseBuilder,
};
use ic_cdk::api::management_canister::http_request::{
    http_request as make_http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod,
    HttpResponse, TransformArgs, TransformContext,
};
use ic_nervous_system_common::{serve_logs, serve_logs_v2, serve_metrics};
#[cfg(not(target_arch = "wasm32"))]
use ic_stable_structures::file_mem::FileMemory;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
#[cfg(target_arch = "wasm32")]
use ic_stable_structures::DefaultMemoryImpl;
use ic_stable_structures::{BoundedStorable, Cell, StableBTreeMap, Storable};
#[macro_use]
extern crate num_derive;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::hash_set::HashSet;
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::fs::File;

const INGRESS_OVERHEAD_BYTES: u128 = 100;
const INGRESS_MESSAGE_RECEIVED_COST: u128 = 1_200_000u128;
const INGRESS_MESSAGE_BYTE_RECEIVED_COST: u128 = 2_000u128;
const HTTP_OUTCALL_REQUEST_COST: u128 = 400_000_000u128;
const HTTP_OUTCALL_BYTE_RECEIEVED_COST: u128 = 100_000u128;
const SUBNET_SIZE: u128 = 13; // App subnet

const MINIMUM_WITHDRAWAL_CYCLES: u128 = 1_000_000_000u128;

const STRING_STORABLE_MAX_SIZE: u32 = 100;
const WASM_PAGE_SIZE: u64 = 65536;

const INITIAL_SERVICE_HOSTS_ALLOWLIST: &[&str] = &[
    "cloudflare-eth.com",
    "ethereum.publicnode.com",
    "eth-mainnet.g.alchemy.com",
    "eth-goerli.g.alchemy.com",
    "rpc.flashbots.net",
    "eth-mainnet.blastapi.io",
    "ethereumnodelight.app.runonflux.io",
    "eth.nownodes.io",
    "rpc.ankr.com/eth_goerli",
    "mainnet.infura.io",
    "eth.getblock.io",
    "rpc.kriptonio.com",
    "api.0x.org",
    "erigon-mainnet--rpc.datahub.figment.io",
    "archivenode.io",
    "eth-mainnet.nodereal.io",
    "ethereum-mainnet.s.chainbase.online",
    "eth.llamarpc.com",
    "ethereum-mainnet-rpc.allthatnode.com",
    "api.zmok.io",
    "in-light.eth.linkpool.iono",
    "api.mycryptoapi.com",
    "mainnet.eth.cloud.ava.dono",
    "eth-mainnet.gateway.pokt.network",
];

// Static permissions. The canister creator is also authorized for all permissions.

// Principals allowed to send JSON RPCs.
const OPEN_RPC_ACCESS: bool = true;
const RPC_ALLOWLIST: &[&str] = &[];
// Principals allowed to registry API keys.
const REGISTER_PROVIDER_ALLOWLIST: &[&str] = &[];
// Principals that will not be charged cycles to send JSON RPCs.
const FREE_RPC_ALLOWLIST: &[&str] = &[];
// Principals who have Admin authorization.
const AUTHORIZED_ADMIN: &[&str] = &[];

type AllowlistSet = HashSet<&'static &'static str>;

#[allow(unused)] // Some compiler quirk causes this to be reported as unused.
#[cfg(not(target_arch = "wasm32"))]
type Memory = VirtualMemory<FileMemory>;
#[cfg(target_arch = "wasm32")]
type Memory = VirtualMemory<DefaultMemoryImpl>;

declare_log_buffer!(name = INFO, capacity = 1000);
declare_log_buffer!(name = ERROR, capacity = 1000);

#[derive(Default)]
struct Metrics {
    json_rpc_requests: u64,
    json_rpc_request_cycles_charged: u128,
    json_rpc_request_cycles_refunded: u128,
    json_rpc_request_err_no_permission: u64,
    json_rpc_request_err_service_url_host_not_allowed: u64,
    json_rpc_request_err_http_request_error: u64,
    json_rpc_host_requests: HashMap<String, u64>,
}

#[derive(Clone, Debug, PartialEq, CandidType, FromPrimitive, Deserialize)]
enum Auth {
    Admin,
    Rpc,
    RegisterProvider,
    FreeRpc,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct Metadata {
    next_provider_id: u64,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
struct StringStorable(String);

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
struct PrincipalStorable(Principal);

impl Storable for StringStorable {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        // String already implements `Storable`.
        self.0.to_bytes()
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self(String::from_bytes(bytes))
    }
}

impl BoundedStorable for StringStorable {
    const MAX_SIZE: u32 = STRING_STORABLE_MAX_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for PrincipalStorable {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::from(self.0.as_slice())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self(Principal::from_slice(&bytes))
    }
}

impl BoundedStorable for PrincipalStorable {
    const MAX_SIZE: u32 = 29;
    const IS_FIXED_SIZE: bool = false;
}

#[derive(Debug, CandidType)]
struct RegisteredProvider {
    provider_id: u64,
    owner: Principal,
    chain_id: u64,
    service_url: String,
    cycles_per_call: u64,
    cycles_per_message_byte: u64,
}

#[derive(Debug, CandidType, Deserialize)]
struct RegisterProvider {
    chain_id: u64,
    service_url: String,
    api_key: String,
    cycles_per_call: u64,
    cycles_per_message_byte: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct Provider {
    provider_id: u64,
    owner: Principal,
    chain_id: u64,
    service_url: String,
    api_key: String,
    cycles_per_call: u64,
    cycles_per_message_byte: u64,
    cycles_owed: u128,
}

impl Storable for Metadata {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}

impl Storable for Provider {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}

impl BoundedStorable for Provider {
    const MAX_SIZE: u32 = 256; // A reasonable limit.
    const IS_FIXED_SIZE: bool = false;
}

thread_local! {
    // Transient static data: this is reset when the canister is upgraded.
    static METRICS: RefCell<Metrics> = RefCell::new(Metrics::default());
    static SERVICE_HOSTS_ALLOWLIST: RefCell<AllowlistSet> = RefCell::new(AllowlistSet::new());
    static AUTH_STABLE: RefCell<HashSet<Principal>> = RefCell::new(HashSet::<Principal>::new());

    // Stable static data: this is preserved when the canister is upgraded.
    #[cfg(not(target_arch = "wasm32"))]
    static MEMORY_MANAGER: RefCell<MemoryManager<FileMemory>> =
        RefCell::new(MemoryManager::init(FileMemory::new(File::open("stable_memory.bin").unwrap())));
    #[cfg(target_arch = "wasm32")]
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static METADATA: RefCell<Cell<Metadata, Memory>> = RefCell::new(Cell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
            <Metadata>::default()).unwrap());
    static AUTH: RefCell<StableBTreeMap<PrincipalStorable, u32, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))));
    static PROVIDERS: RefCell<StableBTreeMap<u64, Provider, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))));
}

#[derive(CandidType, Debug)]
enum EthRpcError {
    NoPermission,
    TooFewCycles(String),
    ServiceUrlParseError,
    ServiceUrlHostMissing,
    ServiceUrlHostNotAllowed,
    ProviderNotFound,
    HttpRequestError { code: u32, message: String },
}

#[macro_export]
macro_rules! inc_metric {
    ($metric:ident) => {{
        METRICS.with(|m| m.borrow_mut().$metric += 1);
    }};
}

#[macro_export]
macro_rules! inc_metric_entry {
    ($metric:ident, $entry:expr) => {{
        METRICS.with(|m| {
            m.borrow_mut()
                .$metric
                .entry($entry.clone())
                .and_modify(|counter| *counter += 1)
                .or_insert(1);
        });
    }};
}

#[macro_export]
macro_rules! add_metric {
    ($metric:ident, $value:expr) => {{
        METRICS.with(|m| m.borrow_mut().$metric += $value);
    }};
}

#[macro_export]
macro_rules! get_metric {
    ($metric:ident) => {{
        METRICS.with(|m| m.borrow().$metric)
    }};
}

#[ic_cdk_macros::update]
#[candid_method]
async fn json_rpc_request(
    json_rpc_payload: String,
    service_url: String,
    max_response_bytes: u64,
) -> Result<Vec<u8>, EthRpcError> {
    json_rpc_request_internal(json_rpc_payload, service_url, max_response_bytes, None).await
}

#[ic_cdk_macros::update]
#[candid_method]
async fn json_rpc_provider_request(
    json_rpc_payload: String,
    provider_id: u64,
    max_response_bytes: u64,
) -> Result<Vec<u8>, EthRpcError> {
    let provider = PROVIDERS.with(|p| {
        p.borrow()
            .get(&provider_id)
            .ok_or(EthRpcError::ProviderNotFound)
    });
    let provider = provider?;
    let service_url = provider.service_url.clone() + &provider.api_key;
    json_rpc_request_internal(
        json_rpc_payload,
        service_url,
        max_response_bytes,
        Some(provider),
    )
    .await
}

async fn json_rpc_request_internal(
    json_rpc_payload: String,
    service_url: String,
    max_response_bytes: u64,
    provider: Option<Provider>,
) -> Result<Vec<u8>, EthRpcError> {
    inc_metric!(json_rpc_requests);
    if !authorized(Auth::Rpc) {
        inc_metric!(json_rpc_request_err_no_permission);
        return Err(EthRpcError::NoPermission);
    }
    let cycles_available = ic_cdk::api::call::msg_cycles_available128();
    let parsed_url = url::Url::parse(&service_url).or(Err(EthRpcError::ServiceUrlParseError))?;
    let host = parsed_url
        .host_str()
        .ok_or(EthRpcError::ServiceUrlHostMissing)?
        .to_string();
    if SERVICE_HOSTS_ALLOWLIST.with(|a| !a.borrow().contains(&host.as_str())) {
        log!(INFO, "host not allowed {}", host);
        inc_metric!(json_rpc_request_err_service_url_host_not_allowed);
        return Err(EthRpcError::ServiceUrlHostNotAllowed);
    }
    let provider_cost = match &provider {
        None => 0,
        Some(provider) => json_rpc_provider_cycles_cost(
            &json_rpc_payload,
            provider.cycles_per_call,
            provider.cycles_per_message_byte,
        ),
    };
    let cost =
        json_rpc_cycles_cost(&json_rpc_payload, &service_url, max_response_bytes) + provider_cost;
    if !authorized(Auth::FreeRpc) {
        if cycles_available < cost {
            return Err(EthRpcError::TooFewCycles(format!(
                "requires {} cycles, got {} cycles",
                cost, cycles_available
            )));
        }
        ic_cdk::api::call::msg_cycles_accept128(cost);
        if let Some(mut provider) = provider {
            provider.cycles_owed += provider_cost;
            PROVIDERS.with(|p| {
                // Error should not happen here as it was checked before.
                p.borrow_mut()
                    .insert(provider.provider_id, provider)
                    .expect("unable to update Provider");
            });
        }
        add_metric!(json_rpc_request_cycles_charged, cost);
        add_metric!(json_rpc_request_cycles_refunded, cycles_available - cost);
    }
    inc_metric_entry!(json_rpc_host_requests, host);
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
        url: service_url,
        max_response_bytes: Some(max_response_bytes),
        method: HttpMethod::POST,
        headers: request_headers,
        body: Some(json_rpc_payload.as_bytes().to_vec()),
        transform: Some(TransformContext::from_name("transform".to_string(), vec![])),
    };
    match make_http_request(request, cost).await {
        Ok((result,)) => Ok(result.body),
        Err((r, m)) => {
            inc_metric!(json_rpc_request_err_http_request_error);
            Err(EthRpcError::HttpRequestError {
                code: r as u32,
                message: m,
            })
        }
    }
}

fn json_rpc_cycles_cost(
    json_rpc_payload: &str,
    service_url: &str,
    max_response_bytes: u64,
) -> u128 {
    let ingress_bytes =
        (json_rpc_payload.len() + service_url.len()) as u128 + INGRESS_OVERHEAD_BYTES;
    INGRESS_MESSAGE_RECEIVED_COST
        + INGRESS_MESSAGE_BYTE_RECEIVED_COST * ingress_bytes
        + HTTP_OUTCALL_REQUEST_COST
        + HTTP_OUTCALL_BYTE_RECEIEVED_COST * (ingress_bytes + max_response_bytes as u128)
}

fn json_rpc_provider_cycles_cost(
    json_rpc_payload: &str,
    provider_cycles_per_call: u64,
    provider_cycles_per_message_byte: u64,
) -> u128 {
    let base_cost = provider_cycles_per_call as u128
        + provider_cycles_per_message_byte as u128
        + json_rpc_payload.len() as u128;
    base_cost * SUBNET_SIZE / 13
}

#[ic_cdk::query]
#[candid_method(query)]
fn get_providers() -> Vec<RegisteredProvider> {
    PROVIDERS.with(|p| {
        p.borrow()
            .iter()
            .map(|(_, e)| RegisteredProvider {
                provider_id: e.provider_id,
                owner: e.owner,
                chain_id: e.chain_id,
                service_url: e.service_url,
                cycles_per_call: e.cycles_per_call,
                cycles_per_message_byte: e.cycles_per_message_byte,
            })
            .collect::<Vec<RegisteredProvider>>()
    })
}

#[ic_cdk::update(guard = "is_authorized_register_provider")]
#[candid_method]
fn register_provider(provider: RegisterProvider) {
    let provider_id = METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.next_provider_id += 1;
        m.borrow_mut().set(metadata.clone()).unwrap();
        metadata.next_provider_id - 1
    });
    PROVIDERS.with(|p| {
        p.borrow_mut().insert(
            provider_id,
            Provider {
                provider_id,
                owner: ic_cdk::caller(),
                chain_id: provider.chain_id,
                service_url: provider.service_url,
                api_key: provider.api_key,
                cycles_per_call: provider.cycles_per_call,
                cycles_per_message_byte: provider.cycles_per_message_byte,
                cycles_owed: 0,
            },
        )
    });
}

#[ic_cdk::update(guard = "is_authorized_register_provider")]
#[candid_method]
fn unregister_provider(provider_id: u64) {
    PROVIDERS.with(|p| {
        if let Some(provider) = p.borrow().get(&provider_id) {
            if provider.owner == ic_cdk::caller() || authorized(Auth::Admin) {
                p.borrow_mut().remove(&provider_id);
            } else {
                ic_cdk::trap("Not authorized");
            }
        }
    });
}

#[ic_cdk::query(guard = "is_authorized_register_provider")]
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

#[ic_cdk::update(guard = "is_authorized_register_provider")]
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
        // Note: cycles are not refunded (would that be exploitable?).
        Err(e) => ic_cdk::trap(&format!("failed to deposit_cycles: {:?}", e)),
    };
}

#[ic_cdk_macros::query(name = "transform")]
fn transform(args: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: args.response.status.clone(),
        body: args.response.body,
        // Strip headers as they contain the Date which is not necessarily the same
        // and will prevent consensus on the result.
        headers: Vec::<HttpHeader>::new(),
    }
}

#[ic_cdk_macros::init]
fn init() {
    initialize();
}

#[ic_cdk_macros::post_upgrade]
fn post_upgrade() {
    initialize();
    stable_authorize(ic_cdk::caller());
}

fn initialize() {
    SERVICE_HOSTS_ALLOWLIST
        .with(|a| (*a.borrow_mut()) = AllowlistSet::from_iter(INITIAL_SERVICE_HOSTS_ALLOWLIST));

    for principal in RPC_ALLOWLIST.iter() {
        authorize(to_principal(principal), Auth::Rpc);
    }
    for principal in REGISTER_PROVIDER_ALLOWLIST.iter() {
        authorize(to_principal(principal), Auth::RegisterProvider);
    }
    for principal in FREE_RPC_ALLOWLIST.iter() {
        authorize(to_principal(principal), Auth::FreeRpc);
    }
    for principal in AUTHORIZED_ADMIN.iter() {
        authorize(to_principal(principal), Auth::Admin);
    }
}

fn to_principal(principal: &str) -> Principal {
    match Principal::from_text(principal) {
        Ok(p) => p,
        Err(e) => ic_cdk::trap(&format!(
            "failed to convert Principal {} {:?}",
            principal, e
        )),
    }
}

#[ic_cdk::query]
fn http_request(request: AssetHttpRequest) -> AssetHttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(encode_metrics),
        "/logs" => serve_logs_v2(request, &INFO, &ERROR),
        "/log/info" => serve_logs(&INFO),
        "/log/error" => serve_logs(&ERROR),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

fn is_stable_authorized() -> Result<(), String> {
    AUTH_STABLE.with(|a| {
        if ic_cdk::api::is_controller(&ic_cdk::caller()) || a.borrow().contains(&ic_cdk::caller()) {
            Ok(())
        } else {
            Err("You are not stable authorized".to_string())
        }
    })
}

#[ic_cdk_macros::update(guard = "is_stable_authorized")]
fn stable_authorize(principal: Principal) {
    AUTH_STABLE.with(|a| a.borrow_mut().insert(principal));
}

#[ic_cdk_macros::query(guard = "is_stable_authorized")]
fn stable_size() -> u64 {
    ic_cdk::api::stable::stable64_size() * WASM_PAGE_SIZE
}

#[ic_cdk_macros::query(guard = "is_stable_authorized")]
fn stable_read(offset: u64, length: u64) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.resize(length as usize, 0);
    ic_cdk::api::stable::stable64_read(offset, buffer.as_mut_slice());
    buffer
}

#[ic_cdk_macros::update(guard = "is_stable_authorized")]
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

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid_method]
fn authorize(principal: Principal, auth: Auth) {
    AUTH.with(|a| {
        let mut auth_map = a.borrow_mut();
        let principal = PrincipalStorable(principal);
        if let Some(v) = auth_map.get(&principal) {
            auth_map.insert(principal, v | (1 << (auth as u32)));
        } else {
            auth_map.insert(principal, 1 << (auth as u32));
        }
    });
}

#[ic_cdk_macros::query(guard = "is_authorized")]
#[candid_method]
fn get_authorized(auth: Auth) -> Vec<String> {
    AUTH.with(|a| {
        let mut result = Vec::new();
        for (k, v) in a.borrow().iter() {
            if v & (1 << (auth.clone() as u32)) != 0 {
            result.push(k.0.to_string());
        }}
        result
    })
}

#[ic_cdk_macros::update(guard = "is_authorized")]
#[candid_method]
fn deauthorize(principal: Principal, auth: Auth) {
    AUTH.with(|a| {
        let mut auth_map = a.borrow_mut();
        let principal = PrincipalStorable(principal);
        if let Some(v) = auth_map.get(&principal) {
            auth_map.insert(principal, v & !(1 << (auth as u32)));
        }
    });
}

fn is_authorized() -> Result<(), String> {
    if ic_cdk::api::is_controller(&ic_cdk::caller()) || authorized(Auth::Admin) {
        Ok(())
    } else {
        Err("You are not authorized".to_string())
    }
}

fn is_authorized_register_provider() -> Result<(), String> {
    if ic_cdk::api::is_controller(&ic_cdk::caller()) || authorized(Auth::RegisterProvider) {
        Ok(())
    } else {
        Err("You are not authorized".to_string())
    }
}

fn authorized(auth: Auth) -> bool {
    if auth == Auth::Rpc && OPEN_RPC_ACCESS {
        return true;
    }
    let caller = PrincipalStorable(ic_cdk::caller());
    AUTH.with(|a| {
        if let Some(v) = a.borrow().get(&caller) {
            (v & (1 << (auth as u32))) != 0
        } else {
            false
        }
    })
}

/// Encode the metrics in a format that can be understood by Prometheus.
fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "canister_version",
        ic_cdk::api::canister_version() as f64,
        "Canister version.",
    )?;
    w.encode_gauge(
        "stable_memory_pages",
        ic_cdk::api::stable::stable64_size() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_counter(
        "json_rpc_requests",
        get_metric!(json_rpc_requests) as f64,
        "Number of json_rpc_request() calls.",
    )?;
    w.encode_counter(
        "json_rpc_request_cycles_charged",
        get_metric!(json_rpc_request_cycles_charged) as f64,
        "Cycles charged by json_rpc_request() calls.",
    )?;
    w.encode_counter(
        "json_rpc_request_cycles_refunded",
        get_metric!(json_rpc_request_cycles_refunded) as f64,
        "Cycles refunded by json_rpc_request() calls.",
    )?;
    METRICS.with(|m| {
        m.borrow()
            .json_rpc_host_requests
            .iter()
            .map(|(k, v)| {
                w.counter_vec(
                    "json_rpc_host_requests",
                    "Number of json_rpc_request() calls to a service host.",
                )
                .and_then(|m| m.value(&[("host", k)], *v as f64))
                .and(Ok(()))
            })
            .find(|e| e.is_err())
            .unwrap_or(Ok(()))
    })?;

    Ok(())
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

#[test]
fn check_candid_interface() {
    use candid::utils::{service_compatible, CandidSource};
    use std::path::Path;

    candid::export_service!();
    let new_interface = __export_service();

    service_compatible(
        CandidSource::Text(&new_interface),
        CandidSource::File(Path::new("iceth.did")),
    )
    .unwrap();
}

#[test]
fn check_json_rpc_cycles_cost() {
    let base_cost = json_rpc_cycles_cost(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",
        "https://cloudflare-eth.com",
        1000,
    );
    let s10 = "0123456789";
    let base_cost_s10 = json_rpc_cycles_cost(
        &("{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".to_string()
            + s10),
        "https://cloudflare-eth.com",
        1000,
    );
    assert_eq!(
        base_cost + 10 * (INGRESS_MESSAGE_BYTE_RECEIVED_COST + HTTP_OUTCALL_BYTE_RECEIEVED_COST),
        base_cost_s10
    )
}
