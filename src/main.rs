use candid::{candid_method, CandidType, Decode, Deserialize, Encode, Principal};
use ic_canister_log::{declare_log_buffer, log};
use ic_canisters_http_types::{
    HttpRequest as AssetHttpRequest, HttpResponse as AssetHttpResponse, HttpResponseBuilder,
};
use ic_cdk::api::management_canister::http_request::{
    http_request as make_http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod,
    HttpResponse, TransformArgs, TransformContext,
};
use ic_cdk::{query, update};
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

const INGRESS_OVERHEAD_BYTES: u128 = 100;
const INGRESS_MESSAGE_RECEIVED_COST: u128 = 1_200_000;
const INGRESS_MESSAGE_BYTE_RECEIVED_COST: u128 = 2_000;
const HTTP_OUTCALL_REQUEST_COST: u128 = 400_000_000;
const HTTP_OUTCALL_BYTE_RECEIEVED_COST: u128 = 100_000;
const BASE_SUBNET_SIZE: u128 = 13; // App subnet

const MINIMUM_WITHDRAWAL_CYCLES: u128 = 1_000_000_000;

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
    "rpc.ankr.com",
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
const DEFAULT_NODES_IN_SUBNET: u32 = 13;
const DEFAULT_OPEN_RPC_ACCESS: bool = true;
const RPC_ALLOWLIST: &[&str] = &[];
// Principals allowed to registry API keys.
const REGISTER_PROVIDER_ALLOWLIST: &[&str] = &[];
// Principals that will not be charged cycles to send JSON RPCs.
const FREE_RPC_ALLOWLIST: &[&str] = &[];
// Principals who have Admin authorization.
const AUTHORIZED_ADMIN: &[&str] = &[];

type AllowlistSet = HashSet<&'static &'static str>;

#[cfg(not(target_arch = "wasm32"))]
type Memory = VirtualMemory<FileMemory>;
#[cfg(target_arch = "wasm32")]
type Memory = VirtualMemory<DefaultMemoryImpl>;

declare_log_buffer!(name = INFO, capacity = 1000);
declare_log_buffer!(name = ERROR, capacity = 1000);

#[derive(Default)]
struct Metrics {
    requests: u64,
    request_cycles_charged: u128,
    request_cycles_refunded: u128,
    request_err_no_permission: u64,
    request_err_service_url_host_not_allowed: u64,
    request_err_http: u64,
    json_rpc_host_requests: HashMap<String, u64>,
}

// These need to be powers of two so that they can be used as bit fields.
#[derive(Clone, Debug, PartialEq, CandidType, FromPrimitive, Deserialize)]
enum Auth {
    Admin = 0b0001,
    Rpc = 0b0010,
    RegisterProvider = 0b0100,
    FreeRpc = 0b1000,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct Metadata {
    nodes_in_subnet: u32,
    next_provider_id: u64,
    open_rpc_access: bool,
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
        RefCell::new(MemoryManager::init(FileMemory::new(std::fs::OpenOptions::new().read(true).write(true).create(true).open("target/test_stable_memory.bin").unwrap())));
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

#[update]
#[candid_method]
async fn request(
    service_url: String,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<Vec<u8>, EthRpcError> {
    request_internal(json_rpc_payload, service_url, max_response_bytes, None).await
}

#[update]
#[candid_method]
async fn provider_request(
    provider_id: u64,
    json_rpc_payload: String,
    max_response_bytes: u64,
) -> Result<Vec<u8>, EthRpcError> {
    let provider = PROVIDERS.with(|p| {
        p.borrow()
            .get(&provider_id)
            .ok_or(EthRpcError::ProviderNotFound)
    })?;
    let service_url = provider.service_url.clone() + &provider.api_key;
    request_internal(
        json_rpc_payload,
        service_url,
        max_response_bytes,
        Some(provider),
    )
    .await
}

#[query]
#[candid_method]
fn cycles_cost(service_url: String, json_rpc_payload: String, max_response_bytes: u64) -> u128 {
    json_rpc_cycles_cost_(&json_rpc_payload, &service_url, max_response_bytes)
}

#[query]
#[candid_method]
fn provider_cycles_cost(provider_id: u64, json_rpc_payload: String) -> Option<u128> {
    let provider = PROVIDERS.with(|p| p.borrow().get(&provider_id))?;
    Some(json_rpc_provider_cycles_cost_(
        &json_rpc_payload,
        provider.cycles_per_call,
        provider.cycles_per_message_byte,
    ))
}

async fn request_internal(
    json_rpc_payload: String,
    service_url: String,
    max_response_bytes: u64,
    provider: Option<Provider>,
) -> Result<Vec<u8>, EthRpcError> {
    inc_metric!(requests);
    if !is_authorized(Auth::Rpc) {
        inc_metric!(request_err_no_permission);
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
        inc_metric!(request_err_service_url_host_not_allowed);
        return Err(EthRpcError::ServiceUrlHostNotAllowed);
    }
    let provider_cost = match &provider {
        None => 0,
        Some(provider) => json_rpc_provider_cycles_cost_(
            &json_rpc_payload,
            provider.cycles_per_call,
            provider.cycles_per_message_byte,
        ),
    };
    let cost =
        json_rpc_cycles_cost_(&json_rpc_payload, &service_url, max_response_bytes) + provider_cost;
    if !is_authorized(Auth::FreeRpc) {
        if cycles_available < cost {
            return Err(EthRpcError::TooFewCycles(format!(
                "requires {cost} cycles, got {cycles_available} cycles",
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
        add_metric!(request_cycles_charged, cost);
        add_metric!(request_cycles_refunded, cycles_available - cost);
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
        transform: Some(TransformContext::from_name(
            "__transform_json_rpc".to_string(),
            vec![],
        )),
    };
    match make_http_request(request, cost).await {
        Ok((result,)) => Ok(result.body),
        Err((r, m)) => {
            inc_metric!(request_err_http);
            Err(EthRpcError::HttpRequestError {
                code: r as u32,
                message: m,
            })
        }
    }
}

fn json_rpc_cycles_cost_(
    json_rpc_payload: &str,
    service_url: &str,
    max_response_bytes: u64,
) -> u128 {
    let nodes_in_subnet = METADATA.with(|m| m.borrow().get().nodes_in_subnet);
    let ingress_bytes =
        (json_rpc_payload.len() + service_url.len()) as u128 + INGRESS_OVERHEAD_BYTES;
    let base_cost = INGRESS_MESSAGE_RECEIVED_COST
        + INGRESS_MESSAGE_BYTE_RECEIVED_COST * ingress_bytes
        + HTTP_OUTCALL_REQUEST_COST
        + HTTP_OUTCALL_BYTE_RECEIEVED_COST * (ingress_bytes + max_response_bytes as u128);
    base_cost * (nodes_in_subnet as u128) / BASE_SUBNET_SIZE
}

fn json_rpc_provider_cycles_cost_(
    json_rpc_payload: &str,
    provider_cycles_per_call: u64,
    provider_cycles_per_message_byte: u64,
) -> u128 {
    let nodes_in_subnet = METADATA.with(|m| m.borrow().get().nodes_in_subnet);
    let base_cost = provider_cycles_per_call as u128
        + provider_cycles_per_message_byte as u128 * json_rpc_payload.len() as u128;
    base_cost * (nodes_in_subnet as u128)
}

#[query]
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

#[ic_cdk::update(guard = "require_register_provider")]
#[candid_method]
fn register_provider(provider: RegisterProvider) -> u64 {
    let parsed_url = url::Url::parse(&provider.service_url).expect("unable to parse service_url");
    let host = parsed_url.host_str().expect("service_url host missing");
    if SERVICE_HOSTS_ALLOWLIST.with(|a| !a.borrow().contains(&host)) {
        ic_cdk::trap("service_url host not allowed");
    }
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
    provider_id
}

#[ic_cdk::update(guard = "require_register_provider")]
#[candid_method]
fn update_provider_api_key(provider_id: u64, api_key: String) {
    PROVIDERS.with(|p| match p.borrow_mut().get(&provider_id) {
        Some(mut provider) => {
            if provider.owner != ic_cdk::caller() && !is_authorized(Auth::Admin) {
                ic_cdk::trap("Provider owner != caller");
            }
            provider.api_key = api_key;
            p.borrow_mut().insert(provider_id, provider);
        }
        None => ic_cdk::trap("Provider not found"),
    });
}

#[ic_cdk::update(guard = "require_register_provider")]
#[candid_method]
fn unregister_provider(provider_id: u64) {
    PROVIDERS.with(|p| {
        if let Some(provider) = p.borrow().get(&provider_id) {
            if provider.owner == ic_cdk::caller() || is_authorized(Auth::Admin) {
                p.borrow_mut().remove(&provider_id);
            } else {
                ic_cdk::trap("Not authorized");
            }
        }
    });
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

#[ic_cdk::update(guard = "require_register_provider")]
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

#[ic_cdk_macros::init]
fn init() {
    initialize();
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = DEFAULT_NODES_IN_SUBNET;
        metadata.open_rpc_access = DEFAULT_OPEN_RPC_ACCESS;
        m.borrow_mut().set(metadata).unwrap();
    });
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
        Err(e) => ic_cdk::trap(&format!("failed to convert Principal {principal} {e:?}",)),
    }
}

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

fn is_stable_authorized() -> Result<(), String> {
    AUTH_STABLE.with(|a| {
        if ic_cdk::api::is_controller(&ic_cdk::caller()) || a.borrow().contains(&ic_cdk::caller()) {
            Ok(())
        } else {
            Err("You are not stable authorized".to_string())
        }
    })
}

#[update(guard = "is_stable_authorized")]
fn stable_authorize(principal: Principal) {
    AUTH_STABLE.with(|a| a.borrow_mut().insert(principal));
}

#[query(guard = "is_stable_authorized")]
fn stable_size() -> u64 {
    ic_cdk::api::stable::stable64_size() * WASM_PAGE_SIZE
}

#[query(guard = "is_stable_authorized")]
fn stable_read(offset: u64, length: u64) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.resize(length as usize, 0);
    ic_cdk::api::stable::stable64_read(offset, buffer.as_mut_slice());
    buffer
}

#[update(guard = "is_stable_authorized")]
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

#[update(guard = "require_admin")]
#[candid_method]
fn authorize(principal: Principal, auth: Auth) {
    AUTH.with(|a| {
        let mut auth_map = a.borrow_mut();
        let principal = PrincipalStorable(principal);
        if let Some(v) = auth_map.get(&principal) {
            auth_map.insert(principal, v | (auth as u32));
        } else {
            auth_map.insert(principal, auth as u32);
        }
    });
}

#[query(guard = "require_admin")]
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

#[update(guard = "require_admin")]
#[candid_method]
fn deauthorize(principal: Principal, auth: Auth) {
    AUTH.with(|a| {
        let mut auth_map = a.borrow_mut();
        let principal = PrincipalStorable(principal);
        if let Some(v) = auth_map.get(&principal) {
            auth_map.insert(principal, v & !(auth as u32));
        }
    });
}

fn require_admin() -> Result<(), String> {
    if is_authorized(Auth::Admin) {
        Ok(())
    } else {
        Err("You are not authorized".to_string())
    }
}

fn require_register_provider() -> Result<(), String> {
    if is_authorized(Auth::RegisterProvider) {
        Ok(())
    } else {
        Err("You are not authorized".to_string())
    }
}

fn is_authorized(auth: Auth) -> bool {
    ic_cdk::api::is_controller(&ic_cdk::caller())
        || is_authorized_principal(&ic_cdk::caller(), auth)
}

fn is_authorized_principal(principal: &Principal, auth: Auth) -> bool {
    if auth == Auth::Rpc && METADATA.with(|m| m.borrow().get().open_rpc_access) {
        return true;
    }
    AUTH.with(|a| {
        if let Some(v) = a.borrow().get(&PrincipalStorable(*principal)) {
            (v & (auth as u32)) != 0
        } else {
            false
        }
    })
}

#[update(guard = "require_admin")]
#[candid_method]
fn set_open_rpc_access(open_rpc_access: bool) {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.open_rpc_access = open_rpc_access;
        m.borrow_mut().set(metadata).unwrap();
    });
}

#[query(guard = "require_admin")]
#[candid_method(query)]
fn get_open_rpc_access() -> bool {
    METADATA.with(|m| m.borrow().get().open_rpc_access)
}

#[update(guard = "require_admin")]
#[candid_method]
fn set_nodes_in_subnet(nodes_in_subnet: u32) {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = nodes_in_subnet;
        m.borrow_mut().set(metadata).unwrap();
    });
}

#[query(guard = "require_admin")]
#[candid_method(query)]
fn get_nodes_in_subnet() -> u32 {
    METADATA.with(|m| m.borrow().get().nodes_in_subnet)
}

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
        "requests",
        get_metric!(requests) as f64,
        "Number of request() calls.",
    )?;
    w.encode_counter(
        "request_cycles_charged",
        get_metric!(request_cycles_charged) as f64,
        "Cycles charged by request() calls.",
    )?;
    w.encode_counter(
        "request_cycles_refunded",
        get_metric!(request_cycles_refunded) as f64,
        "Cycles refunded by request() calls.",
    )?;
    METRICS.with(|m| {
        m.borrow()
            .json_rpc_host_requests
            .iter()
            .map(|(k, v)| {
                w.counter_vec(
                    "json_rpc_host_requests",
                    "Number of request() calls to a service host.",
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
        CandidSource::File(Path::new("candid/ic_eth.did")),
    )
    .unwrap();
}

#[test]
fn check_json_rpc_cycles_cost() {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = 13;
        m.borrow_mut().set(metadata).unwrap();
    });

    let base_cost = json_rpc_cycles_cost_(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",
        "https://cloudflare-eth.com",
        1000,
    );
    let s10 = "0123456789";
    let base_cost_s10 = json_rpc_cycles_cost_(
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

#[test]
fn check_json_rpc_provider_cycles_cost() {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = 13;
        m.borrow_mut().set(metadata).unwrap();
    });

    let base_cost = json_rpc_provider_cycles_cost_(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",
        0,
        2,
    );
    let s10 = "0123456789";
    let base_cost_s10 = json_rpc_provider_cycles_cost_(
        &("{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".to_string()
            + s10),
        1000,
        2,
    );
    assert_eq!(base_cost + (10 * 2 + 1000) * 13, base_cost_s10)
}

#[test]
fn check_authorization() {
    let principal1 =
        Principal::from_text("k5dlc-ijshq-lsyre-qvvpq-2bnxr-pb26c-ag3sc-t6zo5-rdavy-recje-zqe")
            .unwrap();
    let principal2 =
        Principal::from_text("yxhtl-jlpgx-wqnzc-ysego-h6yqe-3zwfo-o3grn-gvuhm-nz3kv-ainub-6ae")
            .unwrap();
    assert!(!is_authorized_principal(&principal1, Auth::Rpc));
    assert!(!is_authorized_principal(&principal2, Auth::Rpc));
    authorize(principal1, Auth::Rpc);
    assert!(is_authorized_principal(&principal1, Auth::Rpc));
    assert!(!is_authorized_principal(&principal2, Auth::Rpc));
    deauthorize(principal1, Auth::Rpc);
    assert!(!is_authorized_principal(&principal1, Auth::Rpc));
    assert!(!is_authorized_principal(&principal2, Auth::Rpc));
}
