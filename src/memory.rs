use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
#[cfg(target_arch = "wasm32")]
use ic_stable_structures::DefaultMemoryImpl;
#[cfg(not(target_arch = "wasm32"))]
use ic_stable_structures::VectorMemory;
use ic_stable_structures::{Cell, StableBTreeMap};
use std::cell::RefCell;

use crate::{
    constants::NODES_IN_FIDUCIARY_SUBNET,
    types::{
        ApiKey, AuthSet, Metadata, Metrics, PrincipalStorable, Provider, ProviderId,
        StorableRpcService,
    },
};

#[cfg(not(target_arch = "wasm32"))]
type Memory = VirtualMemory<VectorMemory>;
#[cfg(target_arch = "wasm32")]
type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    // Unstable static data: this is reset when the canister is upgraded.
    pub static UNSTABLE_METRICS: RefCell<Metrics> = RefCell::new(Metrics::default());
    static UNSTABLE_SUBNET_SIZE: RefCell<u32> = RefCell::new(NODES_IN_FIDUCIARY_SUBNET);

    // Stable static data: this is preserved when the canister is upgraded.
    #[cfg(not(target_arch = "wasm32"))]
    pub static MEMORY_MANAGER: RefCell<MemoryManager<VectorMemory>> =
        RefCell::new(MemoryManager::init(VectorMemory::new(RefCell::new(vec![]))));
    #[cfg(target_arch = "wasm32")]
    pub static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    pub static METADATA: RefCell<Cell<Metadata, Memory>> = RefCell::new(Cell::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        Metadata::default()).unwrap());
    pub static AUTH: RefCell<StableBTreeMap<PrincipalStorable, AuthSet, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))));
    pub static PROVIDERS: RefCell<StableBTreeMap<ProviderId, Provider, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))));
    pub static SERVICE_PROVIDER_MAP: RefCell<StableBTreeMap<StorableRpcService, ProviderId, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))));
    pub static API_KEY_MAP: RefCell<StableBTreeMap<ProviderId, ApiKey, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))));
}

pub fn get_nodes_in_subnet() -> u32 {
    UNSTABLE_SUBNET_SIZE.with_borrow(|n| *n)
}

pub fn set_nodes_in_subnet(nodes_in_subnet: u32) {
    UNSTABLE_SUBNET_SIZE.with_borrow_mut(|n| *n = nodes_in_subnet)
}

pub fn get_api_key(provider_id: ProviderId) -> ApiKey {
    API_KEY_MAP.with_borrow_mut(|map| {
        map.get(&provider_id)
            .map(|api_key| api_key.clone())
            .unwrap_or_else(|| ApiKey("".to_string()))
    })
}

pub fn insert_api_key(provider_id: ProviderId, api_key: ApiKey) {
    API_KEY_MAP.with_borrow_mut(|map| map.insert(provider_id, api_key));
}

pub fn remove_api_key(provider_id: ProviderId) {
    API_KEY_MAP.with_borrow_mut(|map| map.remove(&provider_id));
}
