use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
#[cfg(target_arch = "wasm32")]
use ic_stable_structures::DefaultMemoryImpl;
#[cfg(not(target_arch = "wasm32"))]
use ic_stable_structures::VectorMemory;
use ic_stable_structures::{Cell, StableBTreeMap};
use std::cell::RefCell;

use crate::{types::*, NODES_IN_FIDUCIARY_SUBNET};

#[cfg(not(target_arch = "wasm32"))]
type Memory = VirtualMemory<VectorMemory>;
#[cfg(target_arch = "wasm32")]
type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    // Unstable static data: this is reset when the canister is upgraded.
    pub static UNSTABLE_METRICS: RefCell<Metrics> = RefCell::new(Metrics::default());
    pub static UNSTABLE_SUBNET_SIZE: RefCell<u32> = RefCell::new(NODES_IN_FIDUCIARY_SUBNET);

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
    pub static PROVIDERS: RefCell<StableBTreeMap<u64, Provider, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))));
    pub static SERVICE_PROVIDER_MAP: RefCell<StableBTreeMap<StorableRpcService, u64, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))));
}
