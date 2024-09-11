use candid::Principal;
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager},
    DefaultMemoryImpl,
};
use ic_stable_structures::{Cell, StableBTreeMap};
use std::cell::RefCell;

use crate::types::{ApiKey, Metrics, ProviderId};

const IS_DEMO_ACTIVE_ID: MemoryId = MemoryId::new(4);
const API_KEY_MAP_MEMORY_ID: MemoryId = MemoryId::new(5);
const MANAGE_API_KEYS_MEMORY_ID: MemoryId = MemoryId::new(6);

type StableMemory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    // Unstable static data: these are reset when the canister is upgraded.
    pub static UNSTABLE_METRICS: RefCell<Metrics> = RefCell::new(Metrics::default());

    // Stable static data: these are preserved when the canister is upgraded.
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static IS_DEMO_ACTIVE: RefCell<Cell<bool, StableMemory>> =
        RefCell::new(Cell::init(MEMORY_MANAGER.with_borrow(|m| m.get(IS_DEMO_ACTIVE_ID)), false).expect("Unable to read demo status from stable memory"));
    static API_KEY_MAP: RefCell<StableBTreeMap<ProviderId, ApiKey, StableMemory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(API_KEY_MAP_MEMORY_ID))));
    static MANAGE_API_KEYS: RefCell<ic_stable_structures::Vec<ic_principal::Principal, StableMemory>> =
        RefCell::new(ic_stable_structures::Vec::init(MEMORY_MANAGER.with_borrow(|m| m.get(MANAGE_API_KEYS_MEMORY_ID))).expect("Unable to read API key principals from stable memory"));
}

pub fn get_api_key(provider_id: ProviderId) -> Option<ApiKey> {
    API_KEY_MAP.with_borrow_mut(|map| map.get(&provider_id))
}

pub fn insert_api_key(provider_id: ProviderId, api_key: ApiKey) {
    API_KEY_MAP.with_borrow_mut(|map| map.insert(provider_id, api_key));
}

pub fn remove_api_key(provider_id: ProviderId) {
    API_KEY_MAP.with_borrow_mut(|map| map.remove(&provider_id));
}

pub fn is_api_key_principal(principal: &Principal) -> bool {
    let principal = ic_principal::Principal::from_slice(principal.as_slice());
    MANAGE_API_KEYS.with_borrow(|principals| principals.iter().any(|other| other == principal))
}

pub fn set_api_key_principals(new_principals: Vec<Principal>) {
    MANAGE_API_KEYS.with_borrow_mut(|principals| {
        while !principals.is_empty() {
            principals.pop();
        }
        for principal in new_principals {
            principals
                .push(&ic_principal::Principal::from_slice(principal.as_slice()))
                .expect("Error while adding API key principal");
        }
    });
}

pub fn is_demo_active() -> bool {
    IS_DEMO_ACTIVE.with_borrow(|demo| *demo.get())
}

pub fn set_demo_active(is_active: bool) {
    IS_DEMO_ACTIVE.with_borrow_mut(|demo| {
        demo.set(is_active)
            .expect("Error while storing new demo status")
    });
}

#[cfg(test)]
mod test {
    use candid::Principal;

    use crate::memory::{is_api_key_principal, set_api_key_principals};

    #[test]
    fn test_api_key_principals() {
        let principal1 =
            Principal::from_text("k5dlc-ijshq-lsyre-qvvpq-2bnxr-pb26c-ag3sc-t6zo5-rdavy-recje-zqe")
                .unwrap();
        let principal2 =
            Principal::from_text("yxhtl-jlpgx-wqnzc-ysego-h6yqe-3zwfo-o3grn-gvuhm-nz3kv-ainub-6ae")
                .unwrap();
        assert!(!is_api_key_principal(&principal1));
        assert!(!is_api_key_principal(&principal2));

        set_api_key_principals(vec![principal1]);
        assert!(is_api_key_principal(&principal1));
        assert!(!is_api_key_principal(&principal2));

        set_api_key_principals(vec![principal2]);
        assert!(!is_api_key_principal(&principal1));
        assert!(is_api_key_principal(&principal2));

        set_api_key_principals(vec![principal1, principal2]);
        assert!(is_api_key_principal(&principal1));
        assert!(is_api_key_principal(&principal2));

        set_api_key_principals(vec![]);
        assert!(!is_api_key_principal(&principal1));
        assert!(!is_api_key_principal(&principal2));
    }
}
