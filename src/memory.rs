use candid::Principal;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
#[cfg(target_arch = "wasm32")]
use ic_stable_structures::DefaultMemoryImpl;
use ic_stable_structures::StableBTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use ic_stable_structures::VectorMemory;
use std::cell::RefCell;

use crate::types::{ApiKey, Metrics, PrincipalStorable, ProviderId};

#[cfg(not(target_arch = "wasm32"))]
type Memory = VirtualMemory<VectorMemory>;
#[cfg(target_arch = "wasm32")]
type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    // Unstable static data: these are reset when the canister is upgraded.
    pub static UNSTABLE_METRICS: RefCell<Metrics> = RefCell::new(Metrics::default());

    // Stable static data: these are preserved when the canister is upgraded.
    #[cfg(not(target_arch = "wasm32"))]
    static MEMORY_MANAGER: RefCell<MemoryManager<VectorMemory>> =
        RefCell::new(MemoryManager::init(VectorMemory::new(RefCell::new(vec![]))));
    #[cfg(target_arch = "wasm32")]
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static API_KEY_MAP: RefCell<StableBTreeMap<ProviderId, ApiKey, Memory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(5)))));
    static MANAGE_API_KEYS: RefCell<ic_stable_structures::Vec<PrincipalStorable, Memory>> =
        RefCell::new(ic_stable_structures::Vec::init(MEMORY_MANAGER.with_borrow(|m|m.get(MemoryId::new(6)))).expect("Unable to read API key principals from stable memory"));
}

pub fn get_api_key(provider_id: ProviderId) -> ApiKey {
    API_KEY_MAP.with_borrow_mut(|map| map.get(&provider_id).unwrap_or_else(ApiKey::empty))
}

pub fn insert_api_key(provider_id: ProviderId, api_key: ApiKey) {
    API_KEY_MAP.with_borrow_mut(|map| map.insert(provider_id, api_key));
}

pub fn remove_api_key(provider_id: ProviderId) {
    API_KEY_MAP.with_borrow_mut(|map| map.remove(&provider_id));
}

pub fn is_api_key_principal(principal: &Principal) -> bool {
    MANAGE_API_KEYS.with_borrow_mut(|principals| {
        principals
            .iter()
            .any(|PrincipalStorable(other)| &other == principal)
    })
}

pub fn set_api_key_principals(new_principals: Vec<Principal>) {
    MANAGE_API_KEYS.with_borrow_mut(|principals| {
        while !principals.is_empty() {
            principals.pop();
        }
        for principal in new_principals {
            principals
                .push(&PrincipalStorable(principal))
                .expect("Error while adding API key principal");
        }
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
