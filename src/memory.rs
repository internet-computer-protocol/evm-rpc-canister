use candid::Principal;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
#[cfg(target_arch = "wasm32")]
use ic_stable_structures::DefaultMemoryImpl;
use ic_stable_structures::StableBTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use ic_stable_structures::VectorMemory;
use std::cell::RefCell;

use crate::{
    constants::NODES_IN_FIDUCIARY_SUBNET,
    types::{ApiKey, Metrics, PrincipalStorable, ProviderId},
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
    static MEMORY_MANAGER: RefCell<MemoryManager<VectorMemory>> =
        RefCell::new(MemoryManager::init(VectorMemory::new(RefCell::new(vec![]))));
    #[cfg(target_arch = "wasm32")]
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static API_KEY_PRINCIPALS: RefCell<Vec<PrincipalStorable>> = RefCell::new(vec![]);
    static API_KEY_MAP: RefCell<StableBTreeMap<ProviderId, ApiKey, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5)))));
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

pub fn is_api_key_principal(principal: &Principal) -> bool {
    API_KEY_PRINCIPALS.with_borrow_mut(|principals| {
        principals
            .iter()
            .any(|PrincipalStorable(other)| other == principal)
    })
}

pub fn set_api_key_principals(new_principals: Vec<Principal>) {
    API_KEY_PRINCIPALS.with_borrow_mut(|principals| {
        *principals = new_principals.into_iter().map(PrincipalStorable).collect()
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

        set_api_key_principals(vec![principal1.clone()]);
        assert!(is_api_key_principal(&principal1));
        assert!(!is_api_key_principal(&principal2));

        set_api_key_principals(vec![principal2.clone()]);
        assert!(!is_api_key_principal(&principal1));
        assert!(is_api_key_principal(&principal2));

        set_api_key_principals(vec![principal1.clone(), principal2.clone()]);
        assert!(is_api_key_principal(&principal1));
        assert!(is_api_key_principal(&principal2));

        set_api_key_principals(vec![]);
        assert!(!is_api_key_principal(&principal1));
        assert!(!is_api_key_principal(&principal2));
    }
}
