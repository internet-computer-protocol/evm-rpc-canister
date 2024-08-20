use candid::Principal;

use crate::{
    memory::{AUTH, METADATA},
    types::{Auth, PrincipalStorable},
};

pub fn is_authorized(principal: &Principal, auth: Auth) -> bool {
    AUTH.with(|a| {
        if let Some(v) = a.borrow().get(&PrincipalStorable(*principal)) {
            v.is_authorized(auth)
        } else {
            false
        }
    })
}

pub fn require_manage_or_controller() -> Result<(), String> {
    let caller = ic_cdk::caller();
    if is_authorized(&caller, Auth::Manage) || ic_cdk::api::is_controller(&caller) {
        Ok(())
    } else {
        Err("You are not authorized".to_string())
    }
}

pub fn is_rpc_allowed(caller: &Principal) -> bool {
    METADATA.with(|m| m.borrow().get().open_rpc_access) || is_authorized(caller, Auth::PriorityRpc)
}

pub fn authorize(principal: Principal, auth: Auth) -> bool {
    if principal == Principal::anonymous() {
        false
    } else {
        AUTH.with_borrow_mut(|auth_map| {
            let principal = PrincipalStorable(principal);
            let mut auth_set = auth_map.get(&principal).unwrap_or_default();
            if auth_set.authorize(auth) {
                auth_map.insert(principal, auth_set);
                true
            } else {
                false
            }
        })
    }
}

pub fn deauthorize(principal: Principal, auth: Auth) -> bool {
    AUTH.with_borrow_mut(|auth_map| {
        let principal = PrincipalStorable(principal);
        if let Some(mut auth_set) = auth_map.get(&principal) {
            let changed = auth_set.deauthorize(auth);
            if auth_set.is_empty() {
                auth_map.remove(&principal);
            } else {
                auth_map.insert(principal, auth_set);
            }
            changed
        } else {
            false
        }
    })
}

#[cfg(test)]
mod test {
    use candid::Principal;

    use crate::{
        auth::{authorize, deauthorize, is_authorized},
        types::Auth,
    };

    #[test]
    fn test_authorization() {
        let principal1 =
            Principal::from_text("k5dlc-ijshq-lsyre-qvvpq-2bnxr-pb26c-ag3sc-t6zo5-rdavy-recje-zqe")
                .unwrap();
        let principal2 =
            Principal::from_text("yxhtl-jlpgx-wqnzc-ysego-h6yqe-3zwfo-o3grn-gvuhm-nz3kv-ainub-6ae")
                .unwrap();
        assert!(!is_authorized(&principal1, Auth::PriorityRpc));
        assert!(!is_authorized(&principal2, Auth::PriorityRpc));

        authorize(principal1, Auth::PriorityRpc);
        assert!(is_authorized(&principal1, Auth::PriorityRpc));
        assert!(!is_authorized(&principal2, Auth::PriorityRpc));

        deauthorize(principal1, Auth::PriorityRpc);
        assert!(!is_authorized(&principal1, Auth::PriorityRpc));
        assert!(!is_authorized(&principal2, Auth::PriorityRpc));

        authorize(principal1, Auth::FreeRpc);
        assert!(is_authorized(&principal1, Auth::FreeRpc));
        assert!(!is_authorized(&principal2, Auth::FreeRpc));

        deauthorize(principal1, Auth::FreeRpc);
        assert!(!is_authorized(&principal1, Auth::FreeRpc));

        authorize(principal2, Auth::Manage);
        assert!(!is_authorized(&principal1, Auth::Manage));
        assert!(is_authorized(&principal2, Auth::Manage));

        assert!(!is_authorized(&principal2, Auth::PriorityRpc));
        assert!(!is_authorized(&principal2, Auth::FreeRpc));
    }
}
