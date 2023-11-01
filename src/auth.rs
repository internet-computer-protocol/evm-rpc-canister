use candid::Principal;

use crate::{Auth, AuthSet, PrincipalStorable, AUTH};

pub fn is_authorized(principal: &Principal, auth: Auth) -> bool {
    AUTH.with(|a| {
        if let Some(v) = a.borrow().get(&PrincipalStorable(*principal)) {
            v.is_authorized(auth)
        } else {
            false
        }
    })
}

pub fn require_admin_or_controller() -> Result<(), String> {
    let caller = ic_cdk::caller();
    if is_authorized(&caller, Auth::Admin) || ic_cdk::api::is_controller(&caller) {
        Ok(())
    } else {
        Err("You are not authorized".to_string())
    }
}

pub fn require_register_provider() -> Result<(), String> {
    if is_authorized(&ic_cdk::caller(), Auth::RegisterProvider) {
        Ok(())
    } else {
        Err("You are not authorized".to_string())
    }
}

pub fn do_authorize(principal: Principal, auth: Auth) {
    AUTH.with(|a| {
        let mut auth_map = a.borrow_mut();
        let principal = PrincipalStorable(principal);
        if let Some(mut v) = auth_map.get(&principal) {
            v.authorize(auth);
            auth_map.insert(principal, v);
        } else {
            auth_map.insert(principal, AuthSet::new(vec![auth]));
        }
    });
}

pub fn do_deauthorize(principal: Principal, auth: Auth) {
    AUTH.with(|a| {
        let mut auth_map = a.borrow_mut();
        let principal = PrincipalStorable(principal);
        if let Some(mut v) = auth_map.get(&principal) {
            v.deauthorize(auth);
            if v.is_empty() {
                auth_map.remove(&principal);
            } else {
                auth_map.insert(principal, v);
            }
        }
    });
}

#[test]
fn test_authorization() {
    let principal1 =
        Principal::from_text("k5dlc-ijshq-lsyre-qvvpq-2bnxr-pb26c-ag3sc-t6zo5-rdavy-recje-zqe")
            .unwrap();
    let principal2 =
        Principal::from_text("yxhtl-jlpgx-wqnzc-ysego-h6yqe-3zwfo-o3grn-gvuhm-nz3kv-ainub-6ae")
            .unwrap();
    assert!(!is_authorized(&principal1, Auth::Rpc));
    assert!(!is_authorized(&principal2, Auth::Rpc));

    do_authorize(principal1, Auth::Rpc);
    assert!(is_authorized(&principal1, Auth::Rpc));
    assert!(!is_authorized(&principal2, Auth::Rpc));

    do_deauthorize(principal1, Auth::Rpc);
    assert!(!is_authorized(&principal1, Auth::Rpc));
    assert!(!is_authorized(&principal2, Auth::Rpc));

    do_authorize(principal1, Auth::RegisterProvider);
    assert!(is_authorized(&principal1, Auth::RegisterProvider));
    assert!(!is_authorized(&principal2, Auth::RegisterProvider));

    do_deauthorize(principal1, Auth::RegisterProvider);
    assert!(!is_authorized(&principal1, Auth::RegisterProvider));

    do_authorize(principal2, Auth::Admin);
    assert!(!is_authorized(&principal1, Auth::Admin));
    assert!(is_authorized(&principal2, Auth::Admin));

    assert!(!is_authorized(&principal2, Auth::Rpc));
    assert!(!is_authorized(&principal2, Auth::FreeRpc));
    assert!(!is_authorized(&principal2, Auth::RegisterProvider));
}
