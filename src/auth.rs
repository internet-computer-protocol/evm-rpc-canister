use candid::Principal;

use crate::{Auth, PrincipalStorable, AUTH, AUTH_STABLE, METADATA};

pub fn is_authorized(auth: Auth) -> bool {
    is_authorized_principal(&ic_cdk::caller(), auth)
}

pub fn is_authorized_principal(principal: &Principal, auth: Auth) -> bool {
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

pub fn require_admin_or_controller() -> Result<(), String> {
    let caller = ic_cdk::caller();
    if is_authorized_principal(&caller, Auth::Admin) || ic_cdk::api::is_controller(&caller) {
        Ok(())
    } else {
        Err("You are not authorized".to_string())
    }
}

pub fn require_register_provider() -> Result<(), String> {
    if is_authorized(Auth::RegisterProvider) {
        Ok(())
    } else {
        Err("You are not authorized".to_string())
    }
}

pub fn require_stable_authorized() -> Result<(), String> {
    AUTH_STABLE.with(|a| {
        if ic_cdk::api::is_controller(&ic_cdk::caller()) || a.borrow().contains(&ic_cdk::caller()) {
            Ok(())
        } else {
            Err("You are not stable authorized".to_string())
        }
    })
}

pub fn do_authorize(principal: Principal, auth: Auth) {
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

pub fn do_deauthorize(principal: Principal, auth: Auth) {
    AUTH.with(|a| {
        let mut auth_map = a.borrow_mut();
        let principal = PrincipalStorable(principal);
        if let Some(v) = auth_map.get(&principal) {
            auth_map.insert(principal, v & !(auth as u32));
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
    assert!(!is_authorized_principal(&principal1, Auth::Rpc));
    assert!(!is_authorized_principal(&principal2, Auth::Rpc));

    do_authorize(principal1, Auth::Rpc);
    assert!(is_authorized_principal(&principal1, Auth::Rpc));
    assert!(!is_authorized_principal(&principal2, Auth::Rpc));

    do_deauthorize(principal1, Auth::Rpc);
    assert!(!is_authorized_principal(&principal1, Auth::Rpc));
    assert!(!is_authorized_principal(&principal2, Auth::Rpc));

    do_authorize(principal1, Auth::RegisterProvider);
    assert!(!is_authorized_principal(&principal1, Auth::Admin));
    assert!(is_authorized_principal(&principal1, Auth::RegisterProvider));
}
