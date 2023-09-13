use candid::Principal;

use crate::{Auth, PrincipalStorable, AUTH, AUTH_STABLE, METADATA};

pub fn require_admin() -> Result<(), String> {
    if is_authorized(Auth::Admin) {
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

pub fn is_authorized(auth: Auth) -> bool {
    ic_cdk::api::is_controller(&ic_cdk::caller())
        || is_authorized_principal(&ic_cdk::caller(), auth)
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
