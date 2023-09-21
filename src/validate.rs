use crate::*;

pub fn validate_base_url(base_url: &str) {
    if SERVICE_HOSTS_ALLOWLIST.with(|a| !a.borrow().contains(&base_url)) {
        ic_cdk::trap("base_url host not allowed");
    }
}

pub fn validate_credential_path(credential_path: &str) {
    if !(credential_path.len() == 0
        || credential_path.starts_with('/')
        || credential_path.starts_with('?'))
    {
        ic_cdk::trap("credential path must start with '/' or '?' unless empty");
    }
}
