use crate::*;

pub fn validate_hostname(hostname: &str) {
    if !SERVICE_HOSTS_ALLOWLIST.contains(&hostname) {
        ic_cdk::trap("hostname not allowed");
    }
}

pub fn validate_credential_path(credential_path: &str) {
    if !(credential_path.is_empty()
        || credential_path.starts_with('/')
        || credential_path.starts_with('?'))
    {
        ic_cdk::trap("credential path must start with '/' or '?' unless empty");
    }
}

pub fn validate_credential_headers(credential_headers: &[(String, String)]) {
    if credential_headers
        .iter()
        .any(|(name, _value)| name == "Content-Type")
    {
        ic_cdk::trap("unexpected credential header: 'Content-Type'");
    }
}
