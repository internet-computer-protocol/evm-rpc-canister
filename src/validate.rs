use cketh_common::eth_rpc::ValidationError;
use ic_cdk::api::management_canister::http_request::HttpHeader;

use crate::*;

pub fn validate_hostname(hostname: &str) -> Result<(), ValidationError> {
    if SERVICE_HOSTS_BLOCKLIST.contains(&hostname) {
        Err(ValidationError::HostNotAllowed(hostname.to_string()))
    } else {
        Ok(())
    }
}

pub fn validate_credential_path(credential_path: &str) -> Result<(), ValidationError> {
    if !(credential_path.is_empty()
        || credential_path.starts_with('/')
        || credential_path.starts_with('?'))
    {
        Err(ValidationError::CredentialPathNotAllowed)
    } else {
        Ok(())
    }
}

pub fn validate_credential_headers(
    credential_headers: &[HttpHeader],
) -> Result<(), ValidationError> {
    if credential_headers
        .iter()
        .any(|HttpHeader { name, .. }| name == CONTENT_TYPE_HEADER)
    {
        Err(ValidationError::CredentialHeaderNotAllowed)
    } else {
        Ok(())
    }
}
