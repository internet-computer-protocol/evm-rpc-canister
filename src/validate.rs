use cketh_common::eth_rpc::ValidationError;
use ic_cdk::api::management_canister::http_request::HttpHeader;

use crate::{
    constants::{CONTENT_TYPE_HEADER, SERVICE_HOSTS_BLOCKLIST},
    util::hostname_from_url,
};

pub fn validate_hostname(hostname: &str) -> Result<(), ValidationError> {
    if SERVICE_HOSTS_BLOCKLIST.contains(&hostname) {
        Err(ValidationError::HostNotAllowed(hostname.to_string()))
    } else {
        Ok(())
    }
}

pub fn validate_url_pattern(url_pattern: &str) -> Result<(), ValidationError> {
    if !(url_pattern.is_empty()
        || url_pattern.starts_with('/')
        || url_pattern.starts_with('?')
        || hostname_from_url(url_pattern).is_none())
    {
        Err(ValidationError::CredentialPathNotAllowed) // TODO: rename to `UrlNotAllowed`
    } else {
        Ok(())
    }
}

pub fn validate_header_patterns(header_patterns: &[HttpHeader]) -> Result<(), ValidationError> {
    if header_patterns
        .iter()
        .any(|HttpHeader { name, .. }| name == CONTENT_TYPE_HEADER)
    {
        Err(ValidationError::CredentialHeaderNotAllowed) // TODO: rename to `HeaderNotAllowed`
    } else {
        Ok(())
    }
}

pub fn validate_api_key(api_key: &str) -> Result<(), ValidationError> {
    if api_key.contains("/") {
        Err(ValidationError::CredentialPathNotAllowed) // TODO: rename to `ApiKeyNotAllowed`
    } else {
        Ok(())
    }
}
