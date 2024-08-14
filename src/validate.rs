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
    validate_hostname(
        &hostname_from_url(&url_pattern).ok_or(ValidationError::CredentialPathNotAllowed)?,
    )
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_validate_url_pattern() {
        assert_eq!(validate_url_pattern("https://example.com"), Ok(()));
        assert_eq!(validate_url_pattern("https://example.com/v1/rpc"), Ok(()));
        assert_eq!(
            validate_url_pattern("https://example.com/{API_KEY}"),
            Ok(())
        );
        assert_eq!(
            validate_url_pattern("https://{API_KEY}"),
            Err(ValidationError::CredentialPathNotAllowed)
        );
        assert_eq!(
            validate_url_pattern("https://{API_KEY}/v1/rpc"),
            Err(ValidationError::CredentialPathNotAllowed)
        );
        assert_eq!(
            validate_url_pattern("https://{API_KEY}/{API_KEY}"),
            Err(ValidationError::CredentialPathNotAllowed)
        );
    }

    #[test]
    pub fn test_validate_header_patterns() {
        assert_eq!(
            validate_header_patterns(&[HttpHeader {
                name: "abc".to_string(),
                value: "123".to_string(),
            }]),
            Ok(())
        );
        assert_eq!(
            validate_header_patterns(&[HttpHeader {
                name: CONTENT_TYPE_HEADER.to_string(),
                value: "text/xml".to_string(),
            }]),
            Err(ValidationError::CredentialHeaderNotAllowed)
        );
    }

    #[test]
    pub fn test_validate_api_key() {
        assert_eq!(validate_api_key("abc"), Ok(()));
        assert_eq!(
            validate_api_key("abc"),
            Err(ValidationError::CredentialPathNotAllowed)
        );
    }
}
