use ic_cdk::api::management_canister::http_request::HttpHeader;

use crate::{
    constants::{CONTENT_TYPE_HEADER, SERVICE_HOSTS_BLOCKLIST},
    util::hostname_from_url,
};

pub fn validate_hostname(hostname: &str) -> Result<(), &'static str> {
    if SERVICE_HOSTS_BLOCKLIST.contains(&hostname) {
        Err("Hostname not allowed")
    } else {
        Ok(())
    }
}

pub fn validate_url_pattern(url_pattern: &str) -> Result<(), &'static str> {
    validate_hostname(&hostname_from_url(url_pattern).ok_or("Invalid hostname in URL")?)
}

pub fn validate_header_patterns(header_patterns: &[HttpHeader]) -> Result<(), &'static str> {
    if header_patterns
        .iter()
        .any(|HttpHeader { name, .. }| name == CONTENT_TYPE_HEADER)
    {
        Err("Invalid header name")
    } else {
        Ok(())
    }
}

pub fn validate_api_key(api_key: &str) -> Result<(), &'static str> {
    if api_key.contains(['.', '/', '?', '&']) {
        Err("Invalid character in API key")
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
            Err("Invalid hostname in URL")
        );
        assert_eq!(
            validate_url_pattern("https://{API_KEY}/v1/rpc"),
            Err("Invalid hostname in URL")
        );
        assert_eq!(
            validate_url_pattern("https://{API_KEY}/{API_KEY}"),
            Err("Invalid hostname in URL")
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
            Err("Invalid header name")
        );
    }

    #[test]
    pub fn test_validate_api_key() {
        assert_eq!(validate_api_key("abc"), Ok(()));
        assert_eq!(validate_api_key(".."), Err("Invalid character in API key"));
        assert_eq!(
            validate_api_key("abc/def"),
            Err("Invalid character in API key")
        );
        assert_eq!(
            validate_api_key("../def"),
            Err("Invalid character in API key")
        );
        assert_eq!(
            validate_api_key("abc/.."),
            Err("Invalid character in API key")
        );
        assert_eq!(
            validate_api_key("../.."),
            Err("Invalid character in API key")
        );
    }
}
