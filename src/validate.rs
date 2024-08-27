use crate::{
    constants::{SERVICE_HOSTS_BLOCKLIST, VALID_API_KEY_CHARS},
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

pub fn validate_api_key(api_key: &str) -> Result<(), &'static str> {
    if api_key.is_empty() {
        Err("API key must not be an empty string")
    } else if api_key.len() > 200 {
        Err("API key must be <= 200 characters")
    } else if api_key
        .chars()
        .any(|char| !VALID_API_KEY_CHARS.contains(char))
    {
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
    pub fn test_validate_api_key() {
        assert_eq!(validate_api_key("abc"), Ok(()));
        assert_eq!(
            validate_api_key("?a=b"),
            Err("Invalid character in API key")
        );
        assert_eq!(validate_api_key("/"), Err("Invalid character in API key"));
        assert_eq!(
            validate_api_key("abc/def"),
            Err("Invalid character in API key")
        );
        assert_eq!(
            validate_api_key("../def"),
            Err("Invalid character in API key")
        );
        assert_eq!(
            validate_api_key("abc/:key"),
            Err("Invalid character in API key")
        );
    }
}
