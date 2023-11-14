use cketh_common::eth_rpc::ValidationError;

use crate::*;

pub fn validate_hostname(hostname: &str) -> Result<(), ValidationError> {
    if !SERVICE_HOSTS_ALLOWLIST.contains(&hostname) {
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
        Err(ValidationError::CredentialPathNotAllowed(
            credential_path.to_string(),
        ))
    } else {
        Ok(())
    }
}

pub fn validate_credential_headers(
    credential_headers: &[(String, String)],
) -> Result<(), ValidationError> {
    if credential_headers
        .iter()
        .any(|(name, _value)| name == CONTENT_TYPE_HEADER)
    {
        Err(ValidationError::CredentialHeaderNotAllowed(
            CONTENT_TYPE_HEADER.to_string(),
        ))
    } else {
        Ok(())
    }
}
