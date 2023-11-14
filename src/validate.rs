use cketh_common::eth_rpc::ValidateError;

use crate::*;

pub fn validate_hostname(hostname: &str) -> Result<(), ValidateError> {
    if !SERVICE_HOSTS_ALLOWLIST.contains(&hostname) {
        Err(ValidateError::HostNotAllowed(hostname.to_string()))
    } else {
        Ok(())
    }
}

pub fn validate_credential_path(credential_path: &str) -> Result<(), ValidateError> {
    if !(credential_path.is_empty()
        || credential_path.starts_with('/')
        || credential_path.starts_with('?'))
    {
        Err(ValidateError::CredentialPathNotAllowed(
            credential_path.to_string(),
        ))
    } else {
        Ok(())
    }
}

pub fn validate_credential_headers(
    credential_headers: &[(String, String)],
) -> Result<(), ValidateError> {
    if credential_headers
        .iter()
        .any(|(name, _value)| name == CONTENT_TYPE_HEADER)
    {
        Err(ValidateError::CredentialHeaderNotAllowed(
            CONTENT_TYPE_HEADER.to_string(),
        ))
    } else {
        Ok(())
    }
}
