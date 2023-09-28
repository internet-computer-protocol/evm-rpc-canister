pub mod declarations;

use declarations::ic_eth::EthRpcError;

impl std::fmt::Display for EthRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use EthRpcError::*;
        match self {
            HttpRequestError { code, message } => write!(f, "HTTP {}: {}", code, message),
            TooFewCycles { expected, received } => {
                write!(f, "not enough cycles: {} < {}", received, expected)
            }
            ServiceUrlParseError => write!(f, "URL parse error"),
            ProviderNotFound => write!(f, "provider not found"),
            ServiceHostNotAllowed(host) => write!(f, "service host not allowed: {}", host),
            NoPermission => write!(f, "no permission"),
        }
    }
}
