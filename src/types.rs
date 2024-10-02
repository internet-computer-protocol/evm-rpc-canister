use crate::constants::{API_KEY_MAX_SIZE, API_KEY_REPLACE_STRING};
use crate::memory::get_api_key;
use crate::util::hostname_from_url;
use crate::validate::validate_api_key;
use candid::{CandidType, Principal};
use ic_cdk::api::management_canister::http_request::HttpHeader;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct InstallArgs {
    pub demo: Option<bool>,
    #[serde(rename = "manageApiKeys")]
    pub manage_api_keys: Option<Vec<Principal>>,
    #[serde(rename = "logFilter")]
    pub log_filter: Option<LogFilter>,
}

pub enum ResolvedRpcService {
    Api(evm_rpc_types::RpcApi),
    Provider(Provider),
}

impl ResolvedRpcService {
    pub fn api(&self) -> evm_rpc_types::RpcApi {
        match self {
            Self::Api(api) => api.clone(),
            Self::Provider(provider) => provider.api(),
        }
    }
}

pub trait MetricValue {
    fn metric_value(&self) -> f64;
}

impl MetricValue for u32 {
    fn metric_value(&self) -> f64 {
        *self as f64
    }
}

impl MetricValue for u64 {
    fn metric_value(&self) -> f64 {
        *self as f64
    }
}

impl MetricValue for u128 {
    fn metric_value(&self) -> f64 {
        *self as f64
    }
}

pub trait MetricLabels {
    fn metric_labels(&self) -> Vec<(&str, &str)>;
}

impl<A: MetricLabels, B: MetricLabels> MetricLabels for (A, B) {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        [self.0.metric_labels(), self.1.metric_labels()].concat()
    }
}

impl<A: MetricLabels, B: MetricLabels, C: MetricLabels> MetricLabels for (A, B, C) {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        [
            self.0.metric_labels(),
            self.1.metric_labels(),
            self.2.metric_labels(),
        ]
        .concat()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub struct MetricRpcMethod(pub String);

impl From<RpcMethod> for MetricRpcMethod {
    fn from(method: RpcMethod) -> Self {
        MetricRpcMethod(method.name().to_string())
    }
}

impl MetricLabels for MetricRpcMethod {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        vec![("method", &self.0)]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub struct MetricRpcHost(pub String);

impl<'a> From<&'a str> for MetricRpcHost {
    fn from(hostname: &str) -> Self {
        MetricRpcHost(hostname.to_string())
    }
}

impl MetricLabels for MetricRpcHost {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        vec![("host", &self.0)]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub struct MetricHttpStatusCode(pub String);

impl From<u32> for MetricHttpStatusCode {
    fn from(value: u32) -> Self {
        MetricHttpStatusCode(value.to_string())
    }
}

impl MetricLabels for MetricHttpStatusCode {
    fn metric_labels(&self) -> Vec<(&str, &str)> {
        vec![("status", &self.0)]
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, CandidType, Deserialize)]
pub struct Metrics {
    pub requests: HashMap<(MetricRpcMethod, MetricRpcHost), u64>,
    pub responses: HashMap<(MetricRpcMethod, MetricRpcHost, MetricHttpStatusCode), u64>,
    #[serde(rename = "inconsistentResponses")]
    pub inconsistent_responses: HashMap<(MetricRpcMethod, MetricRpcHost), u64>,
    #[serde(rename = "cyclesCharged")]
    pub cycles_charged: HashMap<(MetricRpcMethod, MetricRpcHost), u128>,
    #[serde(rename = "cyclesWithdrawn")]
    pub cycles_withdrawn: u128,
    #[serde(rename = "errNoPermission")]
    pub err_no_permission: u64,
    #[serde(rename = "errHttpOutcall")]
    pub err_http_outcall: HashMap<(MetricRpcMethod, MetricRpcHost), u64>,
    #[serde(rename = "errHostNotAllowed")]
    pub err_host_not_allowed: HashMap<MetricRpcHost, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcMethod {
    EthFeeHistory,
    EthGetLogs,
    EthGetBlockByNumber,
    EthGetTransactionCount,
    EthGetTransactionReceipt,
    EthSendRawTransaction,
}

impl RpcMethod {
    fn name(self) -> &'static str {
        match self {
            RpcMethod::EthFeeHistory => "eth_feeHistory",
            RpcMethod::EthGetLogs => "eth_getLogs",
            RpcMethod::EthGetBlockByNumber => "eth_getBlockByNumber",
            RpcMethod::EthGetTransactionCount => "eth_getTransactionCount",
            RpcMethod::EthGetTransactionReceipt => "eth_getTransactionReceipt",
            RpcMethod::EthSendRawTransaction => "eth_sendRawTransaction",
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ApiKey(String);

impl ApiKey {
    /// Explicitly read API key (use sparingly)
    pub fn read(&self) -> &str {
        &self.0
    }
}

// Enable printing data structures which include an API key
impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{API_KEY_REPLACE_STRING}")
    }
}

impl TryFrom<String> for ApiKey {
    type Error = String;
    fn try_from(key: String) -> Result<ApiKey, Self::Error> {
        validate_api_key(&key)?;
        Ok(ApiKey(key))
    }
}

impl Storable for ApiKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(String::from_bytes(bytes))
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: API_KEY_MAX_SIZE,
        is_fixed_size: false,
    };
}

pub type ProviderId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstHeader {
    pub name: &'static str,
    pub value: &'static str,
}

impl<'a> From<&'a ConstHeader> for HttpHeader {
    fn from(header: &'a ConstHeader) -> Self {
        HttpHeader {
            name: header.name.to_string(),
            value: header.value.to_string(),
        }
    }
}

/// Internal RPC provider representation.
#[derive(Debug, Clone, PartialEq, Eq, CandidType, Serialize)]
pub struct Provider {
    #[serde(rename = "providerId")]
    pub provider_id: ProviderId,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    pub access: RpcAccess,
    pub alias: Option<evm_rpc_types::RpcService>,
}

impl Provider {
    pub fn api(&self) -> evm_rpc_types::RpcApi {
        match &self.access {
            RpcAccess::Authenticated { auth, public_url } => match get_api_key(self.provider_id) {
                Some(api_key) => match auth {
                    RpcAuth::BearerToken { url } => evm_rpc_types::RpcApi {
                        url: url.to_string(),
                        headers: Some(vec![evm_rpc_types::HttpHeader {
                            name: "Authorization".to_string(),
                            value: format!("Bearer {}", api_key.read()),
                        }]),
                    },
                    RpcAuth::UrlParameter { url_pattern } => evm_rpc_types::RpcApi {
                        url: url_pattern.replace(API_KEY_REPLACE_STRING, api_key.read()),
                        headers: None,
                    },
                },
                None => evm_rpc_types::RpcApi {
                    url: public_url
                        .unwrap_or_else(|| {
                            panic!(
                                "API key not yet initialized for provider: {}",
                                self.provider_id
                            )
                        })
                        .to_string(),
                    headers: None,
                },
            },
            RpcAccess::Unauthenticated { public_url } => evm_rpc_types::RpcApi {
                url: public_url.to_string(),
                headers: None,
            },
        }
    }

    pub fn hostname(&self) -> Option<String> {
        hostname_from_url(match &self.access {
            RpcAccess::Authenticated { auth, .. } => match auth {
                RpcAuth::BearerToken { url } => url,
                RpcAuth::UrlParameter { url_pattern } => url_pattern,
            },
            RpcAccess::Unauthenticated { public_url } => public_url,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Serialize)]
pub enum RpcAccess {
    Authenticated {
        auth: RpcAuth,
        /// Public URL to use when the API key is not available.
        #[serde(rename = "publicUrl")]
        public_url: Option<&'static str>,
    },
    Unauthenticated {
        #[serde(rename = "publicUrl")]
        public_url: &'static str,
    },
}

impl RpcAccess {
    pub fn public_url(&self) -> Option<&'static str> {
        match self {
            RpcAccess::Authenticated { public_url, .. } => *public_url,
            RpcAccess::Unauthenticated { public_url } => Some(public_url),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize, Default)]
pub enum LogFilter {
    #[default]
    ShowAll,
    HideAll,
    ShowPattern(RegexString),
    HidePattern(RegexString),
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize, Default)]
pub struct RegexString(String);

impl RegexString {
    pub fn try_is_valid(&self, value: &str) -> Result<bool, regex::Error> {
        // Currently only used in the local replica. This can be optimized if eventually used in production.
        Ok(Regex::new(&self.0)?.is_match(value))
    }
}

impl<T> From<T> for RegexString
where
    T: Into<String>,
{
    fn from(value: T) -> Self {
        RegexString(value.into())
    }
}

impl LogFilter {
    pub fn is_match(&self, message: &str) -> bool {
        match self {
            Self::ShowAll => true,
            Self::HideAll => false,
            Self::ShowPattern(regex) => regex
                .try_is_valid(message)
                .expect("Invalid regex in ShowPattern log filter"),
            Self::HidePattern(regex) => !regex
                .try_is_valid(message)
                .expect("Invalid regex in HidePattern log filter"),
        }
    }
}

impl Storable for LogFilter {
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_json::from_slice(&bytes).expect("Error while deserializing `MessageFilter`")
    }
    fn to_bytes(&self) -> Cow<[u8]> {
        serde_json::to_vec(self)
            .expect("Error while serializing `MessageFilter`")
            .into()
    }
}

impl BoundedStorable for LogFilter {
    const IS_FIXED_SIZE: bool = true;
    const MAX_SIZE: u32 = MESSAGE_FILTER_MAX_SIZE;
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Serialize)]
pub enum RpcAuth {
    /// API key will be used in an Authorization header as Bearer token, e.g.,
    /// `Authorization: Bearer API_KEY`
    BearerToken { url: &'static str },
    UrlParameter {
        #[serde(rename = "urlPattern")]
        url_pattern: &'static str,
    },
}

#[cfg(test)]
mod test {
    use super::{ApiKey, LogFilter, RegexString};
    use candid::Principal;
    use ic_stable_structures::Storable;

    #[test]
    fn test_message_filter_storable() {
        let patterns: &[RegexString] =
            &["[.]", "^DEBUG ", "(.*)?", "\\?"].map(|regex| regex.into());
        let cases = [
            vec![
                (LogFilter::ShowAll, r#""ShowAll""#.to_string()),
                (LogFilter::HideAll, r#""HideAll""#.to_string()),
            ],
            patterns
                .iter()
                .map(|regex| {
                    (
                        LogFilter::ShowPattern(regex.clone()),
                        format!(r#"{{"ShowPattern":{:?}}}"#, regex.0),
                    )
                })
                .collect(),
            patterns
                .iter()
                .map(|regex| {
                    (
                        LogFilter::HidePattern(regex.clone()),
                        format!(r#"{{"HidePattern":{:?}}}"#, regex.0),
                    )
                })
                .collect(),
        ]
        .concat();
        for (filter, expected_json) in cases {
            let bytes = filter.to_bytes();
            assert_eq!(String::from_utf8(bytes.to_vec()).unwrap(), expected_json);
            assert_eq!(filter, LogFilter::from_bytes(bytes));
        }
    }
}
