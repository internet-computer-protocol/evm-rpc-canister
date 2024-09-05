use candid::{CandidType, Principal};
use cketh_common::eth_rpc::RpcError;
use cketh_common::eth_rpc_client::providers::{
    EthMainnetService, EthSepoliaService, L2MainnetService, RpcApi, RpcService,
};

use ic_cdk::api::management_canister::http_request::HttpHeader;
use ic_stable_structures::{BoundedStorable, Storable};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use crate::constants::{API_KEY_MAX_SIZE, API_KEY_REPLACE_STRING, STRING_STORABLE_MAX_SIZE};
use crate::memory::get_api_key;
use crate::util::hostname_from_url;
use crate::validate::validate_api_key;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InitArgs {
    pub demo: Option<bool>,
    #[serde(rename = "manageApiKeys")]
    pub manage_api_keys: Option<Vec<Principal>>,
}

pub enum ResolvedRpcService {
    Api(RpcApi),
    Provider(Provider),
}

impl ResolvedRpcService {
    pub fn api(&self) -> RpcApi {
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

#[derive(Clone, PartialEq, Eq)]
pub struct BoolStorable(pub bool);

impl Storable for BoolStorable {
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        assert!(
            bytes.len() == 1,
            "Unexpected byte length for `BoolStorable`"
        );
        BoolStorable(bytes[0] == 0)
    }

    fn to_bytes(&self) -> Cow<[u8]> {
        vec![self.0 as u8].into()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StringStorable(pub String);

impl Storable for StringStorable {
    fn to_bytes(&self) -> Cow<[u8]> {
        // String already implements `Storable`.
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(String::from_bytes(bytes))
    }
}

impl BoundedStorable for StringStorable {
    const MAX_SIZE: u32 = STRING_STORABLE_MAX_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrincipalStorable(pub Principal);

impl Storable for PrincipalStorable {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::from(self.0.as_slice())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(Principal::from_slice(&bytes))
    }
}

impl BoundedStorable for PrincipalStorable {
    const MAX_SIZE: u32 = 29;
    const IS_FIXED_SIZE: bool = false;
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
}

impl BoundedStorable for ApiKey {
    const MAX_SIZE: u32 = API_KEY_MAX_SIZE;
    const IS_FIXED_SIZE: bool = false;
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
    pub alias: Option<RpcService>,
}

impl Provider {
    pub fn api(&self) -> RpcApi {
        match &self.access {
            RpcAccess::Authenticated { auth, public_url } => match get_api_key(self.provider_id) {
                Some(api_key) => match auth {
                    RpcAuth::BearerToken { url } => RpcApi {
                        url: url.to_string(),
                        headers: Some(vec![HttpHeader {
                            name: "Authorization".to_string(),
                            value: format!("Bearer {}", api_key.read()),
                        }]),
                    },
                    RpcAuth::UrlParameter { url_pattern } => RpcApi {
                        url: url_pattern.replace(API_KEY_REPLACE_STRING, api_key.read()),
                        headers: None,
                    },
                },
                None => RpcApi {
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
            RpcAccess::Unauthenticated { public_url } => RpcApi {
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

pub type RpcResult<T> = Result<T, RpcError>;

#[derive(Clone, Debug, Eq, PartialEq, CandidType, Deserialize)]
pub enum MultiRpcResult<T> {
    Consistent(RpcResult<T>),
    Inconsistent(Vec<(RpcService, RpcResult<T>)>),
}

impl<T> MultiRpcResult<T> {
    pub fn map<R>(self, mut f: impl FnMut(T) -> R) -> MultiRpcResult<R> {
        match self {
            MultiRpcResult::Consistent(result) => MultiRpcResult::Consistent(result.map(f)),
            MultiRpcResult::Inconsistent(results) => MultiRpcResult::Inconsistent(
                results
                    .into_iter()
                    .map(|(service, result)| {
                        (
                            service,
                            match result {
                                Ok(ok) => Ok(f(ok)),
                                Err(err) => Err(err),
                            },
                        )
                    })
                    .collect(),
            ),
        }
    }

    pub fn consistent(self) -> Option<RpcResult<T>> {
        match self {
            MultiRpcResult::Consistent(result) => Some(result),
            MultiRpcResult::Inconsistent(_) => None,
        }
    }

    pub fn inconsistent(self) -> Option<Vec<(RpcService, RpcResult<T>)>> {
        match self {
            MultiRpcResult::Consistent(_) => None,
            MultiRpcResult::Inconsistent(results) => Some(results),
        }
    }

    pub fn expect_consistent(self) -> RpcResult<T> {
        self.consistent().expect("expected consistent results")
    }

    pub fn expect_inconsistent(self) -> Vec<(RpcService, RpcResult<T>)> {
        self.inconsistent().expect("expected inconsistent results")
    }
}

impl<T> From<RpcResult<T>> for MultiRpcResult<T> {
    fn from(result: RpcResult<T>) -> Self {
        MultiRpcResult::Consistent(result)
    }
}

#[derive(Clone, CandidType, Deserialize)]
pub enum RpcServices {
    Custom {
        #[serde(rename = "chainId")]
        chain_id: u64,
        services: Vec<RpcApi>,
    },
    EthMainnet(Option<Vec<EthMainnetService>>),
    EthSepolia(Option<Vec<EthSepoliaService>>),
    ArbitrumOne(Option<Vec<L2MainnetService>>),
    BaseMainnet(Option<Vec<L2MainnetService>>),
    OptimismMainnet(Option<Vec<L2MainnetService>>),
}

pub mod candid_types {
    use std::str::FromStr;

    use candid::CandidType;
    use cketh_common::{address::Address, eth_rpc::ValidationError, numeric::BlockNumber};
    use serde::Deserialize;

    pub use cketh_common::eth_rpc::Hash;

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize, Default)]
    pub enum BlockTag {
        #[default]
        Latest,
        Finalized,
        Safe,
        Earliest,
        Pending,
        Number(BlockNumber),
    }

    impl From<BlockTag> for cketh_common::eth_rpc::BlockSpec {
        fn from(value: BlockTag) -> Self {
            use cketh_common::eth_rpc::{self, BlockSpec};
            match value {
                BlockTag::Number(n) => BlockSpec::Number(n),
                BlockTag::Latest => BlockSpec::Tag(eth_rpc::BlockTag::Latest),
                BlockTag::Safe => BlockSpec::Tag(eth_rpc::BlockTag::Safe),
                BlockTag::Finalized => BlockSpec::Tag(eth_rpc::BlockTag::Finalized),
                BlockTag::Earliest => BlockSpec::Tag(eth_rpc::BlockTag::Earliest),
                BlockTag::Pending => BlockSpec::Tag(eth_rpc::BlockTag::Pending),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
    pub struct GetTransactionCountArgs {
        pub address: String,
        pub block: BlockTag,
    }

    impl TryFrom<GetTransactionCountArgs>
        for cketh_common::eth_rpc_client::requests::GetTransactionCountParams
    {
        type Error = ValidationError;
        fn try_from(value: GetTransactionCountArgs) -> Result<Self, Self::Error> {
            Ok(
                cketh_common::eth_rpc_client::requests::GetTransactionCountParams {
                    address: Address::from_str(&value.address)
                        .map_err(|_| ValidationError::InvalidHex(value.address))?,
                    block: value.block.into(),
                },
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
    pub enum SendRawTransactionStatus {
        Ok(Option<Hash>),
        InsufficientFunds,
        NonceTooLow,
        NonceTooHigh,
    }
}

#[cfg(test)]
mod test {
    use cketh_common::{
        eth_rpc::RpcError,
        eth_rpc_client::providers::{EthMainnetService, RpcService},
    };

    use crate::types::{ApiKey, MultiRpcResult};

    #[test]
    fn test_multi_rpc_result_map() {
        use cketh_common::eth_rpc::ProviderError;

        let err = RpcError::ProviderError(ProviderError::ProviderNotFound);
        assert_eq!(
            MultiRpcResult::Consistent(Ok(5)).map(|n| n + 1),
            MultiRpcResult::Consistent(Ok(6))
        );
        assert_eq!(
            MultiRpcResult::Consistent(Err(err.clone())).map(|()| unreachable!()),
            MultiRpcResult::Consistent(Err(err.clone()))
        );
        assert_eq!(
            MultiRpcResult::Inconsistent(vec![(
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Ok(5)
            )])
            .map(|n| n + 1),
            MultiRpcResult::Inconsistent(vec![(
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Ok(6)
            )])
        );
        assert_eq!(
            MultiRpcResult::Inconsistent(vec![
                (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
                (
                    RpcService::EthMainnet(EthMainnetService::Cloudflare),
                    Ok(10)
                )
            ])
            .map(|n| n + 1),
            MultiRpcResult::Inconsistent(vec![
                (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(6)),
                (
                    RpcService::EthMainnet(EthMainnetService::Cloudflare),
                    Ok(11)
                )
            ])
        );
        assert_eq!(
            MultiRpcResult::Inconsistent(vec![
                (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
                (
                    RpcService::EthMainnet(EthMainnetService::PublicNode),
                    Err(err.clone())
                )
            ])
            .map(|n| n + 1),
            MultiRpcResult::Inconsistent(vec![
                (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(6)),
                (
                    RpcService::EthMainnet(EthMainnetService::PublicNode),
                    Err(err)
                )
            ])
        );
    }

    #[test]
    fn test_api_key_debug_output() {
        let api_key = ApiKey("55555".to_string());
        assert!(format!("{api_key:?}") == "{API_KEY}");
    }
}
