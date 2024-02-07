use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use cketh_common::eth_rpc::RpcError;
use cketh_common::eth_rpc_client::providers::{
    EthMainnetService, EthSepoliaService, RpcApi, RpcService,
};

use ic_cdk::api::management_canister::http_request::HttpHeader;
use ic_stable_structures::{BoundedStorable, Storable};

use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;

use crate::constants::STRING_STORABLE_MAX_SIZE;
use crate::{
    AUTH_SET_STORABLE_MAX_SIZE, DEFAULT_OPEN_RPC_ACCESS, PROVIDER_MAX_SIZE, RPC_SERVICE_MAX_SIZE,
};

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InitArgs {
    #[serde(rename = "nodesInSubnet")]
    pub nodes_in_subnet: u32,
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

#[derive(Clone, Copy, Debug, PartialEq, CandidType, Serialize, Deserialize)]
pub enum Auth {
    Manage,
    RegisterProvider,
    PriorityRpc,
    FreeRpc,
}

#[derive(Clone, Debug, PartialEq, CandidType, Serialize, Deserialize, Default)]
pub struct AuthSet(Vec<Auth>);

impl AuthSet {
    pub fn new(auths: Vec<Auth>) -> Self {
        let mut auth_set = Self(Vec::with_capacity(auths.len()));
        for auth in auths {
            // Deduplicate
            auth_set.authorize(auth);
        }
        auth_set
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_authorized(&self, auth: Auth) -> bool {
        self.0.contains(&auth)
    }

    pub fn authorize(&mut self, auth: Auth) -> bool {
        if !self.is_authorized(auth) {
            self.0.push(auth);
            true
        } else {
            false
        }
    }

    pub fn deauthorize(&mut self, auth: Auth) -> bool {
        if let Some(index) = self.0.iter().position(|a| *a == auth) {
            self.0.remove(index);
            true
        } else {
            false
        }
    }
}

// Using explicit JSON representation in place of enum indices for security
impl Storable for AuthSet {
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_json::from_slice(&bytes).expect("Unable to deserialize AuthSet")
    }

    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(self).expect("Unable to serialize AuthSet"))
    }
}

impl BoundedStorable for AuthSet {
    const MAX_SIZE: u32 = AUTH_SET_STORABLE_MAX_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Metadata {
    pub next_provider_id: u64,
    pub open_rpc_access: bool,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            next_provider_id: 0,
            open_rpc_access: DEFAULT_OPEN_RPC_ACCESS,
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct StringStorable(pub String);

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct PrincipalStorable(pub Principal);

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

#[derive(Clone, Debug, Eq, PartialEq, CandidType, Deserialize)]
pub struct ProviderView {
    #[serde(rename = "providerId")]
    pub provider_id: u64,
    pub owner: Principal,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    pub hostname: String,
    #[serde(rename = "cyclesPerCall")]
    pub cycles_per_call: u64,
    #[serde(rename = "cyclesPerMessageByte")]
    pub cycles_per_message_byte: u64,
    pub primary: bool,
}

impl From<Provider> for ProviderView {
    fn from(provider: Provider) -> Self {
        ProviderView {
            provider_id: provider.provider_id,
            owner: provider.owner,
            chain_id: provider.chain_id,
            hostname: provider.hostname,
            cycles_per_call: provider.cycles_per_call,
            cycles_per_message_byte: provider.cycles_per_message_byte,
            primary: provider.primary,
        }
    }
}

#[derive(Clone, CandidType, Deserialize)]
pub struct RegisterProviderArgs {
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    pub hostname: String,
    #[serde(rename = "credentialPath")]
    pub credential_path: String,
    #[serde(rename = "credentialHeaders")]
    pub credential_headers: Option<Vec<HttpHeader>>,
    #[serde(rename = "cyclesPerCall")]
    pub cycles_per_call: u64,
    #[serde(rename = "cyclesPerMessageByte")]
    pub cycles_per_message_byte: u64,
}

#[derive(Clone, CandidType, Deserialize)]
pub struct UpdateProviderArgs {
    #[serde(rename = "providerId")]
    pub provider_id: u64,
    pub hostname: Option<String>,
    #[serde(rename = "credentialPath")]
    pub credential_path: Option<String>,
    #[serde(rename = "credentialHeaders")]
    pub credential_headers: Option<Vec<HttpHeader>>,
    #[serde(rename = "cyclesPerCall")]
    pub cycles_per_call: Option<u64>,
    #[serde(rename = "cyclesPerMessageByte")]
    pub cycles_per_message_byte: Option<u64>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ManageProviderArgs {
    #[serde(rename = "providerId")]
    pub provider_id: u64,
    pub primary: Option<bool>,
    pub service: Option<RpcService>,
}

#[derive(Clone, CandidType, Deserialize)]
pub struct Provider {
    #[serde(rename = "providerId")]
    pub provider_id: u64,
    pub owner: Principal,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    pub hostname: String,
    #[serde(rename = "credentialPath")]
    pub credential_path: String,
    #[serde(rename = "credentialHeaders")]
    pub credential_headers: Vec<HttpHeader>,
    #[serde(rename = "cyclesPerCall")]
    pub cycles_per_call: u64,
    #[serde(rename = "cyclesPerMessageByte")]
    pub cycles_per_message_byte: u64,
    #[serde(rename = "cyclesOwed")]
    pub cycles_owed: u128,
    pub primary: bool,
}

impl Provider {
    pub fn api(&self) -> RpcApi {
        RpcApi {
            url: format!("https://{}{}", self.hostname, self.credential_path),
            headers: if self.credential_headers.is_empty() {
                None
            } else {
                Some(self.credential_headers.clone())
            },
        }
    }
}

impl Storable for Metadata {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}

impl Storable for Provider {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}

impl BoundedStorable for Provider {
    const MAX_SIZE: u32 = PROVIDER_MAX_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct StorableRpcService(Vec<u8>);

impl TryFrom<StorableRpcService> for RpcService {
    type Error = serde_json::Error;
    fn try_from(value: StorableRpcService) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value.0)
    }
}

impl StorableRpcService {
    pub fn new(service: &RpcService) -> Self {
        // Store as JSON string to remove the possibility of RPC services getting mixed up
        // if we make changes to `RpcService`, `EthMainnetService`, etc.
        Self(
            serde_json::to_vec(service)
                .expect("BUG: unexpected error while serializing RpcService"),
        )
    }
}

impl Storable for StorableRpcService {
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        StorableRpcService(bytes.to_vec())
    }

    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.to_owned())
    }
}

impl BoundedStorable for StorableRpcService {
    const MAX_SIZE: u32 = RPC_SERVICE_MAX_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

pub type RpcResult<T> = Result<T, RpcError>;

#[derive(Clone, Debug, Eq, PartialEq, CandidType, Deserialize)]
pub enum MultiRpcResult<T> {
    Consistent(RpcResult<T>),
    Inconsistent(Vec<(RpcService, RpcResult<T>)>),
}

impl<T> MultiRpcResult<T> {
    pub fn map<R>(self, f: impl Fn(T) -> R) -> MultiRpcResult<R> {
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
    EthMainnet(Option<Vec<EthMainnetService>>),
    EthSepolia(Option<Vec<EthSepoliaService>>),
    Custom {
        #[serde(rename = "chainId")]
        chain_id: u64,
        services: Vec<RpcApi>,
    },
}

pub mod candid_types {
    use std::str::FromStr;

    use candid::CandidType;
    use cketh_common::{
        address::Address,
        eth_rpc::{into_nat, FixedSizeData, ValidationError},
        numeric::BlockNumber,
    };
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
            use cketh_common::eth_rpc::BlockSpec::*;
            use cketh_common::eth_rpc::BlockTag::*;
            match value {
                BlockTag::Number(n) => Number(n),
                BlockTag::Latest => Tag(Latest),
                BlockTag::Safe => Tag(Safe),
                BlockTag::Finalized => Tag(Finalized),
                BlockTag::Earliest => Tag(Earliest),
                BlockTag::Pending => Tag(Pending),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
    pub struct GetLogsArgs {
        #[serde(rename = "fromBlock")]
        pub from_block: Option<BlockTag>,
        #[serde(rename = "toBlock")]
        pub to_block: Option<BlockTag>,
        pub addresses: Vec<String>,
        pub topics: Option<Vec<Vec<String>>>,
    }

    impl TryFrom<GetLogsArgs> for cketh_common::eth_rpc::GetLogsParam {
        type Error = ValidationError;
        fn try_from(value: GetLogsArgs) -> Result<Self, Self::Error> {
            Ok(cketh_common::eth_rpc::GetLogsParam {
                from_block: value.from_block.map(|x| x.into()).unwrap_or_default(),
                to_block: value.to_block.map(|x| x.into()).unwrap_or_default(),
                address: value
                    .addresses
                    .into_iter()
                    .map(|s| Address::from_str(&s).map_err(|_| ValidationError::InvalidHex(s)))
                    .collect::<Result<_, _>>()?,
                topics: value
                    .topics
                    .unwrap_or_default()
                    .into_iter()
                    .map(|topic| {
                        topic
                            .into_iter()
                            .map(|s| {
                                FixedSizeData::from_str(&s)
                                    .map_err(|_| ValidationError::InvalidHex(s))
                            })
                            .collect::<Result<_, _>>()
                    })
                    .collect::<Result<_, _>>()?,
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
    pub struct TransactionReceipt {
        #[serde(rename = "blockHash")]
        pub block_hash: String,
        #[serde(rename = "blockNumber")]
        pub block_number: BlockNumber,
        #[serde(rename = "effectiveGasPrice")]
        pub effective_gas_price: candid::Nat,
        #[serde(rename = "gasUsed")]
        pub gas_used: candid::Nat,
        pub status: candid::Nat,
        #[serde(rename = "transactionHash")]
        pub transaction_hash: String,
        #[serde(rename = "contractAddress")]
        pub contract_address: Option<String>,
        pub from: String,
        pub logs: Vec<cketh_common::eth_rpc::LogEntry>,
        #[serde(rename = "logsBloom")]
        pub logs_bloom: String,
        pub to: String,
        #[serde(rename = "transactionIndex")]
        pub transaction_index: candid::Nat,
        pub r#type: String,
    }

    impl From<cketh_common::eth_rpc_client::responses::TransactionReceipt> for TransactionReceipt {
        fn from(value: cketh_common::eth_rpc_client::responses::TransactionReceipt) -> Self {
            TransactionReceipt {
                block_hash: format!("{:#x}", value.block_hash),
                block_number: value.block_number,
                effective_gas_price: into_nat(value.effective_gas_price.into_inner()),
                gas_used: into_nat(value.gas_used.into_inner()),
                status: into_nat(value.status.into()),
                transaction_hash: format!("{:#x}", value.transaction_hash),
                contract_address: value.contract_address,
                from: value.from,
                logs: value.logs,
                logs_bloom: value.logs_bloom,
                to: value.to,
                transaction_index: into_nat(value.transaction_index.into_inner()),
                r#type: value.r#type,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
    pub struct FeeHistoryArgs {
        #[serde(rename = "blockCount")]
        pub block_count: u128,
        #[serde(rename = "newestBlock")]
        pub newest_block: BlockTag,
        #[serde(rename = "rewardPercentiles")]
        pub reward_percentiles: Option<Vec<u8>>,
    }

    impl From<FeeHistoryArgs> for cketh_common::eth_rpc::FeeHistoryParams {
        fn from(value: FeeHistoryArgs) -> Self {
            cketh_common::eth_rpc::FeeHistoryParams {
                block_count: value.block_count.into(),
                highest_block: value.newest_block.into(),
                reward_percentiles: value.reward_percentiles.unwrap_or_default(),
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
}

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
