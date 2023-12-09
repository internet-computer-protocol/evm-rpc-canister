use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use cketh_common::eth_rpc::{ProviderError, RpcError};
use cketh_common::eth_rpc_client::providers::{EthMainnetService, EthSepoliaService, RpcApi};

use ic_cdk::api::management_canister::http_request::HttpHeader;
use ic_eth::core::types::RecoveryMessage;
use ic_stable_structures::{BoundedStorable, Storable};

use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;

use crate::constants::STRING_STORABLE_MAX_SIZE;
use crate::{AUTH_SET_STORABLE_MAX_SIZE, PROVIDERS};

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Source {
    Chain(u64),
    Provider(u64),
    Service {
        hostname: String,
        #[serde(rename = "chainId")]
        chain_id: Option<u64>,
    },
    Custom {
        url: String,
        headers: Option<Vec<HttpHeader>>,
    },
}

impl Source {
    pub fn resolve(self) -> Result<ResolvedSource, ProviderError> {
        Ok(match self {
            Source::Custom { url, headers } => ResolvedSource::Api(RpcApi {
                url,
                headers: headers.unwrap_or_default(),
            }),
            Source::Provider(id) => ResolvedSource::Provider({
                PROVIDERS.with(|providers| {
                    providers
                        .borrow()
                        .get(&id)
                        .ok_or(ProviderError::ProviderNotFound)
                })?
            }),
            Source::Chain(id) => ResolvedSource::Provider(PROVIDERS.with(|providers| {
                let providers = providers.borrow();
                Ok(providers
                    .iter()
                    .find(|(_, p)| p.primary && p.chain_id == id)
                    .or_else(|| providers.iter().find(|(_, p)| p.chain_id == id))
                    .ok_or(ProviderError::ProviderNotFound)?
                    .1)
            })?),
            Source::Service { hostname, chain_id } => {
                ResolvedSource::Provider(PROVIDERS.with(|providers| {
                    let matches_provider = |p: &Provider| {
                        p.hostname == hostname
                            && match chain_id {
                                Some(id) => p.chain_id == id,
                                None => true,
                            }
                    };
                    let providers = providers.borrow();
                    Ok(providers
                        .iter()
                        .find(|(_, p)| p.primary && matches_provider(p))
                        .or_else(|| providers.iter().find(|(_, p)| matches_provider(p)))
                        .ok_or(ProviderError::ProviderNotFound)?
                        .1)
                })?)
            }
        })
    }
}

pub enum ResolvedSource {
    Api(RpcApi),
    Provider(Provider),
}

#[derive(Default)]
pub struct Metrics {
    pub requests: u64,
    pub request_cycles_charged: u128,
    pub request_cycles_refunded: u128,
    pub request_err_no_permission: u64,
    pub request_err_host_not_allowed: u64,
    pub request_err_http: u64,
    pub host_requests: HashMap<String, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, CandidType, Serialize, Deserialize)]
pub enum Auth {
    ManageService,
    RegisterProvider,
    Rpc,
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

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct Metadata {
    pub nodes_in_subnet: u32,
    pub next_provider_id: u64,
    pub open_rpc_access: bool,
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

#[derive(Clone, Debug, CandidType, Deserialize)]
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

#[derive(Clone, Debug, CandidType, Deserialize)]
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
    pub primary: Option<bool>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
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
            headers: self.credential_headers.clone(),
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
    const MAX_SIZE: u32 = 256; // A reasonable limit.
    const IS_FIXED_SIZE: bool = false;
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Message {
    Data(Vec<u8>),
    Hash([u8; 32]),
}

impl From<Message> for RecoveryMessage {
    fn from(message: Message) -> Self {
        match message {
            Message::Data(d) => RecoveryMessage::Data(d),
            Message::Hash(h) => RecoveryMessage::Hash(h.into()),
        }
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignedMessage {
    pub address: String,
    pub message: Message,
    pub signature: String,
}

pub type RpcResult<T> = Result<T, RpcError>;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum CandidRpcSource {
    EthMainnet(Option<EthMainnetService>),
    EthSepolia(Option<EthSepoliaService>),
}

pub mod candid_types {
    use std::str::FromStr;

    use candid::CandidType;
    use cketh_common::{
        address::Address,
        eth_rpc::{into_nat, FixedSizeData, ValidationError},
        eth_rpc_client::responses::TransactionStatus,
        numeric::BlockNumber,
    };
    use serde::Deserialize;

    pub use cketh_common::eth_rpc::Hash;

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
    pub enum BlockSpec {
        Number(u128),
        Tag(BlockTag),
    }

    impl From<BlockSpec> for cketh_common::eth_rpc::BlockSpec {
        fn from(value: BlockSpec) -> Self {
            use cketh_common::eth_rpc::BlockSpec::*;
            match value {
                BlockSpec::Number(n) => Number(n.into()),
                BlockSpec::Tag(t) => Tag(t.into()),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize, Default)]
    pub enum BlockTag {
        #[default]
        Latest,
        Finalized,
        Safe,
        Earliest,
        Pending,
        Number(u64),
    }

    impl From<BlockTag> for cketh_common::eth_rpc::BlockTag {
        fn from(value: BlockTag) -> cketh_common::eth_rpc::BlockTag {
            use cketh_common::eth_rpc::BlockTag::*;
            match value {
                BlockTag::Latest => Latest,
                BlockTag::Safe => Safe,
                BlockTag::Finalized => Finalized,
                _ => unimplemented!(),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
    pub struct GetLogsArgs {
        #[serde(rename = "fromBlock")]
        pub from_block: Option<BlockSpec>,
        #[serde(rename = "toBlock")]
        pub to_block: Option<BlockSpec>,
        pub addresses: Vec<String>,
        pub topics: Option<Vec<String>>,
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
                    .map(|s| {
                        FixedSizeData::from_str(&s).map_err(|_| ValidationError::InvalidHex(s))
                    })
                    .collect::<Result<_, _>>()?,
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
    pub struct TransactionReceipt {
        #[serde(rename = "blockHash")]
        pub block_hash: Hash,
        #[serde(rename = "blockNumber")]
        pub block_number: BlockNumber,
        #[serde(rename = "effectiveGasPrice")]
        pub effective_gas_price: candid::Nat,
        #[serde(rename = "gasUsed")]
        pub gas_used: candid::Nat,
        pub status: TransactionStatus,
        #[serde(rename = "transactionHash")]
        pub transaction_hash: Hash,
    }

    impl From<cketh_common::eth_rpc_client::responses::TransactionReceipt> for TransactionReceipt {
        fn from(value: cketh_common::eth_rpc_client::responses::TransactionReceipt) -> Self {
            TransactionReceipt {
                block_hash: value.block_hash,
                block_number: value.block_number,
                effective_gas_price: into_nat(value.effective_gas_price.into_inner()),
                gas_used: into_nat(value.gas_used.into_inner()),
                status: value.status,
                transaction_hash: value.transaction_hash,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
    pub struct FeeHistoryArgs {
        #[serde(rename = "blockCount")]
        pub block_count: u128,
        #[serde(rename = "newestBlock")]
        pub newest_block: BlockSpec,
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
        pub block: BlockSpec,
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
