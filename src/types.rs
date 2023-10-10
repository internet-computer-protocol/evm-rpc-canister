use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use cketh_common::eth_rpc_client::providers::{EthereumProvider, SepoliaProvider};
use cketh_common::eth_rpc_client::MultiCallError;
use ic_eth::core::types::RecoveryMessage;
use ic_stable_structures::{BoundedStorable, Storable};
use num_derive::FromPrimitive;
use std::borrow::Cow;
use std::collections::HashMap;

use crate::constants::STRING_STORABLE_MAX_SIZE;
use crate::PROVIDERS;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Source {
    Url(String),
    Provider(u64),
    Chain(u64),
    Service {
        hostname: String,
        chain_id: Option<u64>,
    },
}

impl Source {
    pub fn resolve(self) -> Result<ResolvedSource, EthRpcError> {
        Ok(match self {
            Source::Url(name) => ResolvedSource::Url(name),
            Source::Provider(id) => ResolvedSource::Provider({
                PROVIDERS.with(|providers| {
                    providers
                        .borrow()
                        .get(&id)
                        .ok_or(EthRpcError::ProviderNotFound)
                })?
            }),
            Source::Chain(id) => ResolvedSource::Provider(PROVIDERS.with(|providers| {
                let providers = providers.borrow();
                Ok(providers
                    .iter()
                    .find(|(_, p)| p.primary && p.chain_id == id)
                    .or_else(|| providers.iter().find(|(_, p)| p.chain_id == id))
                    .ok_or(EthRpcError::ProviderNotFound)?
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
                        .ok_or(EthRpcError::ProviderNotFound)?
                        .1)
                })?)
            }
        })
    }
}

pub enum ResolvedSource {
    Url(String),
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

// These need to be powers of two so that they can be used as bit fields.
#[derive(Clone, Debug, PartialEq, CandidType, FromPrimitive, Deserialize)]
pub enum Auth {
    Admin = 0b0001,
    Rpc = 0b0010,
    RegisterProvider = 0b0100,
    FreeRpc = 0b1000,
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
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        // String already implements `Storable`.
        self.0.to_bytes()
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self(String::from_bytes(bytes))
    }
}

impl BoundedStorable for StringStorable {
    const MAX_SIZE: u32 = STRING_STORABLE_MAX_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for PrincipalStorable {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::from(self.0.as_slice())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self(Principal::from_slice(&bytes))
    }
}

impl BoundedStorable for PrincipalStorable {
    const MAX_SIZE: u32 = 29;
    const IS_FIXED_SIZE: bool = false;
}

#[derive(Debug, CandidType)]
pub struct ProviderView {
    pub provider_id: u64,
    pub owner: Principal,
    pub chain_id: u64,
    pub hostname: String,
    pub cycles_per_call: u64,
    pub cycles_per_message_byte: u64,
    pub primary: bool,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct RegisterProvider {
    pub chain_id: u64,
    pub hostname: String,
    pub credential_path: String,
    pub cycles_per_call: u64,
    pub cycles_per_message_byte: u64,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct UpdateProvider {
    pub provider_id: u64,
    pub hostname: Option<String>,
    pub credential_path: Option<String>,
    pub cycles_per_call: Option<u64>,
    pub cycles_per_message_byte: Option<u64>,
    pub primary: Option<bool>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Provider {
    pub provider_id: u64,
    pub owner: Principal,
    pub chain_id: u64,
    pub hostname: String,
    pub credential_path: String,
    pub cycles_per_call: u64,
    pub cycles_per_message_byte: u64,
    pub cycles_owed: u128,
    pub primary: bool,
}

impl Provider {
    pub fn service_url(&self) -> String {
        format!("https://{}{}", self.hostname, self.credential_path)
    }
}

impl Storable for Metadata {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Self).unwrap()
    }
}

impl Storable for Provider {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
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

#[derive(CandidType, Debug, Deserialize)]
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

#[derive(CandidType, Debug, Deserialize)]
pub struct SignedMessage {
    // TODO: Candid `blob` in place of `vec nat8`
    pub address: Vec<u8>,
    pub message: Message,
    pub signature: Vec<u8>,
}

#[derive(CandidType, Debug)]
pub enum EthRpcError {
    NoPermission,
    TooFewCycles { expected: u128, received: u128 },
    ServiceUrlParseError,
    ServiceHostNotAllowed(String),
    ResponseParseError,
    ProviderNotFound,
    HttpRequestError { code: u32, message: String },
}

pub type MultiCallResult<T> = Result<T, MultiCallError<T>>;

#[derive(Deserialize, CandidType)]
pub enum MultiSource {
    Ethereum(Option<Vec<EthereumProvider>>),
    Sepolia(Option<Vec<SepoliaProvider>>),
}

pub mod candid_types {
    use candid::CandidType;
    use cketh_common::address::Address;
    use serde::Deserialize;

    #[derive(Deserialize, CandidType)]
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

    #[derive(CandidType, Debug, Default, Deserialize)]
    pub enum BlockTag {
        #[default]
        Latest,
        Safe,
        Finalized,
    }

    impl From<BlockTag> for cketh_common::eth_rpc::BlockTag {
        fn from(value: BlockTag) -> cketh_common::eth_rpc::BlockTag {
            use cketh_common::eth_rpc::BlockTag::*;
            match value {
                BlockTag::Latest => Latest,
                BlockTag::Safe => Safe,
                BlockTag::Finalized => Finalized,
            }
        }
    }

    #[derive(CandidType, Default, Deserialize)]
    // #[serde(rename_all = "camelCase")]
    pub struct GetLogsArgs {
        // pub from_block: Option<BlockSpec>,
        // pub to_block: Option<BlockSpec>,
        pub addresses: Vec<[u8; 20]>,
        // pub topics: Option<Vec<FixedSizeData>>,
    }

    impl From<GetLogsArgs> for cketh_common::eth_rpc::GetLogsParam {
        fn from(value: GetLogsArgs) -> Self {
            cketh_common::eth_rpc::GetLogsParam {
                // from_block: value.from_block.map(|x| x.into()),
                // to_block: value.to_block.map(|x| x.into()),
                address: value.addresses.into_iter().map(Address::new).collect(),
                // topics: value.topics,
                from_block: None,
                to_block: None,
                topics: None,
            }
        }
    }
}
