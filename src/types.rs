use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_stable_structures::{BoundedStorable, Storable};
use num_derive::FromPrimitive;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use crate::constants::STRING_STORABLE_MAX_SIZE;
use crate::PROVIDERS;

pub type Result<T, E = EthRpcError> = std::result::Result<T, E>;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Source {
    Url(String),
    Provider(u64),
    Chain(u64),
}

impl Source {
    pub fn resolve(self) -> Result<ResolvedSource> {
        Ok(match self {
            Source::Url(name) => ResolvedSource::Url(name),
            Source::Provider(id) => ResolvedSource::Provider({
                let p = PROVIDERS.with(|providers| {
                    providers
                        .borrow()
                        .get(&id)
                        .ok_or(EthRpcError::ProviderNotFound)
                })?;
                if !p.active {
                    Err(EthRpcError::ProviderNotActive)?
                } else {
                    p
                }
            }),
            Source::Chain(id) => ResolvedSource::Provider(PROVIDERS.with(|p| {
                p.borrow()
                    .iter()
                    .find(|(_, p)| p.active && p.chain_id == id)
                    .map(|(_, p)| p)
                    .ok_or(EthRpcError::ProviderNotFound)
            })?),
        })
    }
}

#[derive(Clone, Debug)]
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
    pub base_url: String,
    pub cycles_per_call: u64,
    pub cycles_per_message_byte: u64,
    pub active: bool,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct RegisterProvider {
    pub chain_id: u64,
    pub base_url: String,
    pub credential_path: String,
    pub cycles_per_call: u64,
    pub cycles_per_message_byte: u64,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct UpdateProvider {
    pub provider_id: u64,
    pub base_url: Option<String>,
    pub credential_path: Option<String>,
    pub cycles_per_call: Option<u64>,
    pub cycles_per_message_byte: Option<u64>,
    pub active: Option<bool>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Provider {
    pub provider_id: u64,
    pub owner: Principal,
    pub chain_id: u64,
    pub base_url: String,
    pub credential_path: String,
    pub cycles_per_call: u64,
    pub cycles_per_message_byte: u64,
    pub cycles_owed: u128,
    pub active: bool,
}

impl Provider {
    pub fn service_url(&self) -> String {
        format!("{}{}", self.base_url, self.credential_path)
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

#[derive(CandidType, Debug)]
pub enum EthRpcError {
    NoPermission,
    TooFewCycles(String),
    ServiceUrlParseError,
    ServiceUrlHostMissing,
    ServiceUrlHostNotAllowed,
    ProviderNotFound,
    ProviderNotActive,
    SerializeError,
    HttpRequestError { code: u32, message: String },
}

pub type AllowlistSet = HashSet<&'static &'static str>;

pub mod candid_types {
    use candid::CandidType;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, CandidType)]
    pub enum BlockNumber {
        Latest,
        Finalized,
        Safe,
        Earliest,
        Pending,
        Number(u64),
    }

    impl Into<ic_eth::core::types::BlockNumber> for BlockNumber {
        fn into(self) -> ic_eth::core::types::BlockNumber {
            use ic_eth::core::types::BlockNumber::*;
            match self {
                Self::Latest => Latest,
                Self::Finalized => Finalized,
                Self::Safe => Safe,
                Self::Earliest => Earliest,
                Self::Pending => Pending,
                Self::Number(n) => Number(n.into()),
            }
        }
    }
}
