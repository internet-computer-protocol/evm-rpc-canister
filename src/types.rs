use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_eth::core::types::RecoveryMessage;
use ic_stable_structures::{BoundedStorable, Storable};

use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;

use crate::constants::STRING_STORABLE_MAX_SIZE;
use crate::{PROVIDERS, AUTH_SET_STORABLE_MAX_SIZE};

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

#[derive(Clone, Copy, Debug, PartialEq, CandidType, Serialize, Deserialize)]
pub enum Auth {
    Admin,
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
        serde_json::from_slice(&*bytes).expect("Unable to deserialize AuthSet")
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

// pub type AllowlistSet = HashSet<&'static &'static str>;
