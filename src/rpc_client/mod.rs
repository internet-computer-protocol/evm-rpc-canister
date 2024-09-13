use async_trait::async_trait;
use candid::CandidType;
use evm_rpc_types::{ProviderError, RpcApi, RpcConfig, RpcError, RpcService, RpcServices};
use ic_cdk::api::management_canister::http_request::{CanisterHttpRequestArgument, HttpResponse};
use serde_json::to_vec;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait RpcTransport: Debug {
    fn resolve_api(provider: &RpcService) -> Result<RpcApi, ProviderError>;

    async fn http_request(
        provider: &RpcService,
        method: &str,
        request: CanisterHttpRequestArgument,
        effective_size_estimate: u64,
    ) -> Result<HttpResponse, RpcError>;
}

// Placeholder during refactoring
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultTransport;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RpcTransport for cketh_common::eth_rpc_client::DefaultTransport {
    fn resolve_api(_provider: &RpcService) -> Result<RpcApi, ProviderError> {
        unimplemented!()
    }

    async fn http_request(
        _provider: &RpcService,
        _method: &str,
        _request: CanisterHttpRequestArgument,
        _effective_size_estimate: u64,
    ) -> Result<HttpResponse, RpcError> {
        unimplemented!()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthereumNetwork(#[n(0)] u64);

/// Aggregates responses of different providers to the same query.
/// Guaranteed to be non-empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiCallResults<T> {
    pub results: BTreeMap<RpcService, Result<T, RpcError>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MultiCallError<T> {
    ConsistentError(RpcError),
    InconsistentResults(MultiCallResults<T>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthRpcClient<T: RpcTransport> {
    chain: EthereumNetwork,
    providers: Option<Vec<RpcService>>,
    config: RpcConfig,
    phantom: PhantomData<T>,
}

impl<T: RpcTransport> EthRpcClient<T> {
    pub fn new(source: RpcServices, config: RpcConfig) -> Result<Self, ProviderError> {
        todo!()
    }
}
