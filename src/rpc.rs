use crate::*;
use async_trait::async_trait;
use ethers_providers::{JsonRpcClient, ProviderError};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

pub fn get_provider(
    source: ResolvedSource,
    max_response_bytes: u64,
) -> ethers_providers::Provider<HttpOutcallClient> {
    ethers_providers::Provider::new(HttpOutcallClient::new(source, max_response_bytes))
}

#[derive(Debug)]
pub struct HttpOutcallClient {
    pub source: ResolvedSource,
    pub max_response_bytes: u64,
}

impl HttpOutcallClient {
    pub fn new(source: ResolvedSource, max_response_bytes: u64) -> Self {
        Self {
            source,
            max_response_bytes,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl JsonRpcClient for HttpOutcallClient {
    type Error = ProviderError;

    async fn request<T, R>(&self, method: &str, params: T) -> Result<R, Self::Error>
    where
        T: Debug + Serialize + Send + Sync,
        R: DeserializeOwned,
    {
        Ok(
            do_http_request(self.source.clone(), method, params, self.max_response_bytes)
                .await
                .unwrap(), // TODO: error handling
        )
    }
}
