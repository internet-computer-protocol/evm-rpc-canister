use std::str::FromStr;

use async_trait::async_trait;
use cketh_common::{
    eth_rpc::{
        into_nat, Block, FeeHistory, GetLogsParam, Hash, HttpOutcallError, JsonRpcReply, LogEntry,
        ProviderError, RpcError, SendRawTransactionResult, ValidationError,
    },
    eth_rpc_client::{
        providers::{RpcApi, RpcNodeProvider},
        requests::GetTransactionCountParams,
        EthRpcClient as CkEthRpcClient, MultiCallError, RpcTransport,
    },
    lifecycle::EthereumNetwork,
};
use serde::de::DeserializeOwned;

use crate::*;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanisterTransport;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RpcTransport for CanisterTransport {
    fn get_subnet_size() -> u32 {
        METADATA.with(|m| m.borrow().get().nodes_in_subnet)
    }

    fn resolve_api(provider: RpcNodeProvider) -> Result<RpcApi, ProviderError> {
        // TODO: https://github.com/internet-computer-protocol/ic-eth-rpc/issues/73
        Ok(provider.api())
    }

    async fn call_json_rpc<T: DeserializeOwned>(
        provider: RpcNodeProvider,
        json: &str,
        max_response_bytes: u64,
    ) -> Result<T, RpcError> {
        let response = do_http_request(
            ic_cdk::caller(),
            ResolvedSource::Api(Self::resolve_api(provider)?),
            json,
            max_response_bytes,
        )
        .await
        .unwrap();
        let status = get_http_response_status(response.status.clone());
        let body = get_http_response_body(response)?;
        let json: JsonRpcReply<T> = serde_json::from_str(&body).unwrap_or_else(|e| {
            Err(HttpOutcallError::InvalidHttpJsonRpcResponse {
                status,
                body,
                parsing_error: Some(format!("JSON response parse error: {e}")),
            })
        })?;
        json.result.into()
    }
}

fn get_rpc_client(source: CandidRpcSource) -> RpcResult<CkEthRpcClient<CanisterTransport>> {
    fn validate_providers<T>(opt_vec: Option<Vec<T>>) -> RpcResult<Option<Vec<T>>> {
        Ok(match opt_vec {
            Some(v) if v.is_empty() => Err(ProviderError::ProviderNotFound)?,
            opt => opt,
        })
    }
    if !is_rpc_allowed(&ic_cdk::caller()) {
        // inc_metric!(eth_*_err_no_permission);
        return Err(ProviderError::NoPermission.into());
    }
    Ok(match source {
        CandidRpcSource::EthMainnet(service) => CkEthRpcClient::new(
            EthereumNetwork::Ethereum,
            validate_providers(Some(vec![service.unwrap_or(
                cketh_common::eth_rpc_client::providers::EthereumProvider::Ankr,
            )]))?
            .map(|p| p.into_iter().map(RpcNodeProvider::Ethereum).collect()),
        ),
        CandidRpcSource::EthSepolia(service) => CkEthRpcClient::new(
            EthereumNetwork::Sepolia,
            validate_providers(Some(vec![service.unwrap_or(
                cketh_common::eth_rpc_client::providers::SepoliaProvider::PublicNode,
            )]))?
            .map(|p| p.into_iter().map(RpcNodeProvider::Sepolia).collect()),
        ),
    })
}

fn wrap_result<T>(result: Result<T, MultiCallError<T>>) -> RpcResult<T> {
    match result {
        Ok(value) => Ok(value),
        Err(err) => match err {
            MultiCallError::ConsistentError(err) => Err(err),
            MultiCallError::InconsistentResults(_results) => {
                unreachable!("BUG: receieved more than one RPC provider result")
            }
        },
    }
}

pub struct CandidRpcClient {
    client: CkEthRpcClient<CanisterTransport>,
}

impl CandidRpcClient {
    pub fn from_source(source: CandidRpcSource) -> RpcResult<Self> {
        Ok(Self {
            client: get_rpc_client(source)?,
        })
    }

    pub async fn eth_get_logs(&self, args: candid_types::GetLogsArgs) -> RpcResult<Vec<LogEntry>> {
        let args: GetLogsParam = match args.try_into() {
            Ok(args) => args,
            Err(err) => return Err(RpcError::from(err)),
        };
        wrap_result(self.client.eth_get_logs(args).await)
    }

    pub async fn eth_get_block_by_number(
        &self,
        block: candid_types::BlockSpec,
    ) -> RpcResult<Block> {
        wrap_result(self.client.eth_get_block_by_number(block.into()).await)
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        hash: String,
    ) -> RpcResult<Option<candid_types::TransactionReceipt>> {
        wrap_result(
            self.client
                .eth_get_transaction_receipt(
                    Hash::from_str(&hash).map_err(|_| ValidationError::InvalidHex(hash))?,
                )
                .await,
        )
        .map(|option| option.map(|r| r.into()))
    }

    pub async fn eth_get_transaction_count(
        &self,
        args: candid_types::GetTransactionCountArgs,
    ) -> RpcResult<candid::Nat> {
        let args: GetTransactionCountParams = match args.try_into() {
            Ok(args) => args,
            Err(err) => return Err(RpcError::from(err)),
        };
        wrap_result(
            self.client
                .eth_get_transaction_count(args)
                .await
                .reduce_with_equality(),
        )
        .map(|count| into_nat(count.into_inner()))
    }

    pub async fn eth_fee_history(
        &self,
        args: candid_types::FeeHistoryArgs,
    ) -> RpcResult<Option<FeeHistory>> {
        wrap_result(self.client.eth_fee_history(args.into()).await).map(|history| history.into())
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: String,
    ) -> RpcResult<SendRawTransactionResult> {
        self.client
            .eth_send_raw_transaction(raw_signed_transaction_hex)
            .await
    }
}
