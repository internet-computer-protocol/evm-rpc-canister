use std::str::FromStr;

use async_trait::async_trait;
use cketh_common::{
    eth_rpc::{
        into_nat, Block, FeeHistory, GetLogsParam, Hash, LogEntry, ProviderError, RpcError,
        SendRawTransactionResult, ValidationError,
    },
    eth_rpc_client::{
        providers::{RpcApi, RpcNodeProvider},
        requests::GetTransactionCountParams,
        EthRpcClient as CkEthRpcClient, MultiCallError, RpcTransport,
    },
    lifecycle::EthereumNetwork,
};
use ic_cdk::api::{
    call::CallResult,
    management_canister::http_request::{CanisterHttpRequestArgument, HttpResponse},
};

use crate::*;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanisterTransport;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RpcTransport for CanisterTransport {
    fn get_subnet_size() -> u32 {
        METADATA.with(|m| m.borrow().get().nodes_in_subnet)
    }

    fn resolve_api(provider: &RpcNodeProvider) -> Result<RpcApi, ProviderError> {
        // TODO: https://github.com/internet-computer-protocol/ic-eth-rpc/issues/73
        Ok(provider.api())
    }

    async fn http_request(
        _provider: &RpcNodeProvider,
        request: CanisterHttpRequestArgument,
        cost: u128,
    ) -> CallResult<HttpResponse> {
        Ok(
            ic_cdk::api::management_canister::http_request::http_request(request, cost)
                .await?
                .0,
        )
    }
}

fn get_rpc_client(source: CandidRpcSource) -> RpcResult<CkEthRpcClient<CanisterTransport>> {
    if !is_rpc_allowed(&ic_cdk::caller()) {
        return Err(ProviderError::NoPermission.into());
    }
    Ok(match source {
        CandidRpcSource::EthMainnet(service) => CkEthRpcClient::new(
            EthereumNetwork::Ethereum,
            Some(vec![service.unwrap_or(DEFAULT_ETHEREUM_PROVIDER)])
                .map(|p| p.into_iter().map(RpcNodeProvider::Ethereum).collect()),
        ),
        CandidRpcSource::EthSepolia(service) => CkEthRpcClient::new(
            EthereumNetwork::Sepolia,
            Some(vec![service.unwrap_or(DEFAULT_SEPOLIA_PROVIDER)])
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
