use std::str::FromStr;

use async_trait::async_trait;
use cketh_common::{
    eth_rpc::{
        into_nat, Block, FeeHistory, GetLogsParam, Hash, HttpOutcallError, LogEntry, ProviderError,
        RpcError, SendRawTransactionResult, ValidationError,
    },
    eth_rpc_client::{
        providers::{EthMainnetService, EthSepoliaService, RpcApi, RpcService},
        requests::GetTransactionCountParams,
        EthRpcClient as CkEthRpcClient, MultiCallError, RpcTransport,
    },
    lifecycle::EthereumNetwork,
};
use ic_cdk::api::management_canister::http_request::{CanisterHttpRequestArgument, HttpResponse};

use crate::*;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanisterTransport;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RpcTransport for CanisterTransport {
    fn get_subnet_size() -> u32 {
        TRANSIENT_SUBNET_SIZE.with(|m| *m.borrow())
    }

    fn resolve_api(provider: &RpcService) -> Result<RpcApi, ProviderError> {
        use RpcService::*;
        let (chain_id, hostname) = match provider {
            EthMainnet(provider) => (
                ETH_MAINNET_CHAIN_ID,
                match provider {
                    EthMainnetService::Ankr => ANKR_HOSTNAME,
                    EthMainnetService::BlockPi => BLOCKPI_ETH_MAINNET_HOSTNAME,
                    EthMainnetService::PublicNode => PUBLICNODE_ETH_MAINNET_HOSTNAME,
                    EthMainnetService::Cloudflare => CLOUDFLARE_HOSTNAME,
                },
            ),
            EthSepolia(provider) => (
                ETH_SEPOLIA_CHAIN_ID,
                match provider {
                    EthSepoliaService::Ankr => ANKR_HOSTNAME,
                    EthSepoliaService::BlockPi => BLOCKPI_ETH_SEPOLIA_HOSTNAME,
                    EthSepoliaService::PublicNode => PUBLICNODE_ETH_SEPOLIA_HOSTNAME,
                },
            ),
        };
        Ok(
            find_provider(|p| p.chain_id == chain_id && p.hostname == hostname)
                .ok_or(ProviderError::MissingRequiredProvider)?
                .api(),
        )
    }

    async fn http_request(
        _provider: &RpcService,
        request: CanisterHttpRequestArgument,
        cycles_cost: u128,
    ) -> RpcResult<HttpResponse> {
        if !is_authorized(&ic_cdk::caller(), Auth::FreeRpc) {
            let cycles_available = ic_cdk::api::call::msg_cycles_available128();
            if cycles_available < cycles_cost {
                return Err(ProviderError::TooFewCycles {
                    expected: cycles_cost,
                    received: cycles_available,
                }
                .into());
            }
            ic_cdk::api::call::msg_cycles_accept128(cycles_cost);
        }
        match ic_cdk::api::management_canister::http_request::http_request(request, cycles_cost)
            .await
        {
            Ok((response,)) => Ok(response),
            Err((code, message)) => Err(HttpOutcallError::IcError { code, message }.into()),
        }
    }
}

fn check_services<T>(services: Option<Vec<T>>) -> RpcResult<Option<Vec<T>>> {
    match services {
        Some(services) => {
            if services.is_empty() {
                Err(ProviderError::ProviderNotFound)?;
            }
            Ok(Some(services))
        }
        None => Ok(None),
    }
}

fn get_rpc_client(source: RpcSource) -> RpcResult<CkEthRpcClient<CanisterTransport>> {
    if !is_rpc_allowed(&ic_cdk::caller()) {
        return Err(ProviderError::NoPermission.into());
    }
    Ok(match source {
        RpcSource::EthMainnet(services) => CkEthRpcClient::new(
            EthereumNetwork::Mainnet,
            Some(
                check_services(services)?
                    .unwrap_or_else(|| DEFAULT_ETHEREUM_SERVICES.to_vec())
                    .into_iter()
                    .map(RpcService::EthMainnet)
                    .collect(),
            ),
        ),
        RpcSource::EthSepolia(services) => CkEthRpcClient::new(
            EthereumNetwork::Sepolia,
            Some(
                check_services(services)?
                    .unwrap_or_else(|| DEFAULT_SEPOLIA_SERVICES.to_vec())
                    .into_iter()
                    .map(RpcService::EthSepolia)
                    .collect(),
            ),
        ),
    })
}

fn multi_result<T>(result: Result<T, MultiCallError<T>>) -> MultiRpcResult<T> {
    match result {
        Ok(value) => MultiRpcResult::Consistent(Ok(value)),
        Err(err) => match err {
            MultiCallError::ConsistentError(err) => MultiRpcResult::Consistent(Err(err)),
            MultiCallError::InconsistentResults(multi_call_results) => {
                MultiRpcResult::Inconsistent(multi_call_results.results.into_iter().collect())
            }
        },
    }
}

pub struct CandidRpcClient {
    client: CkEthRpcClient<CanisterTransport>,
}

impl CandidRpcClient {
    pub fn from_source(source: RpcSource) -> RpcResult<Self> {
        Ok(Self {
            client: get_rpc_client(source)?,
        })
    }

    pub async fn eth_get_logs(
        &self,
        args: candid_types::GetLogsArgs,
    ) -> MultiRpcResult<Vec<LogEntry>> {
        let args: GetLogsParam = match args.try_into() {
            Ok(args) => args,
            Err(err) => return MultiRpcResult::Consistent(Err(RpcError::from(err))),
        };
        multi_result(self.client.eth_get_logs(args).await)
    }

    pub async fn eth_get_block_by_number(
        &self,
        block: candid_types::BlockTag,
    ) -> MultiRpcResult<Block> {
        multi_result(self.client.eth_get_block_by_number(block.into()).await)
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        hash: String,
    ) -> MultiRpcResult<Option<candid_types::TransactionReceipt>> {
        match Hash::from_str(&hash) {
            Ok(hash) => multi_result(self.client.eth_get_transaction_receipt(hash).await)
                .map(|option| option.map(|r| r.into())),
            Err(_) => MultiRpcResult::Consistent(Err(ValidationError::InvalidHex(hash).into())),
        }
    }

    pub async fn eth_get_transaction_count(
        &self,
        args: candid_types::GetTransactionCountArgs,
    ) -> MultiRpcResult<candid::Nat> {
        let args: GetTransactionCountParams = match args.try_into() {
            Ok(args) => args,
            Err(err) => return MultiRpcResult::Consistent(Err(RpcError::from(err))),
        };
        multi_result(
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
    ) -> MultiRpcResult<Option<FeeHistory>> {
        multi_result(self.client.eth_fee_history(args.into()).await).map(|history| history.into())
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: String,
    ) -> MultiRpcResult<SendRawTransactionResult> {
        multi_result(
            self.client
                .multi_eth_send_raw_transaction(raw_signed_transaction_hex)
                .await,
        )
    }
}

#[test]
fn test_multi_result_mapping() {
    use cketh_common::eth_rpc_client::MultiCallResults;

    assert_eq!(multi_result(Ok(5)), MultiRpcResult::Consistent(Ok(5)));
    assert_eq!(
        multi_result(Err(MultiCallError::<()>::ConsistentError(
            RpcError::ProviderError(ProviderError::MissingRequiredProvider)
        ))),
        MultiRpcResult::Consistent(Err(RpcError::ProviderError(
            ProviderError::MissingRequiredProvider
        )))
    );
    assert_eq!(
        multi_result(Err(MultiCallError::<()>::InconsistentResults(
            MultiCallResults {
                results: Default::default()
            }
        ))),
        MultiRpcResult::Inconsistent(vec![])
    );
    assert_eq!(
        multi_result(Err(MultiCallError::InconsistentResults(MultiCallResults {
            results: vec![(RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5))]
                .into_iter()
                .collect(),
        }))),
        MultiRpcResult::Inconsistent(vec![(
            RpcService::EthMainnet(EthMainnetService::Ankr),
            Ok(5)
        )])
    );
    assert_eq!(
        multi_result(Err(MultiCallError::InconsistentResults(MultiCallResults {
            results: vec![
                (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
                (
                    RpcService::EthMainnet(EthMainnetService::Cloudflare),
                    Err(RpcError::ProviderError(ProviderError::NoPermission))
                )
            ]
            .into_iter()
            .collect(),
        }))),
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
            (
                RpcService::EthMainnet(EthMainnetService::Cloudflare),
                Err(RpcError::ProviderError(ProviderError::NoPermission))
            )
        ])
    );
}
