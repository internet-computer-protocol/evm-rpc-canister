use std::str::FromStr;

use async_trait::async_trait;
use cketh_common::{
    eth_rpc::{
        into_nat, Block, FeeHistory, GetLogsParam, Hash, LogEntry, ProviderError, RpcError,
        SendRawTransactionResult, ValidationError,
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
    fn resolve_api(service: &RpcService) -> Result<RpcApi, ProviderError> {
        Ok(resolve_provider(service)?.api())
    }

    async fn http_request(
        service: &RpcService,
        method: &str,
        request: CanisterHttpRequestArgument,
        effective_response_size_estimate: u64,
    ) -> RpcResult<HttpResponse> {
        let provider = resolve_provider(service)?;
        let cycles_cost = get_candid_rpc_cost(
            &provider,
            request
                .body
                .as_ref()
                .map(|bytes| bytes.len() as u64)
                .unwrap_or_default(),
            effective_response_size_estimate,
        );
        let rpc_method = MetricRpcMethod(method.to_string());
        let rpc_host = MetricRpcHost(provider.hostname.to_string());
        do_http_request_with_metrics(
            ic_cdk::caller(),
            rpc_method,
            rpc_host,
            Some(provider),
            request,
            cycles_cost,
        )
        .await
    }
}

fn resolve_provider(service: &RpcService) -> Result<Provider, ProviderError> {
    use RpcService::*;
    let (chain_id, hostname) = match service {
        EthMainnet(service) => (
            ETH_MAINNET_CHAIN_ID,
            match service {
                EthMainnetService::Alchemy => ALCHEMY_ETH_MAINNET_HOSTNAME,
                EthMainnetService::Ankr => ANKR_HOSTNAME,
                EthMainnetService::BlockPi => BLOCKPI_ETH_MAINNET_HOSTNAME,
                EthMainnetService::PublicNode => PUBLICNODE_ETH_MAINNET_HOSTNAME,
                EthMainnetService::Cloudflare => CLOUDFLARE_HOSTNAME,
            },
        ),
        EthSepolia(service) => (
            ETH_SEPOLIA_CHAIN_ID,
            match service {
                EthSepoliaService::Alchemy => ALCHEMY_ETH_SEPOLIA_HOSTNAME,
                EthSepoliaService::Ankr => ANKR_HOSTNAME,
                EthSepoliaService::BlockPi => BLOCKPI_ETH_SEPOLIA_HOSTNAME,
                EthSepoliaService::PublicNode => PUBLICNODE_ETH_SEPOLIA_HOSTNAME,
            },
        ),
    };
    find_provider(|p| p.chain_id == chain_id && p.hostname == hostname)
        .ok_or(ProviderError::MissingRequiredProvider)
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
        add_metric!(err_no_permission, 1);
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

fn process_result<T>(method: RpcMethod, result: Result<T, MultiCallError<T>>) -> MultiRpcResult<T> {
    match result {
        Ok(value) => MultiRpcResult::Consistent(Ok(value)),
        Err(err) => match err {
            MultiCallError::ConsistentError(err) => MultiRpcResult::Consistent(Err(err)),
            MultiCallError::InconsistentResults(multi_call_results) => {
                multi_call_results.results.iter().for_each(|(service, _)| {
                    match resolve_provider(service) {
                        Ok(provider) => add_metric_entry!(
                            inconsistent_responses,
                            (method.into(), MetricRpcHost(provider.hostname)),
                            1
                        ),
                        Err(_) => {}
                    }
                });
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
        process_result(RpcMethod::EthGetLogs, self.client.eth_get_logs(args).await)
    }

    pub async fn eth_get_block_by_number(
        &self,
        block: candid_types::BlockTag,
    ) -> MultiRpcResult<Block> {
        process_result(
            RpcMethod::EthGetBlockByNumber,
            self.client.eth_get_block_by_number(block.into()).await,
        )
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        hash: String,
    ) -> MultiRpcResult<Option<candid_types::TransactionReceipt>> {
        match Hash::from_str(&hash) {
            Ok(hash) => process_result(
                RpcMethod::EthGetTransactionReceipt,
                self.client.eth_get_transaction_receipt(hash).await,
            )
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
        process_result(
            RpcMethod::EthGetTransactionCount,
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
        process_result(
            RpcMethod::EthFeeHistory,
            self.client.eth_fee_history(args.into()).await,
        )
        .map(|history| history.into())
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: String,
    ) -> MultiRpcResult<SendRawTransactionResult> {
        process_result(
            RpcMethod::EthSendRawTransaction,
            self.client
                .multi_eth_send_raw_transaction(raw_signed_transaction_hex)
                .await,
        )
    }
}

#[test]
fn test_process_result_mapping() {
    use cketh_common::eth_rpc_client::MultiCallResults;

    let method = RpcMethod::EthGetTransactionCount;

    assert_eq!(
        process_result(method, Ok(5)),
        MultiRpcResult::Consistent(Ok(5))
    );
    assert_eq!(
        process_result(
            method,
            Err(MultiCallError::<()>::ConsistentError(
                RpcError::ProviderError(ProviderError::MissingRequiredProvider)
            ))
        ),
        MultiRpcResult::Consistent(Err(RpcError::ProviderError(
            ProviderError::MissingRequiredProvider
        )))
    );
    assert_eq!(
        process_result(
            method,
            Err(MultiCallError::<()>::InconsistentResults(
                MultiCallResults {
                    results: Default::default()
                }
            ))
        ),
        MultiRpcResult::Inconsistent(vec![])
    );
    assert_eq!(
        process_result(
            method,
            Err(MultiCallError::InconsistentResults(MultiCallResults {
                results: vec![(RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5))]
                    .into_iter()
                    .collect(),
            }))
        ),
        MultiRpcResult::Inconsistent(vec![(
            RpcService::EthMainnet(EthMainnetService::Ankr),
            Ok(5)
        )])
    );
    assert_eq!(
        process_result(
            method,
            Err(MultiCallError::InconsistentResults(MultiCallResults {
                results: vec![
                    (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
                    (
                        RpcService::EthMainnet(EthMainnetService::Cloudflare),
                        Err(RpcError::ProviderError(ProviderError::NoPermission))
                    )
                ]
                .into_iter()
                .collect(),
            }))
        ),
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
            (
                RpcService::EthMainnet(EthMainnetService::Cloudflare),
                Err(RpcError::ProviderError(ProviderError::NoPermission))
            )
        ])
    );
}
