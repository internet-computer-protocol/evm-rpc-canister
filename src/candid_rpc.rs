mod cketh_conversion;

use async_trait::async_trait;
use candid::Nat;
use ethers_core::{types::Transaction, utils::rlp};
use evm_rpc_types::{
    Hex, Hex32, MultiRpcResult, ProviderError, RpcApi, RpcError, RpcResult, RpcService,
    ValidationError,
};
use ic_cdk::api::management_canister::http_request::{CanisterHttpRequestArgument, HttpResponse};

use crate::rpc_client::{EthRpcClient, MultiCallError, RpcTransport};
use crate::{
    accounting::get_http_request_cost,
    add_metric_entry,
    constants::{
        ETH_GET_LOGS_MAX_BLOCKS,
    },
    http::http_request,
    providers::resolve_rpc_service,
    types::{MetricRpcHost, MetricRpcMethod, ResolvedRpcService, RpcMethod},
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanisterTransport;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RpcTransport for CanisterTransport {
    fn resolve_api(service: &RpcService) -> Result<RpcApi, ProviderError> {
        Ok(resolve_rpc_service(service.clone())?.api())
    }

    async fn http_request(
        service: &RpcService,
        method: &str,
        request: CanisterHttpRequestArgument,
        effective_response_size_estimate: u64,
    ) -> Result<HttpResponse, RpcError> {
        let service = resolve_rpc_service(service.clone())?;
        let cycles_cost = get_http_request_cost(
            request
                .body
                .as_ref()
                .map(|bytes| bytes.len() as u64)
                .unwrap_or_default(),
            effective_response_size_estimate,
        );
        let rpc_method = MetricRpcMethod(method.to_string());
        http_request(rpc_method, service, request, cycles_cost).await
    }
}

fn check_services<T>(services: Vec<T>) -> RpcResult<Vec<T>> {
    if services.is_empty() {
        Err(ProviderError::ProviderNotFound)?;
    }
    Ok(services)
}

// fn get_rpc_client(
//     source: RpcServices,
//     config: evm_rpc_types::RpcConfig,
// ) -> RpcResult<CkEthRpcClient<CanisterTransport>> {
//     use crate::candid_rpc::cketh_conversion::{
//         into_ethereum_network, into_rpc_config, into_rpc_services,
//     };
//
//     let config = into_rpc_config(config);
//     let chain = into_ethereum_network(&source);
//     let providers = check_services(into_rpc_services(
//         source,
//         DEFAULT_ETH_MAINNET_SERVICES,
//         DEFAULT_ETH_SEPOLIA_SERVICES,
//         DEFAULT_L2_MAINNET_SERVICES,
//     ))?;
//     Ok(CkEthRpcClient::new(chain, Some(providers), config))
// }

fn process_result<T>(method: RpcMethod, result: Result<T, MultiCallError<T>>) -> MultiRpcResult<T> {
    match result {
        Ok(value) => MultiRpcResult::Consistent(Ok(value)),
        Err(err) => match err {
            MultiCallError::ConsistentError(err) => MultiRpcResult::Consistent(Err(err)),
            MultiCallError::InconsistentResults(multi_call_results) => {
                multi_call_results.results.iter().for_each(|(service, _)| {
                    if let Ok(ResolvedRpcService::Provider(provider)) =
                        resolve_rpc_service(service.clone())
                    {
                        add_metric_entry!(
                            inconsistent_responses,
                            (
                                method.into(),
                                MetricRpcHost(
                                    provider
                                        .hostname()
                                        .unwrap_or_else(|| "(unknown)".to_string())
                                )
                            ),
                            1
                        )
                    }
                });
                MultiRpcResult::Inconsistent(
                    multi_call_results
                        .results
                        .into_iter()
                        .map(|(service, result)| (service, result))
                        .collect(),
                )
            }
        },
    }
}

pub struct CandidRpcClient {
    client: EthRpcClient<CanisterTransport>,
}

impl CandidRpcClient {
    pub fn new(
        source: evm_rpc_types::RpcServices,
        config: Option<evm_rpc_types::RpcConfig>,
    ) -> RpcResult<Self> {
        Ok(Self {
            client: EthRpcClient::new(source, config.unwrap_or_default())?,
        })
    }

    pub async fn eth_get_logs(
        &self,
        args: evm_rpc_types::GetLogsArgs,
    ) -> MultiRpcResult<Vec<evm_rpc_types::LogEntry>> {
        use crate::candid_rpc::cketh_conversion::{from_log_entries, into_get_logs_param};

        if let (
            Some(evm_rpc_types::BlockTag::Number(from)),
            Some(evm_rpc_types::BlockTag::Number(to)),
        ) = (&args.from_block, &args.to_block)
        {
            let from = Nat::from(from.clone());
            let to = Nat::from(to.clone());
            let block_count = if to > from { to - from } else { from - to };
            if block_count > ETH_GET_LOGS_MAX_BLOCKS {
                return MultiRpcResult::Consistent(Err(ValidationError::Custom(format!(
                    "Requested {} blocks; limited to {} when specifying a start and end block",
                    block_count, ETH_GET_LOGS_MAX_BLOCKS
                ))
                .into()));
            }
        }
        process_result(
            RpcMethod::EthGetLogs,
            self.client.eth_get_logs(into_get_logs_param(args)).await,
        )
        .map(from_log_entries)
    }

    pub async fn eth_get_block_by_number(
        &self,
        block: evm_rpc_types::BlockTag,
    ) -> MultiRpcResult<evm_rpc_types::Block> {
        use crate::candid_rpc::cketh_conversion::{from_block, into_block_spec};
        process_result(
            RpcMethod::EthGetBlockByNumber,
            self.client
                .eth_get_block_by_number(into_block_spec(block))
                .await,
        )
        .map(from_block)
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        hash: Hex32,
    ) -> MultiRpcResult<Option<evm_rpc_types::TransactionReceipt>> {
        use crate::candid_rpc::cketh_conversion::{from_transaction_receipt, into_hash};
        process_result(
            RpcMethod::EthGetTransactionReceipt,
            self.client
                .eth_get_transaction_receipt(into_hash(hash))
                .await,
        )
        .map(|option| option.map(from_transaction_receipt))
    }

    pub async fn eth_get_transaction_count(
        &self,
        args: evm_rpc_types::GetTransactionCountArgs,
    ) -> MultiRpcResult<evm_rpc_types::Nat256> {
        use crate::candid_rpc::cketh_conversion::{
            from_checked_amount_of, into_get_transaction_count_params,
        };
        process_result(
            RpcMethod::EthGetTransactionCount,
            self.client
                .eth_get_transaction_count(into_get_transaction_count_params(args))
                .await
                .reduce_with_equality(),
        )
        .map(from_checked_amount_of)
    }

    pub async fn eth_fee_history(
        &self,
        args: evm_rpc_types::FeeHistoryArgs,
    ) -> MultiRpcResult<evm_rpc_types::FeeHistory> {
        use crate::candid_rpc::cketh_conversion::{from_fee_history, into_fee_history_params};
        process_result(
            RpcMethod::EthFeeHistory,
            self.client
                .eth_fee_history(into_fee_history_params(args))
                .await,
        )
        .map(from_fee_history)
    }

    pub async fn eth_send_raw_transaction(
        &self,
        raw_signed_transaction_hex: Hex,
    ) -> MultiRpcResult<evm_rpc_types::SendRawTransactionStatus> {
        use crate::candid_rpc::cketh_conversion::from_send_raw_transaction_result;
        let transaction_hash = get_transaction_hash(&raw_signed_transaction_hex);
        process_result(
            RpcMethod::EthSendRawTransaction,
            self.client
                .multi_eth_send_raw_transaction(raw_signed_transaction_hex.to_string())
                .await,
        )
        .map(|result| from_send_raw_transaction_result(transaction_hash.clone(), result))
    }
}

fn get_transaction_hash(raw_signed_transaction_hex: &Hex) -> Option<Hex32> {
    let transaction: Transaction = rlp::decode(raw_signed_transaction_hex.as_ref()).ok()?;
    Some(Hex32::from(transaction.hash.0))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::candid_rpc::cketh_conversion::into_rpc_service;
    use crate::rpc_client::MultiCallError;
    use evm_rpc_types::RpcError;

    #[test]
    fn test_process_result_mapping() {
        use cketh_common::eth_rpc_client::MultiCallResults;
        use evm_rpc_types::{EthMainnetService, RpcService};

        let method = RpcMethod::EthGetTransactionCount;

        assert_eq!(
            process_result(method, Ok(5)),
            MultiRpcResult::Consistent(Ok(5))
        );
        assert_eq!(
            process_result(
                method,
                Err(MultiCallError::<()>::ConsistentError(
                    cketh_common::eth_rpc::RpcError::ProviderError(
                        cketh_common::eth_rpc::ProviderError::MissingRequiredProvider
                    )
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
                    results: vec![(
                        into_rpc_service(RpcService::EthMainnet(EthMainnetService::Ankr)),
                        Ok(5)
                    )]
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
                        (
                            into_rpc_service(RpcService::EthMainnet(EthMainnetService::Ankr)),
                            Ok(5)
                        ),
                        (
                            into_rpc_service(RpcService::EthMainnet(EthMainnetService::Cloudflare)),
                            Err(cketh_common::eth_rpc::RpcError::ProviderError(
                                cketh_common::eth_rpc::ProviderError::NoPermission
                            ))
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
}
