use std::str::FromStr;

use async_trait::async_trait;
use cketh_common::{
    eth_rpc::{
        into_nat, Block, FeeHistory, GetLogsParam, Hash, LogEntry, ProviderError, RpcError,
        SendRawTransactionResult, ValidationError,
    },
    eth_rpc_client::{
        providers::{RpcApi, RpcService},
        requests::GetTransactionCountParams,
        EthRpcClient as CkEthRpcClient, MultiCallError, RpcConfig, RpcTransport,
    },
    lifecycle::EthereumNetwork,
};
use ic_cdk::api::management_canister::http_request::{CanisterHttpRequestArgument, HttpResponse};

use crate::*;

use self::candid_types::BlockTag;

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
    ) -> RpcResult<HttpResponse> {
        let service = resolve_rpc_service(service.clone())?;
        let cycles_cost = get_rpc_cost(
            &service,
            request
                .body
                .as_ref()
                .map(|bytes| bytes.len() as u64)
                .unwrap_or_default(),
            effective_response_size_estimate,
        );
        let rpc_method = MetricRpcMethod(method.to_string());
        do_http_request(ic_cdk::caller(), rpc_method, service, request, cycles_cost).await
    }
}

fn check_services<T>(services: Vec<T>) -> RpcResult<Vec<T>> {
    if services.is_empty() {
        Err(ProviderError::ProviderNotFound)?;
    }
    Ok(services)
}

fn get_rpc_client(
    source: RpcServices,
    config: RpcConfig,
) -> RpcResult<CkEthRpcClient<CanisterTransport>> {
    if !is_rpc_allowed(&ic_cdk::caller()) {
        add_metric!(err_no_permission, 1);
        return Err(ProviderError::NoPermission.into());
    }
    Ok(match source {
        RpcServices::EthMainnet(services) => CkEthRpcClient::new(
            EthereumNetwork::MAINNET,
            Some(
                check_services(services.unwrap_or_else(|| DEFAULT_ETH_MAINNET_SERVICES.to_vec()))?
                    .into_iter()
                    .map(RpcService::EthMainnet)
                    .collect(),
            ),
            config,
        ),
        RpcServices::EthSepolia(services) => CkEthRpcClient::new(
            EthereumNetwork::SEPOLIA,
            Some(
                check_services(services.unwrap_or_else(|| DEFAULT_ETH_SEPOLIA_SERVICES.to_vec()))?
                    .into_iter()
                    .map(RpcService::EthSepolia)
                    .collect(),
            ),
            config,
        ),
        RpcServices::Custom { chain_id, services } => CkEthRpcClient::new(
            EthereumNetwork(chain_id),
            Some(
                check_services(services)?
                    .into_iter()
                    .map(RpcService::Custom)
                    .collect(),
            ),
            config,
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
                    if let Ok(ResolvedRpcService::Provider(provider)) =
                        resolve_rpc_service(service.clone())
                    {
                        add_metric_entry!(
                            inconsistent_responses,
                            (method.into(), MetricRpcHost(provider.hostname)),
                            1
                        )
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
    pub fn new(source: RpcServices, config: Option<RpcConfig>) -> RpcResult<Self> {
        Ok(Self {
            client: get_rpc_client(source, config.unwrap_or_default())?,
        })
    }

    pub async fn eth_get_logs(
        &self,
        args: candid_types::GetLogsArgs,
    ) -> MultiRpcResult<Vec<LogEntry>> {
        if let (Some(BlockTag::Number(from)), Some(BlockTag::Number(to))) =
            (&args.from_block, &args.to_block)
        {
            let (from, to) = (candid::Nat::from(*from), candid::Nat::from(*to));
            let block_count = if to > from { to - from } else { from - to };
            if block_count > ETH_GET_LOGS_MAX_BLOCKS {
                return MultiRpcResult::Consistent(Err(ValidationError::Custom(format!(
                    "Requested {} blocks; limited to {} when specifying a start and end block",
                    block_count, ETH_GET_LOGS_MAX_BLOCKS
                ))
                .into()));
            }
        }
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
    use cketh_common::eth_rpc_client::{providers::EthMainnetService, MultiCallResults};

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
