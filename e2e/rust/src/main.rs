use candid::candid_method;
use ic_cdk_macros::update;

use e2e::declarations::EVM_RPC_STAGING_FIDUCIARY::{
    BlockTag, EthMainnetService, GetTransactionCountArgs, GetTransactionCountResult,
    MultiGetTransactionCountResult, ProviderError, RpcError, RpcService, RpcServices,
    EVM_RPC_STAGING_FIDUCIARY as evm_rpc,
};

fn main() {}

#[update]
#[candid_method(update)]
pub async fn test() {
    assert!(ic_cdk::api::is_controller(&ic_cdk::caller()));

    // Define request parameters
    let params = (
        RpcService::EthMainnet(EthMainnetService::PublicNode), // Ethereum mainnet
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":null,\"id\":1}".to_string(),
        1000 as u64,
    );

    // Get cycles cost
    let (cycles_result,): (Result<u128, RpcError>,) =
        ic_cdk::api::call::call(evm_rpc.0, "requestCost", params.clone())
            .await
            .unwrap();
    let cycles = cycles_result
        .unwrap_or_else(|e| ic_cdk::trap(&format!("error in `request_cost`: {:?}", e)));

    // Call without sending cycles
    let (result_without_cycles,): (Result<String, RpcError>,) =
        ic_cdk::api::call::call(evm_rpc.0, "request", params.clone())
            .await
            .unwrap();
    match result_without_cycles {
        Ok(s) => ic_cdk::trap(&format!("response from `request` without cycles: {:?}", s)),
        Err(RpcError::ProviderError(ProviderError::TooFewCycles { expected, .. })) => {
            assert_eq!(expected, cycles)
        }
        Err(err) => ic_cdk::trap(&format!("error in `request` without cycles: {:?}", err)),
    }

    // Call with expected number of cycles
    let (result,): (Result<String, RpcError>,) =
        ic_cdk::api::call::call_with_payment128(evm_rpc.0, "request", params, cycles)
            .await
            .unwrap();
    match result {
        Ok(response) => {
            // Check response structure around gas price
            assert_eq!(
                &response[..36],
                "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":\"0x"
            );
            assert_eq!(&response[response.len() - 2..], "\"}");
        }
        Err(err) => ic_cdk::trap(&format!("error in `request` with cycles: {:?}", err)),
    }

    // Call a Candid-RPC method
    let (results,): (MultiGetTransactionCountResult,) = ic_cdk::api::call::call_with_payment128(
        evm_rpc.0,
        "eth_getTransactionCount",
        (
            RpcServices::EthMainnet(Some(vec![
                EthMainnetService::Ankr,
                EthMainnetService::BlockPi,
                EthMainnetService::Llama,
                EthMainnetService::PublicNode,
            ])),
            (),
            GetTransactionCountArgs {
                address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
                block: BlockTag::Latest,
            },
        ),
        10000000000,
    )
    .await
    .unwrap();
    match results {
        MultiGetTransactionCountResult::Consistent(result) => match result {
            GetTransactionCountResult::Ok(count) => {
                assert_eq!(count, 1, "Unexpected transaction count")
            }
            GetTransactionCountResult::Err(err) => {
                ic_cdk::trap(&format!("error in `eth_getTransactionCount`: {:?}", err))
            }
        },
        MultiGetTransactionCountResult::Inconsistent(results) => ic_cdk::trap(&format!(
            "inconsistent results in `eth_getTransactionCount`: {:?}",
            results
        )),
    }
}
