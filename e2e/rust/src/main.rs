use candid::candid_method;
use ic_cdk_macros::update;

mod declarations;

use declarations::EVM_RPC_STAGING::{
    BlockTag, EthMainnetService, GetBlockByNumberResult, MultiGetBlockByNumberResult,
    ProviderError, RpcError, RpcService, RpcServices, EVM_RPC_STAGING as evm_rpc,
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
    let (results,): (MultiGetBlockByNumberResult,) = ic_cdk::api::call::call_with_payment128(
        evm_rpc.0,
        "eth_getBlockByNumber",
        (
            RpcServices::EthMainnet(Some(vec![
                EthMainnetService::Ankr,
                EthMainnetService::BlockPi,
                EthMainnetService::Llama,
                EthMainnetService::PublicNode,
            ])),
            (),
            BlockTag::Number(19709434_u32.into()),
        ),
        10000000000,
    )
    .await
    .unwrap();
    match results {
        MultiGetBlockByNumberResult::Consistent(result) => match result {
            GetBlockByNumberResult::Ok(block) => {
                assert_eq!(
                    block.hash,
                    "0x114755458f57fe1a81e7b03e038ad00f9a675681c8b94cf102c30a84c5545c76"
                );
            }
            GetBlockByNumberResult::Err(err) => {
                ic_cdk::trap(&format!("error in `eth_getBlockByNumber`: {:?}", err))
            }
        },
        MultiGetBlockByNumberResult::Inconsistent(results) => ic_cdk::trap(&format!(
            "inconsistent results in `eth_getBlockByNumber`: {:?}",
            results
        )),
    }
}
