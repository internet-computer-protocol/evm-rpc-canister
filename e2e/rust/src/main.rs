use candid::candid_method;
use ic_cdk_macros::update;

use e2e::declarations::ic_eth::{ic_eth, EthRpcError, Source};

fn main() {}

#[update]
#[candid_method(update)]
pub async fn test() {
    // Define request parameters
    let params = (
        &Source::Chain(1 /* Ethereum */),
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":null,\"id\":1}".to_string(),
        1000 as u64,
    );

    // Get cycles cost
    let (cycles_result,): (Result<u128, EthRpcError>,) =
        ic_cdk::call(ic_eth.0, "request_cost", params.clone())
            .await
            .unwrap();
    let cycles =
        cycles_result.unwrap_or_else(|e| ic_cdk::trap(&format!("error in `request_cost`: {}", e)));

    // Call without sending cycles
    let (result_without_cycles,): (Result<String, EthRpcError>,) =
        ic_cdk::api::call::call(ic_eth.0, "request", params.clone())
            .await
            .unwrap();
    match result_without_cycles {
        Ok(s) => ic_cdk::trap(&format!("response from `request` without cycles: {:?}", s)),
        Err(EthRpcError::TooFewCycles { expected, .. }) => {
            assert_eq!(expected, cycles)
        }
        Err(err) => ic_cdk::trap(&format!("error in `request` without cycles: {}", err)),
    }

    // Call with expected number of cycles
    let (result,): (Result<String, EthRpcError>,) =
        ic_cdk::api::call::call_with_payment128(ic_eth.0, "request", params, cycles)
            .await
            .unwrap();
    match result {
        Ok(response) => assert_eq!(
            response,
            "{\"jsonrpc\":\"2.0\",\"result\":\"0x247a3fa65\",\"id\":1}",
        ),
        Err(err) => ic_cdk::trap(&format!("error in `request` with cycles: {}", err)),
    }
}
