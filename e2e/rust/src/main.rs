use candid::candid_method;
use ic_cdk_macros::update;

use e2e::declarations::ic_eth::{ic_eth, Result_, Source};

fn main() {}

#[update]
#[candid_method(update)]
pub async fn test() {
    // TODO: call with cycles
    let result = ic_eth
        .request(
            Source::Chain(1 /* Ethereum */),
            "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":null,\"id\":1}"
                .to_string(),
            1000,
        )
        .await
        .unwrap()
        .0;
    match result {
        Result_::Ok(response) => assert_eq!(
            response,
            "{\"jsonrpc\":\"2.0\",\"result\":\"0x247a3fa65\",\"id\":1}",
        ),
        Result_::Err(err) => ic_cdk::trap(&format!("{}", err)),
    }
}

