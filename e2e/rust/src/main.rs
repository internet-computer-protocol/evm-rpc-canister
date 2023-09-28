use candid::candid_method;
use ic_cdk_macros::update;

use e2e::ic_eth;

fn main() {}

#[update]
#[candid_method(update)]
pub async fn test() {
    // TODO: call with cycles
    let result = ic_eth
        .request(
            Source::Network(1 /* Ethereum */),
            "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":null,\"id\":1}",
            1000,
        )
        .await;
    assert!(result == Ok("{\"jsonrpc\":\"2.0\",\"result\":\"0x247a3fa65\",\"id\":1}"))
}
