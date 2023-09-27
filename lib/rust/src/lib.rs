use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};

pub mod abi;
pub mod rpc;
pub mod utils;

pub use ethers_core as core;

pub use rpc::{call_contract, get_provider, request};

#[ic_cdk_macros::query(name = "__transform_eth_rpc")]
pub fn transform_eth_rpc(args: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: args.response.status.clone(),
        body: args.response.body,
        // Strip headers as they contain the Date which is not necessarily the same
        // and will prevent consensus on the result.
        headers: Vec::new(),
    }
}
