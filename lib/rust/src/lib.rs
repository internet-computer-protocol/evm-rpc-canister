use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};

pub mod abi;
pub mod rpc;
pub mod utils;

pub use ethers_core as core;

pub use rpc::{call_contract, get_provider, request};

#[ic_cdk_macros::query(name = "__ic_evm_transform_json_rpc")]
pub fn transform_json_rpc(args: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: args.response.status,
        body: args.response.body,
        headers: Vec::new(),
    }
}
