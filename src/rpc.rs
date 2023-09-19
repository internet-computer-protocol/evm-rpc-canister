use serde::{Deserialize, Serialize};
use std::cell::RefCell;

fn next_id() -> u64 {
    thread_local! {
        static NEXT_ID: RefCell<u64> = RefCell::default();
    }
    NEXT_ID.with(|next_id| {
        let mut next_id = next_id.borrow_mut();
        let id = *next_id;
        *next_id = next_id.wrapping_add(1);
        id
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    id: u64,
    jsonrpc: &'static str,
    method: String,
    params: T,
}

impl<T> JsonRpcRequest<T> {
    pub fn new(method: String, params: T) -> Self {
        Self {
            id: next_id(),
            jsonrpc: "2.0",
            method,
            params,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EthCallParams {
    to: String,
    data: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    result: Option<String>,
    error: Option<JsonRpcError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonRpcError {
    code: isize,
    message: String,
}

// mod provider {
//     use async_trait::async_trait;
//     use ethers_providers::{JsonRpcClient, ProviderError};
//     use serde::{de::DeserializeOwned, Serialize};
//     use std::fmt::Debug;

//     #[derive(Debug)]
//     pub struct HttpOutcallClient<'a> {
//         pub service_url: &'a str,
//     }

//     impl<'a> HttpOutcallClient<'a> {
//         pub fn new(service_url: &'a str) -> Self {
//             Self { service_url }
//         }
//     }

//     #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
//     #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
//     impl<'a> JsonRpcClient for HttpOutcallClient<'a> {
//         type Error = ProviderError;

//         async fn request<T, R>(&self, method: &str, params: T) -> Result<R, Self::Error>
//         where
//             T: Debug + Serialize + Send + Sync,
//             R: DeserializeOwned + Send,
//         {
//             // do_http_request(
//             //     ResolvedSource::Url(self.service_url.clone()),
//             //     json_rpc_payload,
//             //     max_response_bytes,
//             // )
//             // .unwrap()
//             unimplemented!()
//         }
//     }
// }
