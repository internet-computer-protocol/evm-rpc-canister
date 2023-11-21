use cketh_common::eth_rpc::{HttpOutcallError, ProviderError, RpcError, ValidationError};
use ic_canister_log::log;
use ic_cdk::api::{
    call::CallResult,
    management_canister::http_request::{
        CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformContext,
    },
};
use num_traits::ToPrimitive;

use crate::*;

pub async fn do_http_request(
    caller: Principal,
    source: ResolvedSource,
    json_rpc_payload: &str,
    max_response_bytes: u64,
) -> Result<HttpResponse, RpcError> {
    inc_metric!(requests);
    if !is_rpc_allowed(&caller) {
        inc_metric!(request_err_no_permission);
        return Err(ProviderError::NoPermission.into());
    }
    let cycles_available = ic_cdk::api::call::msg_cycles_available128();
    let cost = get_request_cost(&source, json_rpc_payload, max_response_bytes);
    let (api, provider) = match source {
        ResolvedSource::Api(api) => (api, None),
        ResolvedSource::Provider(provider) => (provider.api(), Some(provider)),
    };
    let parsed_url = match url::Url::parse(&api.url) {
        Ok(url) => url,
        Err(_) => return Err(ValidationError::UrlParseError(api.url).into()),
    };
    let host = match parsed_url.host_str() {
        Some(host) => host,
        None => return Err(ValidationError::UrlParseError(api.url).into()),
    };
    if !SERVICE_HOSTS_ALLOWLIST.contains(&host) {
        log!(INFO, "host not allowed: {}", host);
        inc_metric!(request_err_host_not_allowed);
        return Err(ValidationError::HostNotAllowed(host.to_string()).into());
    }
    if !is_authorized(&caller, Auth::FreeRpc) {
        if cycles_available < cost {
            return Err(ProviderError::TooFewCycles {
                expected: cost,
                received: cycles_available,
            }
            .into());
        }
        ic_cdk::api::call::msg_cycles_accept128(cost);
        if let Some(mut provider) = provider {
            provider.cycles_owed += get_provider_cost(&provider, json_rpc_payload);
            PROVIDERS.with(|p| {
                // Error should not happen here as it was checked before.
                p.borrow_mut()
                    .insert(provider.provider_id, provider)
                    .expect("unable to update Provider");
            });
        }
        add_metric!(request_cycles_charged, cost);
        add_metric!(request_cycles_refunded, cycles_available - cost);
    }
    inc_metric_entry!(host_requests, host.to_string());
    let mut request_headers = vec![HttpHeader {
        name: CONTENT_TYPE_HEADER.to_string(),
        value: "application/json".to_string(),
    }];
    request_headers.extend(api.headers);
    let request = CanisterHttpRequestArgument {
        url: api.url,
        max_response_bytes: Some(max_response_bytes),
        method: HttpMethod::POST,
        headers: request_headers,
        body: Some(json_rpc_payload.as_bytes().to_vec()),
        transform: Some(TransformContext::from_name(
            "__transform_evm_rpc".to_string(),
            vec![],
        )),
    };
    match perform_http_request(request, cost).await {
        Ok(response) => Ok(response),
        Err((code, message)) => {
            inc_metric!(request_err_http);
            Err(HttpOutcallError::IcError { code, message }.into())
        }
    }
}

pub fn get_http_response_status(status: candid::Nat) -> u16 {
    status.0.to_u16().unwrap_or(u16::MAX)
}

pub fn get_http_response_body(response: HttpResponse) -> Result<String, RpcError> {
    String::from_utf8(response.body).map_err(|e| {
        HttpOutcallError::InvalidHttpJsonRpcResponse {
            status: get_http_response_status(response.status),
            body: "".to_string(),
            parsing_error: Some(format!("{e}")),
        }
        .into()
    })
}

pub async fn perform_http_request(
    request: CanisterHttpRequestArgument,
    cycles: u128,
) -> CallResult<HttpResponse> {
    #[cfg(feature = "mock")]
    {
        if let Some(response) = mock_http::MOCK_OUTCALL.with(|mock| {
            let mut mock = mock.borrow_mut();
            match mock.take() {
                None => None,
                Some(m) => {
                    *mock = None;
                    Some(m.response)
                }
            }
        }) {
            return Ok(response);
        }
    }
    Ok(
        ic_cdk::api::management_canister::http_request::http_request(request, cycles)
            .await?
            .0,
    )
}

#[cfg(feature = "mock")]
pub mod mock_http {
    use std::cell::RefCell;

    use ic_cdk::api::management_canister::http_request::{HttpHeader, HttpMethod, HttpResponse};
    thread_local! {
        pub static MOCK_OUTCALL: RefCell<Option<MockOutcall>> = RefCell::new(None);
    }

    pub struct MockOutcallBody(pub Vec<u8>);

    impl From<String> for MockOutcallBody {
        fn from(string: String) -> Self {
            string.as_bytes().to_vec().into()
        }
    }
    impl<'a> From<&'a str> for MockOutcallBody {
        fn from(string: &'a str) -> Self {
            string.to_string().into()
        }
    }
    impl From<Vec<u8>> for MockOutcallBody {
        fn from(bytes: Vec<u8>) -> Self {
            MockOutcallBody(bytes)
        }
    }

    pub struct MockOutcallBuilder(MockOutcall);

    impl MockOutcallBuilder {
        pub fn new(status: u16, body: impl Into<MockOutcallBody>) -> Self {
            Self(MockOutcall {
                method: None,
                url: None,
                request_headers: None,
                request_body: None,
                response: HttpResponse {
                    status: status.into(),
                    headers: vec![],
                    body: body.into().0,
                },
            })
        }

        pub fn method(mut self, method: HttpMethod) -> Self {
            self.0.method = Some(method);
            self
        }

        pub fn url(mut self, url: impl Into<String>) -> Self {
            self.0.url = Some(url.into());
            self
        }

        pub fn request_headers(mut self, headers: Vec<HttpHeader>) -> Self {
            self.0.request_headers = Some(headers);
            self
        }

        pub fn request_body(mut self, headers: Vec<HttpHeader>) -> Self {
            self.0.request_headers = Some(headers);
            self
        }

        pub fn build(self) -> MockOutcall {
            self.0
        }
    }

    #[derive(Clone, Debug)]
    pub struct MockOutcall {
        pub method: Option<HttpMethod>,
        pub url: Option<String>,
        pub request_headers: Option<Vec<HttpHeader>>,
        pub request_body: Option<String>,
        pub response: HttpResponse,
    }

    impl MockOutcall {
        pub fn mock_once(self) {
            mock_http_request(self)
        }
    }

    impl From<HttpResponse> for MockOutcall {
        fn from(response: HttpResponse) -> Self {
            Self {
                method: None,
                url: None,
                request_headers: None,
                request_body: None,
                response,
            }
        }
    }

    pub fn assert_no_mock_http_request() {
        assert!(
            MOCK_OUTCALL.with(|mock| mock.borrow().is_none()),
            "Previous mock HTTPS outcall was not used"
        )
    }

    fn mock_http_request(mock: MockOutcall) {
        assert_no_mock_http_request();
        MOCK_OUTCALL.with(|current_mock| {
            let mut current_mock = current_mock.borrow_mut();
            *current_mock = Some(mock)
        })
    }
}
