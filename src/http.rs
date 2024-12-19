use crate::{
    accounting::{get_cost_with_collateral, get_http_request_cost},
    add_metric_entry,
    constants::{CONTENT_TYPE_HEADER_LOWERCASE, CONTENT_TYPE_VALUE},
    memory::is_demo_active,
    types::{MetricRpcHost, MetricRpcMethod, ResolvedRpcService},
    util::canonicalize_json,
};
use evm_rpc_types::{HttpOutcallError, ProviderError, RpcError, RpcResult, ValidationError};
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext,
};
use num_traits::ToPrimitive;

pub async fn json_rpc_request(
    service: ResolvedRpcService,
    rpc_method: MetricRpcMethod,
    json_rpc_payload: &str,
    max_response_bytes: u64,
) -> RpcResult<HttpResponse> {
    let cycles_cost = get_http_request_cost(json_rpc_payload.len() as u64, max_response_bytes);
    let api = service.api();
    let mut request_headers = api.headers.unwrap_or_default();
    if !request_headers
        .iter()
        .any(|header| header.name.to_lowercase() == CONTENT_TYPE_HEADER_LOWERCASE)
    {
        request_headers.push(HttpHeader {
            name: CONTENT_TYPE_HEADER_LOWERCASE.to_string(),
            value: CONTENT_TYPE_VALUE.to_string(),
        });
    }
    let request = CanisterHttpRequestArgument {
        url: api.url,
        max_response_bytes: Some(max_response_bytes),
        method: HttpMethod::POST,
        headers: request_headers,
        body: Some(json_rpc_payload.as_bytes().to_vec()),
        transform: Some(TransformContext::from_name(
            "__transform_json_rpc".to_string(),
            vec![],
        )),
    };
    http_request(rpc_method, request, cycles_cost).await
}

pub async fn http_request(
    rpc_method: MetricRpcMethod,
    request: CanisterHttpRequestArgument,
    cycles_cost: u128,
) -> RpcResult<HttpResponse> {
    let url = request.url.clone();
    let parsed_url = match url::Url::parse(&url) {
        Ok(url) => url,
        Err(_) => {
            return Err(ValidationError::Custom(format!("Error parsing URL: {}", url)).into())
        }
    };
    let host = match parsed_url.host_str() {
        Some(host) => host,
        None => {
            return Err(ValidationError::Custom(format!(
                "Error parsing hostname from URL: {}",
                url
            ))
            .into())
        }
    };
    let rpc_host = MetricRpcHost(host.to_string());
    if !is_demo_active() {
        let cycles_available = ic_cdk::api::call::msg_cycles_available128();
        let cycles_cost_with_collateral = get_cost_with_collateral(cycles_cost);
        if cycles_available < cycles_cost_with_collateral {
            return Err(ProviderError::TooFewCycles {
                expected: cycles_cost_with_collateral,
                received: cycles_available,
            }
            .into());
        }
        ic_cdk::api::call::msg_cycles_accept128(cycles_cost);
        add_metric_entry!(
            cycles_charged,
            (rpc_method.clone(), rpc_host.clone()),
            cycles_cost
        );
    }
    add_metric_entry!(requests, (rpc_method.clone(), rpc_host.clone()), 1);
    match ic_cdk::api::management_canister::http_request::http_request(request, cycles_cost).await {
        Ok((response,)) => {
            let status: u32 = response.status.0.clone().try_into().unwrap_or(0);
            add_metric_entry!(responses, (rpc_method, rpc_host, status.into()), 1);
            Ok(response)
        }
        Err((code, message)) => {
            add_metric_entry!(err_http_outcall, (rpc_method, rpc_host, code), 1);
            Err(HttpOutcallError::IcError { code, message }.into())
        }
    }
}

pub fn transform_http_request(args: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: args.response.status,
        body: canonicalize_json(&args.response.body).unwrap_or(args.response.body),
        // Remove headers (which may contain a timestamp) for consensus
        headers: vec![],
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
