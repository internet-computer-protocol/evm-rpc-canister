use candid::Principal;
use cketh_common::eth_rpc::{HttpOutcallError, ProviderError, RpcError, ValidationError};
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext,
};
use num_traits::ToPrimitive;

use crate::{
    accounting::{get_cost_with_collateral, get_rpc_cost},
    add_metric, add_metric_entry,
    auth::is_rpc_allowed,
    constants::{CONTENT_TYPE_HEADER, CONTENT_TYPE_VALUE, SERVICE_HOSTS_BLOCKLIST},
    memory::PROVIDERS,
    types::{MetricRpcHost, MetricRpcMethod, ResolvedRpcService, RpcResult},
    util::canonicalize_json,
};

pub async fn json_rpc_request(
    caller: Principal,
    service: ResolvedRpcService,
    rpc_method: MetricRpcMethod,
    json_rpc_payload: &str,
    max_response_bytes: u64,
) -> RpcResult<HttpResponse> {
    if !is_rpc_allowed(&caller) {
        add_metric!(err_no_permission, 1);
        return Err(ProviderError::NoPermission.into());
    }
    let cycles_cost = get_rpc_cost(&service, json_rpc_payload.len() as u64, max_response_bytes);
    let api = service.api();
    let mut request_headers = vec![HttpHeader {
        name: CONTENT_TYPE_HEADER.to_string(),
        value: CONTENT_TYPE_VALUE.to_string(),
    }];
    if let Some(headers) = api.headers {
        request_headers.extend(headers);
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
    http_request(caller, rpc_method, service, request, cycles_cost).await
}

pub async fn http_request(
    _caller: Principal,
    rpc_method: MetricRpcMethod,
    service: ResolvedRpcService,
    request: CanisterHttpRequestArgument,
    cycles_cost: u128,
) -> RpcResult<HttpResponse> {
    let api = service.api();
    let provider = match service {
        ResolvedRpcService::Api(_) => None,
        ResolvedRpcService::Provider(provider) => Some(provider),
    };
    let parsed_url = match url::Url::parse(&api.url) {
        Ok(url) => url,
        Err(_) => return Err(ValidationError::UrlParseError(api.url).into()),
    };
    let host = match parsed_url.host_str() {
        Some(host) => host,
        None => return Err(ValidationError::UrlParseError(api.url).into()),
    };
    let rpc_host = MetricRpcHost(host.to_string());
    if SERVICE_HOSTS_BLOCKLIST.contains(&rpc_host.0.as_str()) {
        add_metric_entry!(err_host_not_allowed, rpc_host.clone(), 1);
        return Err(ValidationError::HostNotAllowed(rpc_host.0).into());
    }
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
    if let Some(provider) = provider {
        PROVIDERS.with_borrow_mut(|providers| {
            // Error should not happen here as it was checked before
            providers
                .insert(provider.provider_id.clone(), provider)
                .expect("unable to update Provider");
        });
    }
    add_metric_entry!(
        cycles_charged,
        (rpc_method.clone(), rpc_host.clone()),
        cycles_cost
    );
    add_metric_entry!(requests, (rpc_method.clone(), rpc_host.clone()), 1);
    match ic_cdk::api::management_canister::http_request::http_request(request, cycles_cost).await {
        Ok((response,)) => {
            let status: u32 = response.status.0.clone().try_into().unwrap_or(0);
            add_metric_entry!(responses, (rpc_method, rpc_host, status.into()), 1);
            Ok(response)
        }
        Err((code, message)) => {
            add_metric_entry!(err_http_outcall, (rpc_method, rpc_host), 1);
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
