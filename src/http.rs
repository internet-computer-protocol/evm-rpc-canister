use cketh_common::eth_rpc::{HttpOutcallError, ProviderError, RpcError};
use ic_canister_log::log;
use ic_cdk::api::management_canister::http_request::{
    http_request as make_http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod,
    HttpResponse, TransformContext,
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
    let (service_url, provider) = match source {
        ResolvedSource::Url(url) => (url, None),
        ResolvedSource::Provider(provider) => (provider.service_url(), Some(provider)),
    };
    let parsed_url = match url::Url::parse(&service_url) {
        Ok(url) => url,
        Err(_) => return Err(ProviderError::ServiceUrlParseError(service_url).into()),
    };
    let host = match parsed_url.host_str() {
        Some(host) => host,
        None => return Err(ProviderError::ServiceUrlParseError(service_url).into()),
    };
    if !SERVICE_HOSTS_ALLOWLIST.contains(&host) {
        log!(INFO, "host not allowed: {}", host);
        inc_metric!(request_err_host_not_allowed);
        return Err(ProviderError::ServiceHostNotAllowed(host.to_string()).into());
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
    let request_headers = vec![
        HttpHeader {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        },
        HttpHeader {
            name: "Host".to_string(),
            value: host.to_string(),
        },
    ];
    let request = CanisterHttpRequestArgument {
        url: service_url,
        max_response_bytes: Some(max_response_bytes),
        method: HttpMethod::POST,
        headers: request_headers,
        body: Some(json_rpc_payload.as_bytes().to_vec()),
        transform: Some(TransformContext::from_name(
            "__transform_eth_rpc".to_string(),
            vec![],
        )),
    };
    match make_http_request(request, cost).await {
        Ok((response,)) => Ok(response),
        Err((r, m)) => {
            inc_metric!(request_err_http);
            Err(HttpOutcallError::IcError {
                code: r,
                message: m,
            }
            .into())
        }
    }
}

pub fn get_http_response_status(status: candid::Nat) -> u16 {
    status.0.to_u16().unwrap_or(u16::MAX)
}

pub fn get_http_response_body(response: HttpResponse) -> Result<String, RpcError> {
    String::from_utf8(response.body).or_else(|e| {
        Err(HttpOutcallError::InvalidHttpJsonRpcResponse {
            status: get_http_response_status(response.status),
            body: "".to_string(),
            parsing_error: Some(format!("{e}")),
        }
        .into())
    })
}
