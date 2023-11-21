use cketh_common::eth_rpc::{HttpOutcallError, ProviderError, RpcError, ValidationError};
use ic_canister_log::log;
use ic_cdk::api::{
    call::CallResult,
    management_canister::http_request::{
        CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
        TransformContext,
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
        let cycles_available = ic_cdk::api::call::msg_cycles_available128();
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
        value: CONTENT_TYPE_VALUE.to_string(),
    }];
    request_headers.extend(api.headers);
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
    match perform_http_request(request, cost).await {
        Ok(response) => Ok(response),
        Err((code, message)) => {
            inc_metric!(request_err_http);
            Err(HttpOutcallError::IcError { code, message }.into())
        }
    }
}

pub fn do_transform_http_request(args: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: args.response.status,
        body: canonicalize_json(&args.response.body).unwrap_or(args.response.body),
        // Strip headers as they contain the Date which is not necessarily the same
        // and will prevent consensus on the result.
        headers: Vec::<HttpHeader>::new(),
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
    #[allow(unused_variables)] cycles: u128,
) -> CallResult<HttpResponse> {
    Ok(
        ic_cdk::api::management_canister::http_request::http_request(request, cycles)
            .await?
            .0,
    )
}
