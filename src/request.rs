use candid::{candid_method, CandidType, Principal};
use ic_canister_log::log;
use ic_canisters_http_types::{
    HttpRequest as AssetHttpRequest, HttpResponse as AssetHttpResponse, HttpResponseBuilder,
};
use ic_cdk::api::management_canister::http_request::{
    http_request as make_http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod,
    HttpResponse, TransformArgs, TransformContext,
};
use ic_cdk::{query, update};
use ic_nervous_system_common::{serve_logs, serve_logs_v2, serve_metrics};

use crate::*;

pub async fn do_request(
    json_rpc_payload: String,
    service_url: String,
    max_response_bytes: u64,
    provider: Option<Provider>,
) -> Result<Vec<u8>, EthRpcError> {
    inc_metric!(requests);
    if !is_authorized(Auth::Rpc) {
        inc_metric!(request_err_no_permission);
        return Err(EthRpcError::NoPermission);
    }
    let cycles_available = ic_cdk::api::call::msg_cycles_available128();
    let parsed_url = url::Url::parse(&service_url).or(Err(EthRpcError::ServiceUrlParseError))?;
    let host = parsed_url
        .host_str()
        .ok_or(EthRpcError::ServiceUrlHostMissing)?
        .to_string();
    if SERVICE_HOSTS_ALLOWLIST.with(|a| !a.borrow().contains(&host.as_str())) {
        log!(INFO, "host not allowed {}", host);
        inc_metric!(request_err_service_url_host_not_allowed);
        return Err(EthRpcError::ServiceUrlHostNotAllowed);
    }
    let provider_cost = match &provider {
        None => 0,
        Some(provider) => get_provider_cycles_cost(
            &json_rpc_payload,
            provider.cycles_per_call,
            provider.cycles_per_message_byte,
        ),
    };
    let cost = get_cycles_cost(&json_rpc_payload, &service_url, max_response_bytes) + provider_cost;
    if !is_authorized(Auth::FreeRpc) {
        if cycles_available < cost {
            return Err(EthRpcError::TooFewCycles(format!(
                "requires {cost} cycles, got {cycles_available} cycles",
            )));
        }
        ic_cdk::api::call::msg_cycles_accept128(cost);
        if let Some(mut provider) = provider {
            provider.cycles_owed += provider_cost;
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
    inc_metric_entry!(host_requests, host);
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
            "__transform_json_rpc".to_string(),
            vec![],
        )),
    };
    match make_http_request(request, cost).await {
        Ok((result,)) => Ok(result.body),
        Err((r, m)) => {
            inc_metric!(request_err_http);
            Err(EthRpcError::HttpRequestError {
                code: r as u32,
                message: m,
            })
        }
    }
}
