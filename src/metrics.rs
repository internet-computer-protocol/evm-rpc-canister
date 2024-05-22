use std::collections::HashMap;

use crate::types::{MetricLabels, MetricValue};

#[macro_export]
macro_rules! add_metric {
    ($metric:ident, $amount:expr) => {{
        $crate::memory::UNSTABLE_METRICS.with(|m| m.borrow_mut().$metric += $amount);
    }};
}

#[macro_export]
macro_rules! add_metric_entry {
    ($metric:ident, $key:expr, $amount:expr) => {{
        $crate::memory::UNSTABLE_METRICS.with(|m| {
            let amount = $amount;
            if amount != 0 {
                m.borrow_mut()
                    .$metric
                    .entry($key)
                    .and_modify(|counter| *counter += amount)
                    .or_insert(amount);
            }
        });
    }};
}

trait EncoderExtensions {
    fn counter_entries<K: MetricLabels, V: MetricValue>(
        &mut self,
        name: &str,
        map: &HashMap<K, V>,
        help: &str,
    );
}

impl EncoderExtensions for ic_metrics_encoder::MetricsEncoder<Vec<u8>> {
    fn counter_entries<K: MetricLabels, V: MetricValue>(
        &mut self,
        name: &str,
        map: &HashMap<K, V>,
        help: &str,
    ) {
        map.iter().for_each(|(k, v)| {
            self.counter_vec(name, help)
                .and_then(|m| {
                    m.value(&k.metric_labels(), v.metric_value())?;
                    Ok(())
                })
                .unwrap_or(());
        })
    }
}

pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    crate::memory::UNSTABLE_METRICS.with(|m| {
        let m = m.borrow();

        w.gauge_vec("cycle_balance", "Cycle balance of this canister")?
            .value(
                &[("canister", "evmrpc")],
                ic_cdk::api::canister_balance128().metric_value(),
            )?;
        w.encode_gauge(
            "evmrpc_canister_version",
            ic_cdk::api::canister_version().metric_value(),
            "Canister version",
        )?;
        w.encode_gauge(
            "evmrpc_stable_memory_pages",
            ic_cdk::api::stable::stable64_size().metric_value(),
            "Size of the stable memory allocated by this canister measured in 64-bit Wasm pages",
        )?;
        w.counter_entries(
            "evmrpc_cycles_charged",
            &m.cycles_charged,
            "Number of cycles charged for RPC calls",
        );
        w.encode_counter(
            "evmrpc_cycles_withdrawn",
            m.cycles_withdrawn.metric_value(),
            "Number of accumulated cycles withdrawn by RPC providers",
        )?;
        w.counter_entries(
            "evmrpc_requests",
            &m.requests,
            "Number of JSON-RPC requests",
        );
        w.counter_entries(
            "evmrpc_responses",
            &m.responses,
            "Number of JSON-RPC responses",
        );
        w.counter_entries(
            "evmrpc_inconsistent_responses",
            &m.inconsistent_responses,
            "Number of inconsistent RPC responses",
        );
        w.counter_entries(
            "evmrpc_err_http_outcall",
            &m.err_http_outcall,
            "Number of unsuccessful HTTP outcalls",
        );
        w.counter_entries(
            "evmrpc_err_host_not_allowed",
            &m.err_host_not_allowed,
            "Number of HostNotAllowed errors",
        );
        w.encode_counter(
            "evmrpc_err_no_permission",
            m.err_no_permission.metric_value(),
            "Number of NoPermission errors",
        )?;

        Ok(())
    })
}
