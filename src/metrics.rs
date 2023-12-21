use std::collections::HashMap;

use crate::*;

#[macro_export]
macro_rules! add_metric {
    ($metric:ident, $amount:expr) => {{
        $crate::TRANSIENT_METRICS.with(|m| m.borrow_mut().$metric += $amount);
    }};
}

#[macro_export]
macro_rules! add_metric_entry {
    ($metric:ident, $key:expr, $amount:expr) => {{
        $crate::TRANSIENT_METRICS.with(|m| {
            let amount = $amount;
            m.borrow_mut()
                .$metric
                .entry($key.into())
                .and_modify(|counter| *counter += amount)
                .or_insert(amount);
        });
    }};
}

// pub fn update_metric(action: impl FnOnce(RefMut<Metrics>)) {
//     TRANSIENT_METRICS.with(|m| action(m.borrow_mut()));
// }

// pub fn add_metric<T: AddAssign>(metric: impl FnOnce(&mut Metrics) -> &mut T, amount: T) {
//     update_metric(|m| *metric(m) += amount);
// }

// pub fn add_metric_entry<K: Clone + Eq + Hash, V: AddAssign>(
//     metric: impl FnMut(&mut Metrics) -> &mut HashMap<K, V>,
//     key: K,
//     amount: V,
// ) {
//     TRANSIENT_METRICS.with(|m| {
//         metric(m.get_mut())
//             .entry(key)
//             .and_modify(|counter| *counter += amount)
//             .or_insert(amount)
//     });
// }

trait EncoderExtensions {
    fn encode_entries<K: MetricLabels, V: MetricValue>(
        &mut self,
        map: &HashMap<K, V>,
        name: &str,
        help: &str,
    );
}

impl EncoderExtensions for ic_metrics_encoder::MetricsEncoder<Vec<u8>> {
    fn encode_entries<K: MetricLabels, V: MetricValue>(
        &mut self,
        map: &HashMap<K, V>,
        name: &str,
        help: &str,
    ) {
        map.iter().for_each(|(k, v)| {
            self.counter_vec(name, help)
                .and_then(|m| {
                    let (labels, value) = (k.metric_labels(), v.metric_value());
                    m.value(&labels, value)
                })
                .ok();
        })
    }
}

pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "canister_version",
        ic_cdk::api::canister_version() as f64,
        "Canister version",
    )?;
    w.encode_gauge(
        "stable_memory_pages",
        ic_cdk::api::stable::stable64_size() as f64,
        "Size of the stable memory allocated by this canister measured in 64-bit Wasm pages",
    )?;
    crate::TRANSIENT_METRICS.with(|m| {
        let m = m.borrow();
        w.encode_entries(&m.requests, "requests", "Number of RPC requests");
        w.encode_entries(
            &m.responses,
            "responses",
            "Number of successful RPC responses",
        );
        w.encode_entries(
            &m.json_method_requests,
            "cycles_charged",
            "Number of direct JSON-RPC requests",
        );
        w.encode_entries(
            &m.cycles_charged,
            "cycles_charged",
            "Number of cycles charged for RPC calls",
        );
        w.encode_entries(
            &m.host_requests,
            "host_requests",
            "Number of RPC requests to a service host",
        );
    });
    Ok(())
}
