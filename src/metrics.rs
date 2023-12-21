use std::collections::HashMap;

#[macro_export]
macro_rules! add_metric {
    ($metric:ident, $amount:expr) => {{
        $crate::TRANSIENT_METRICS.with(|m| m.borrow_mut().$metric += $amount);
    }};
}

#[macro_export]
macro_rules! add_metric_entry {
    ($metric:ident, $entry:expr, $amount:expr) => {{
        $crate::TRANSIENT_METRICS.with(|m| {
            let amount = $amount;
            m.borrow_mut()
                .$metric
                .entry($entry.into())
                .and_modify(|counter| *counter += amount)
                .or_insert(amount);
        });
    }};
}

#[macro_export]
macro_rules! inc_metric {
    ($metric:ident) => {{
        add_metric!($metric, 1)
    }};
}

#[macro_export]
macro_rules! inc_metric_entry {
    ($metric:ident, $entry:expr) => {{
        add_metric_entry!($metric, $entry, 1)
    }};
}

trait EncodeExt {
    fn encode_entries<'a, K, V, F: Into<f64>>(
        &mut self,
        map: HashMap<K, V>,
        f: impl Fn(&K, &V) -> (&'a [(&'a str, &'a str)], F),
        name: &str,
        help: &str,
    );
}

impl EncodeExt for ic_metrics_encoder::MetricsEncoder<Vec<u8>> {
    fn encode_entries<'a, K, V, F: Into<f64>>(
        &mut self,
        map: HashMap<K, V>,
        f: impl Fn(&K, &V) -> (&'a [(&'a str, &'a str)], F),
        name: &str,
        help: &str,
    ) {
        map.iter()
            .map(|(k, v)| {
                self.counter_vec(
                    "json_rpc_host_requests",
                    "Number of direct JSON-RPC calls to a service host.",
                )
                .and_then(|m| {
                    let (labels, value) = f(k, v);
                    m.value(labels, value.into())
                })
                .and(Ok(()))
            })
            .find(|e| e.is_err())
            .unwrap_or(Ok(()));
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
        w.encode_entries(
            m.requests,
            |k, v| (&[("method", &k.0)], *v as f64),
            "requests",
            "Number of RPC requests",
        );
        w.encode_entries(
            m.responses,
            |k, v| (&[("method", &k.0)], *v as f64),
            "responses",
            "Number of successful RPC responses",
        );
        w.encode_entries(
            m.json_method_requests,
            |k, v| (&[("method", &k.0)], *v as f64),
            "cycles_charged",
            "Number of direct JSON-RPC requests",
        );
        w.encode_entries(
            m.cycles_charged,
            |k, v| (&[("method", &k.0)], *v as f64),
            "cycles_charged",
            "Number of cycles charged for RPC calls",
        );
        w.encode_entries(
            m.host_requests,
            |k, v| (&[("host", &k.0)], *v as f64),
            "host_requests",
            "Number of RPC requests to a service host",
        );
    });
    Ok(())
}
