#[macro_export]
macro_rules! inc_metric {
    ($metric:ident) => {{
        METRICS.with(|m| m.borrow_mut().$metric += 1);
    }};
}

#[macro_export]
macro_rules! inc_metric_entry {
    ($metric:ident, $entry:expr) => {{
        METRICS.with(|m| {
            m.borrow_mut()
                .$metric
                .entry($entry.clone())
                .and_modify(|counter| *counter += 1)
                .or_insert(1);
        });
    }};
}

#[macro_export]
macro_rules! add_metric {
    ($metric:ident, $value:expr) => {{
        METRICS.with(|m| m.borrow_mut().$metric += $value);
    }};
}

#[macro_export]
macro_rules! get_metric {
    ($metric:ident) => {{
        METRICS.with(|m| m.borrow().$metric)
    }};
}
