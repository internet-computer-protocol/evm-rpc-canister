use crate::{
    logs::{Log, LogEntry, Priority, Sort},
    memory::set_log_filter,
    types::LogFilter,
};
use ic_canister_log::{declare_log_buffer, export, log};
use proptest::{prop_assert, proptest};

use super::PrintProxySink;

declare_log_buffer!(name = INFO_TEST_BUF, capacity = 1000);
const INFO_TEST: PrintProxySink = PrintProxySink(&Priority::Info, &INFO_TEST_BUF);

fn info_log_entry_with_timestamp(timestamp: u64) -> LogEntry {
    LogEntry {
        timestamp,
        priority: Priority::Info,
        file: String::default(),
        line: 0,
        message: String::default(),
        counter: 0,
    }
}

fn is_ascending(log: &Log) -> bool {
    for i in 0..log.entries.len() - 1 {
        if log.entries[i].timestamp > log.entries[i + 1].timestamp {
            return false;
        }
    }
    true
}

fn is_descending(log: &Log) -> bool {
    for i in 0..log.entries.len() - 1 {
        if log.entries[i].timestamp < log.entries[i + 1].timestamp {
            return false;
        }
    }
    true
}

fn get_messages() -> Vec<String> {
    export(&INFO_TEST_BUF)
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

proptest! {
    #[test]
    fn logs_always_fit_in_message(
        number_of_entries in (1..100_usize),
        entry_size in (1..10000_usize),
        max_body_size in (100..10000_usize)
    ) {
        let mut entries: Vec<LogEntry> = vec![];
        for _ in 0..number_of_entries {
            entries.push(LogEntry {
                timestamp: 0,
                priority: Priority::Info,
                file: String::default(),
                line: 0,
                message: "1".repeat(entry_size),
                counter: 0,
            });
        }
        let log = Log { entries };
        let truncated_logs_json_len = log.serialize_logs(max_body_size).len();
        prop_assert!(truncated_logs_json_len <= max_body_size);
    }
}

#[test]
fn sorting_order() {
    let mut log = Log { entries: vec![] };
    log.entries.push(info_log_entry_with_timestamp(2));
    log.entries.push(info_log_entry_with_timestamp(0));
    log.entries.push(info_log_entry_with_timestamp(1));
    log.sort_asc();
    assert!(is_ascending(&log));

    log.sort_desc();
    assert!(is_descending(&log));

    log.sort_logs(Sort::Ascending);
    assert!(is_ascending(&log));

    log.sort_logs(Sort::Descending);
    assert!(is_descending(&log));
}

#[test]
fn simple_logs_truncation() {
    let mut entries: Vec<LogEntry> = vec![];
    const MAX_BODY_SIZE: usize = 3_000_000;

    for _ in 0..10 {
        entries.push(LogEntry {
            timestamp: 0,
            priority: Priority::Info,
            file: String::default(),
            line: 0,
            message: String::default(),
            counter: 0,
        });
    }
    let log = Log {
        entries: entries.clone(),
    };
    let small_len = serde_json::to_string(&log).unwrap_or_default().len();

    entries.push(LogEntry {
        timestamp: 0,
        priority: Priority::Info,
        file: String::default(),
        line: 0,
        message: "1".repeat(MAX_BODY_SIZE),
        counter: 0,
    });
    let log = Log { entries };
    let entries_json = serde_json::to_string(&log).unwrap_or_default();
    assert!(entries_json.len() > MAX_BODY_SIZE);

    let truncated_logs_json = log.serialize_logs(MAX_BODY_SIZE);

    assert_eq!(small_len, truncated_logs_json.len());
}

#[test]
fn one_entry_too_big() {
    let mut entries: Vec<LogEntry> = vec![];
    const MAX_BODY_SIZE: usize = 3_000_000;

    entries.push(LogEntry {
        timestamp: 0,
        priority: Priority::Info,
        file: String::default(),
        line: 0,
        message: "1".repeat(MAX_BODY_SIZE),
        counter: 0,
    });
    let log = Log { entries };
    let truncated_logs_json_len = log.serialize_logs(MAX_BODY_SIZE).len();
    assert!(truncated_logs_json_len < MAX_BODY_SIZE);
    assert_eq!("{\"entries\":[]}", log.serialize_logs(MAX_BODY_SIZE));
}

#[test]
fn should_truncate_last_entry() {
    let log_entries = vec![
        info_log_entry_with_timestamp(0),
        info_log_entry_with_timestamp(1),
        info_log_entry_with_timestamp(2),
    ];
    let log_with_2_entries = Log {
        entries: {
            let mut entries = log_entries.clone();
            entries.pop();
            entries
        },
    };
    let log_with_3_entries = Log {
        entries: log_entries,
    };

    let serialized_log_with_2_entries = log_with_2_entries.serialize_logs(usize::MAX);
    let serialized_log_with_3_entries =
        log_with_3_entries.serialize_logs(serialized_log_with_2_entries.len());

    assert_eq!(serialized_log_with_3_entries, serialized_log_with_2_entries);
}

#[test]
fn should_show_all() {
    set_log_filter(LogFilter::ShowAll);
    log!(INFO_TEST, "ABC");
    log!(INFO_TEST, "123");
    log!(INFO_TEST, "!@#");
    assert_eq!(get_messages(), vec!["ABC", "123", "!@#"]);
}

#[test]
fn should_hide_all() {
    set_log_filter(LogFilter::HideAll);
    log!(INFO_TEST, "ABC");
    log!(INFO_TEST, "123");
    log!(INFO_TEST, "!@#");
    assert_eq!(get_messages().len(), 0);
}

#[test]
fn should_show_pattern() {
    set_log_filter(LogFilter::ShowPattern("end$".into()));
    log!(INFO_TEST, "message");
    log!(INFO_TEST, "message end");
    log!(INFO_TEST, "end message");
    assert_eq!(get_messages(), vec!["message end"]);
}

#[test]
fn should_hide_pattern_including_message_type() {
    set_log_filter(LogFilter::ShowPattern("^INFO [^ ]* 123".into()));
    log!(INFO_TEST, "123");
    log!(INFO_TEST, "INFO 123");
    log!(INFO_TEST, "");
    log!(INFO_TEST, "123456");
    assert_eq!(get_messages(), vec!["123", "123456"]);
}

#[test]
fn should_hide_pattern() {
    set_log_filter(LogFilter::HidePattern("[ABC]".into()));
    log!(INFO_TEST, "remove A");
    log!(INFO_TEST, "...B...");
    log!(INFO_TEST, "C");
    log!(INFO_TEST, "message");
    assert_eq!(get_messages(), vec!["message"]);
}
