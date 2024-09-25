#[cfg(test)]
mod tests;

use candid::CandidType;
use ic_canister_log::{declare_log_buffer, export as export_logs, GlobalBuffer, Sink};
use serde::Deserialize;
use std::str::FromStr;

use crate::memory::get_log_message_filter;

// High-priority messages.
declare_log_buffer!(name = INFO_BUF, capacity = 1000);

// Low-priority info messages.
declare_log_buffer!(name = DEBUG_BUF, capacity = 1000);

// Trace of HTTP requests and responses.
declare_log_buffer!(name = TRACE_HTTP_BUF, capacity = 1000);

pub const INFO: PrintProxySink = PrintProxySink(&LogMessageType::Info, &INFO_BUF);
pub const DEBUG: PrintProxySink = PrintProxySink(&LogMessageType::Debug, &DEBUG_BUF);
pub const TRACE_HTTP: PrintProxySink = PrintProxySink(&LogMessageType::TraceHttp, &TRACE_HTTP_BUF);

#[derive(Debug)]
pub struct PrintProxySink(&'static LogMessageType, &'static GlobalBuffer);

impl Sink for PrintProxySink {
    fn append(&self, entry: ic_canister_log::LogEntry) {
        let message_type = self.0;
        if get_log_message_filter().should_print_log_message(*message_type) {
            ic_cdk::println!(
                "{} {}:{} {}",
                message_type.as_str_uppercase(),
                entry.file,
                entry.line,
                entry.message,
            )
        }
        self.1.append(entry)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, CandidType, Deserialize, serde::Serialize)]
pub enum LogMessageType {
    Info,
    TraceHttp,
    Debug,
}

impl LogMessageType {
    pub fn as_str_uppercase(self) -> &'static str {
        match self {
            LogMessageType::Info => "INFO",
            LogMessageType::TraceHttp => "TRACE_HTTP",
            LogMessageType::Debug => "DEBUG",
        }
    }
}

impl FromStr for LogMessageType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(LogMessageType::Info),
            "trace_http" => Ok(LogMessageType::TraceHttp),
            "debug" => Ok(LogMessageType::Debug),
            _ => Err("could not recognize priority".to_string()),
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, serde::Serialize)]
pub enum Sort {
    Ascending,
    Descending,
}

impl FromStr for Sort {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "asc" => Ok(Sort::Ascending),
            "desc" => Ok(Sort::Descending),
            _ => Err("could not recognize sort order".to_string()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, serde::Serialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub priority: LogMessageType,
    pub file: String,
    pub line: u32,
    pub message: String,
    pub counter: u64,
}

#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
pub struct Log {
    pub entries: Vec<LogEntry>,
}

impl Log {
    pub fn push_logs(&mut self, priority: LogMessageType) {
        let logs = match priority {
            LogMessageType::Info => export_logs(&INFO_BUF),
            LogMessageType::TraceHttp => export_logs(&TRACE_HTTP_BUF),
            LogMessageType::Debug => export_logs(&DEBUG_BUF),
        };
        for entry in logs {
            self.entries.push(LogEntry {
                timestamp: entry.timestamp,
                counter: entry.counter,
                priority,
                file: entry.file.to_string(),
                line: entry.line,
                message: entry.message,
            });
        }
    }

    pub fn push_all(&mut self) {
        self.push_logs(LogMessageType::Info);
        self.push_logs(LogMessageType::TraceHttp);
        self.push_logs(LogMessageType::Debug);
    }

    pub fn serialize_logs(&self, max_body_size: usize) -> String {
        let mut entries_json: String = serde_json::to_string(&self).unwrap_or_default();

        if entries_json.len() > max_body_size {
            let mut left = 0;
            let mut right = self.entries.len();

            while left < right {
                let mid = left + (right - left) / 2;
                let mut temp_log = self.clone();
                temp_log.entries.truncate(mid);
                let temp_entries_json = serde_json::to_string(&temp_log).unwrap_or_default();

                if temp_entries_json.len() <= max_body_size {
                    entries_json = temp_entries_json;
                    left = mid + 1;
                } else {
                    right = mid;
                }
            }
        }
        entries_json
    }

    pub fn sort_logs(&mut self, sort_order: Sort) {
        match sort_order {
            Sort::Ascending => self.sort_asc(),
            Sort::Descending => self.sort_desc(),
        }
    }

    pub fn sort_asc(&mut self) {
        self.entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    }

    pub fn sort_desc(&mut self) {
        self.entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    }
}
