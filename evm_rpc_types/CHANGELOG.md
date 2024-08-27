# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- v1.0 `Nat256`: transparent wrapper around a `Nat` to guarantee that it fits in 256 bits.
- v1.0 `Hex`, `Hex20`, and `Hex32`: transparent wrapper around a Candid type `text` to represent Ethereum hex strings (prefixed by `0x`) containing an unbounded, 20 or 32 bytes, respectively.
- v1.0 Move `BlockTag` to this crate.
- v1.0 Move `FeeHistoryArgs` and `FeeHistory` to this crate.
- v1.0 Move `GetLogsArgs` and `LogEntry` to this crate.
