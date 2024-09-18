//! Numeric types for Ethereum.

#[cfg(test)]
mod tests;

use crate::rpc_client::checked_amount::CheckedAmountOf;

pub enum WeiTag {}
pub type Wei = CheckedAmountOf<WeiTag>;

pub enum WeiPerGasUnit {}
pub type WeiPerGas = CheckedAmountOf<WeiPerGasUnit>;

pub enum TransactionCountTag {}
/// Number of transactions emitted by an address at a given block height (`finalized`, `safe` or `latest`).
/// This should closely follow [`TransactionNonce`] in case the address is the same,
/// but depending on the block height the two may differ.
pub type TransactionCount = CheckedAmountOf<TransactionCountTag>;

pub enum BlockNumberTag {}
pub type BlockNumber = CheckedAmountOf<BlockNumberTag>;

pub enum GasUnit {}
/// The number of gas units attached to a transaction for execution.
pub type GasAmount = CheckedAmountOf<GasUnit>;

pub enum EthLogIndexTag {}
pub type LogIndex = CheckedAmountOf<EthLogIndexTag>;

pub enum DifficultyTag {}
pub type Difficulty = CheckedAmountOf<DifficultyTag>;

pub enum BlockNonceTag {}
pub type BlockNonce = CheckedAmountOf<BlockNonceTag>;

pub enum NumBlocksTag {}
pub type NumBlocks = CheckedAmountOf<NumBlocksTag>;

pub enum NumBytesTag {}
pub type NumBytes = CheckedAmountOf<NumBytesTag>;

pub enum TimestampTag {}
pub type Timestamp = CheckedAmountOf<TimestampTag>;
