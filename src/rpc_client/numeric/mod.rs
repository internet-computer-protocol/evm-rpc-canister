//! Numeric types for Ethereum.

#[cfg(test)]
mod tests;

use crate::rpc_client::amount::AmountOf;

pub enum WeiTag {}
pub type Wei = AmountOf<WeiTag>;

pub enum WeiPerGasUnit {}
pub type WeiPerGas = AmountOf<WeiPerGasUnit>;

pub enum TransactionCountTag {}
/// Number of transactions emitted by an address at a given block height (`finalized`, `safe` or `latest`).
/// This should closely follow [`TransactionNonce`] in case the address is the same,
/// but depending on the block height the two may differ.
pub type TransactionCount = AmountOf<TransactionCountTag>;

pub enum BlockNumberTag {}
pub type BlockNumber = AmountOf<BlockNumberTag>;

pub enum GasUnit {}
/// The number of gas units attached to a transaction for execution.
pub type GasAmount = AmountOf<GasUnit>;

pub enum EthLogIndexTag {}
pub type LogIndex = AmountOf<EthLogIndexTag>;

pub enum DifficultyTag {}
pub type Difficulty = AmountOf<DifficultyTag>;

pub enum BlockNonceTag {}
pub type BlockNonce = AmountOf<BlockNonceTag>;

pub enum NumBlocksTag {}
pub type NumBlocks = AmountOf<NumBlocksTag>;

pub enum NumBytesTag {}
pub type NumBytes = AmountOf<NumBytesTag>;

pub enum TimestampTag {}
pub type Timestamp = AmountOf<TimestampTag>;
