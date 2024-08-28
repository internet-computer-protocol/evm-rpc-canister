use crate::{Hex, Hex20, Hex32, Nat256};
use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, CandidType)]
pub struct FeeHistory {
    /// Lowest number block of the returned range.
    #[serde(rename = "oldestBlock")]
    pub oldest_block: Nat256,

    /// An array of block base fees per gas.
    /// This includes the next block after the newest of the returned range,
    /// because this value can be derived from the newest block.
    /// Zeroes are returned for pre-EIP-1559 blocks.
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: Vec<Nat256>,

    /// An array of block gas used ratios (gasUsed / gasLimit).
    #[serde(rename = "gasUsedRatio")]
    pub gas_used_ratio: Vec<f64>,

    /// A two-dimensional array of effective priority fees per gas at the requested block percentiles.
    #[serde(rename = "reward")]
    pub reward: Vec<Vec<Nat256>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, CandidType)]
pub struct LogEntry {
    /// The address from which this log originated.
    pub address: Hex20,

    /// Array of 0 to 4 32-byte DATA elements of indexed log arguments.
    /// In solidity: The first topic is the event signature hash (e.g. Deposit(address,bytes32,uint256)),
    /// unless you declared the event with the anonymous specifier.
    pub topics: Vec<Hex32>,

    /// Contains one or more 32-byte non-indexed log arguments.
    pub data: Hex,

    /// The block number in which this log appeared.
    /// None if the block is pending.
    #[serde(rename = "blockNumber")]
    pub block_number: Option<Nat256>,

    /// 32-byte hash of the transaction from which this log was created.
    /// None if the transaction is still pending.
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<Hex32>,

    /// Integer of the transaction's position within the block the log was created from.
    /// None if the transaction is still pending.
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Option<Nat256>,

    /// 32-byte hash of the block in which this log appeared.
    /// None if the block is pending.
    #[serde(rename = "blockHash")]
    pub block_hash: Option<Hex32>,

    /// Integer of the log index position in the block.
    /// None if the log is pending.
    #[serde(rename = "logIndex")]
    pub log_index: Option<Nat256>,

    /// "true" when the log was removed due to a chain reorganization.
    /// "false" if it is a valid log.
    #[serde(default)]
    pub removed: bool,
}
