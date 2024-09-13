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
/// This should closely follow [`TransactionNonce`] in case the address is the minter's one,
/// but depending on the block height the two may differ.
pub type TransactionCount = CheckedAmountOf<TransactionCountTag>;

pub enum BlockNumberTag {}
pub type BlockNumber = CheckedAmountOf<BlockNumberTag>;

pub enum GasUnit {}
/// The number of gas units attached to a transaction for execution.
pub type GasAmount = CheckedAmountOf<GasUnit>;

pub enum EthLogIndexTag {}
pub type LogIndex = CheckedAmountOf<EthLogIndexTag>;

impl WeiPerGas {
    pub fn transaction_cost(self, gas: GasAmount) -> Option<Wei> {
        self.checked_mul(gas.into_inner())
            .map(|value| value.change_units())
    }
}
