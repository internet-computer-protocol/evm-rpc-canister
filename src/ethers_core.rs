use ethereum_types::{Address, Signature, H256, U256, U64};
use rlp::{Decodable, DecoderError};
use serde::{Deserialize, Serialize};

// Subset of the `ethers_core` crate. This enables reproducible builds via Bazel.

/// Details of a signed transaction.
/// Adapted from https://docs.rs/ethers-core/2.0.14/src/ethers_core/types/transaction/response.rs.html#19-138
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Transaction {
    pub hash: H256,
    pub nonce: U256,
    #[serde(default, rename = "blockHash")]
    pub block_hash: Option<H256>,
    #[serde(default, rename = "blockNumber")]
    pub block_number: Option<U64>,
    #[serde(default, rename = "transactionIndex")]
    pub transaction_index: Option<U64>,
    #[serde(default = "ethereum_types::Address::zero")]
    pub from: Address,
    #[serde(default)]
    pub to: Option<Address>,
    pub value: U256,
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<U256>,
    pub gas: U256,
    pub input: Bytes,
    pub v: U64,
    pub r: U256,
    pub s: U256,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<U64>,
    #[serde(
        rename = "accessList",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub access_list: Option<AccessList>,
    #[serde(
        rename = "maxPriorityFeePerGas",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(
        rename = "maxFeePerGas",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee_per_gas: Option<U256>,
    #[serde(rename = "chainId", default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<U256>,
}

impl Transaction {
    pub fn hash(&self) -> H256 {
        keccak256(self.rlp().as_ref()).into()
    }

    pub fn rlp(&self) -> Bytes {
        let mut rlp = RlpStream::new();
        rlp.begin_unbounded_list();

        match self.transaction_type {
            // EIP-2930 (0x01)
            Some(x) if x == U64::from(0x1) => {
                rlp_opt(&mut rlp, &self.chain_id);
                rlp.append(&self.nonce);
                rlp_opt(&mut rlp, &self.gas_price);
                rlp.append(&self.gas);

                rlp_opt(&mut rlp, &self.to);
                rlp.append(&self.value);
                rlp.append(&self.input.as_ref());
                rlp_opt_list(&mut rlp, &self.access_list);
                if let Some(chain_id) = self.chain_id {
                    rlp.append(&normalize_v(self.v.as_u64(), U64::from(chain_id.as_u64())));
                }
                rlp.append(&self.r);
                rlp.append(&self.s);
            }
            // EIP-1559 (0x02)
            Some(x) if x == U64::from(0x2) => {
                rlp_opt(&mut rlp, &self.chain_id);
                rlp.append(&self.nonce);
                rlp_opt(&mut rlp, &self.max_priority_fee_per_gas);
                rlp_opt(&mut rlp, &self.max_fee_per_gas);
                rlp.append(&self.gas);
                rlp_opt(&mut rlp, &self.to);
                rlp.append(&self.value);
                rlp.append(&self.input.as_ref());
                rlp_opt_list(&mut rlp, &self.access_list);
                if let Some(chain_id) = self.chain_id {
                    rlp.append(&normalize_v(self.v.as_u64(), U64::from(chain_id.as_u64())));
                }
                rlp.append(&self.r);
                rlp.append(&self.s);
            }
            // Legacy (0x00)
            _ => {
                rlp.append(&self.nonce);
                rlp_opt(&mut rlp, &self.gas_price);
                rlp.append(&self.gas);

                rlp_opt(&mut rlp, &self.to);
                rlp.append(&self.value);
                rlp.append(&self.input.as_ref());
                rlp.append(&self.v);
                rlp.append(&self.r);
                rlp.append(&self.s);
            }
        }

        rlp.finalize_unbounded_list();

        let rlp_bytes: Bytes = rlp.out().freeze().into();
        let mut encoded = vec![];
        match self.transaction_type {
            Some(x) if x == U64::from(0x1) => {
                encoded.extend_from_slice(&[0x1]);
                encoded.extend_from_slice(rlp_bytes.as_ref());
                encoded.into()
            }
            Some(x) if x == U64::from(0x2) => {
                encoded.extend_from_slice(&[0x2]);
                encoded.extend_from_slice(rlp_bytes.as_ref());
                encoded.into()
            }
            _ => rlp_bytes,
        }
    }

    /// Decodes fields of the type 2 transaction response starting at the RLP offset passed.
    /// Increments the offset for each element parsed.
    #[inline]
    fn decode_base_eip1559(
        &mut self,
        rlp: &rlp::Rlp,
        offset: &mut usize,
    ) -> Result<(), DecoderError> {
        self.chain_id = Some(rlp.val_at(*offset)?);
        *offset += 1;
        self.nonce = rlp.val_at(*offset)?;
        *offset += 1;
        self.max_priority_fee_per_gas = Some(rlp.val_at(*offset)?);
        *offset += 1;
        self.max_fee_per_gas = Some(rlp.val_at(*offset)?);
        *offset += 1;
        self.gas = rlp.val_at(*offset)?;
        *offset += 1;
        self.to = decode_to(rlp, offset)?;
        self.value = rlp.val_at(*offset)?;
        *offset += 1;
        let input = rlp::Rlp::new(rlp.at(*offset)?.as_raw()).data()?;
        self.input = Bytes::from(input.to_vec());
        *offset += 1;
        self.access_list = Some(rlp.val_at(*offset)?);
        *offset += 1;
        Ok(())
    }

    /// Decodes fields of the type 1 transaction response based on the RLP offset passed.
    /// Increments the offset for each element parsed.
    fn decode_base_eip2930(
        &mut self,
        rlp: &rlp::Rlp,
        offset: &mut usize,
    ) -> Result<(), DecoderError> {
        self.chain_id = Some(rlp.val_at(*offset)?);
        *offset += 1;
        self.nonce = rlp.val_at(*offset)?;
        *offset += 1;
        self.gas_price = Some(rlp.val_at(*offset)?);
        *offset += 1;
        self.gas = rlp.val_at(*offset)?;
        *offset += 1;

        self.to = decode_to(rlp, offset)?;
        self.value = rlp.val_at(*offset)?;
        *offset += 1;
        let input = rlp::Rlp::new(rlp.at(*offset)?.as_raw()).data()?;
        self.input = Bytes::from(input.to_vec());
        *offset += 1;
        self.access_list = Some(rlp.val_at(*offset)?);
        *offset += 1;

        Ok(())
    }

    /// Decodes a legacy transaction starting at the RLP offset passed.
    /// Increments the offset for each element parsed.
    #[inline]
    fn decode_base_legacy(
        &mut self,
        rlp: &rlp::Rlp,
        offset: &mut usize,
    ) -> Result<(), DecoderError> {
        self.nonce = rlp.val_at(*offset)?;
        *offset += 1;
        self.gas_price = Some(rlp.val_at(*offset)?);
        *offset += 1;
        self.gas = rlp.val_at(*offset)?;
        *offset += 1;

        self.to = decode_to(rlp, offset)?;
        self.value = rlp.val_at(*offset)?;
        *offset += 1;
        let input = rlp::Rlp::new(rlp.at(*offset)?.as_raw()).data()?;
        self.input = Bytes::from(input.to_vec());
        *offset += 1;
        Ok(())
    }

    /// Recover the sender of the tx from signature
    pub fn recover_from(&self) -> Result<Address, SignatureError> {
        let signature = Signature {
            r: self.r,
            s: self.s,
            v: self.v.as_u64(),
        };
        let typed_tx: TypedTransaction = self.into();
        signature.recover(typed_tx.sighash())
    }

    /// Recover the sender of the tx from signature and set the from field
    pub fn recover_from_mut(&mut self) -> Result<Address, SignatureError> {
        let from = self.recover_from()?;
        self.from = from;
        Ok(from)
    }
}

/// Get a Transaction directly from a rlp encoded byte stream
impl Decodable for Transaction {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, DecoderError> {
        let mut txn = Self {
            hash: H256(keccak256(rlp.as_raw())),
            ..Default::default()
        };
        // we can get the type from the first value
        let mut offset = 0;

        // only untyped legacy transactions are lists
        if rlp.is_list() {
            // Legacy (0x00)
            // use the original rlp
            txn.decode_base_legacy(rlp, &mut offset)?;
            let sig = decode_signature(rlp, &mut offset)?;
            txn.r = sig.r;
            txn.s = sig.s;
            txn.v = sig.v.into();
            // extract chain id if legacy
            txn.chain_id = extract_chain_id(sig.v).map(|id| id.as_u64().into());
        } else {
            // if it is not enveloped then we need to use rlp.as_raw instead of rlp.data
            let first_byte = *rlp
                .as_raw()
                .first()
                .ok_or(DecoderError::Custom("empty slice"))?;
            let (first, data) = if first_byte <= 0x7f {
                (first_byte, rlp.as_raw())
            } else {
                let data = rlp.data()?;
                let first = *data.first().ok_or(DecoderError::Custom("empty slice"))?;
                (first, data)
            };

            let bytes = data.get(1..).ok_or(DecoderError::Custom("no tx body"))?;
            let rest = rlp::Rlp::new(bytes);
            match first {
                0x01 => {
                    txn.decode_base_eip2930(&rest, &mut offset)?;
                    txn.transaction_type = Some(1u64.into());

                    let odd_y_parity: bool = rest.val_at(offset)?;
                    txn.v = (odd_y_parity as u8).into();
                    txn.r = rest.val_at(offset + 1)?;
                    txn.s = rest.val_at(offset + 2)?;
                }
                0x02 => {
                    txn.decode_base_eip1559(&rest, &mut offset)?;
                    txn.transaction_type = Some(2u64.into());

                    let odd_y_parity: bool = rest.val_at(offset)?;
                    txn.v = (odd_y_parity as u8).into();
                    txn.r = rest.val_at(offset + 1)?;
                    txn.s = rest.val_at(offset + 2)?;
                }
                _ => return Err(DecoderError::Custom("invalid tx type")),
            }
        }

        Ok(txn)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(not(feature = "legacy"), serde(tag = "type"))]
#[cfg_attr(feature = "legacy", serde(untagged))]
pub enum TypedTransaction {
    // 0x00
    #[serde(rename = "0x00", alias = "0x0")]
    Legacy(TransactionRequest),
    // 0x01
    #[serde(rename = "0x01", alias = "0x1")]
    Eip2930(Eip2930TransactionRequest),
    // 0x02
    #[serde(rename = "0x02", alias = "0x2")]
    Eip1559(Eip1559TransactionRequest),
    // 0x7E
    #[cfg(feature = "optimism")]
    #[serde(rename = "0x7E")]
    DepositTransaction(DepositTransaction),
}

use TypedTransaction::*;

impl TypedTransaction {
    pub fn from(&self) -> Option<&Address> {
        match self {
            Legacy(inner) => inner.from.as_ref(),
            Eip2930(inner) => inner.tx.from.as_ref(),
            Eip1559(inner) => inner.from.as_ref(),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.from.as_ref(),
        }
    }

    pub fn set_from(&mut self, from: Address) -> &mut Self {
        match self {
            Legacy(inner) => inner.from = Some(from),
            Eip2930(inner) => inner.tx.from = Some(from),
            Eip1559(inner) => inner.from = Some(from),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.from = Some(from),
        };
        self
    }

    pub fn to(&self) -> Option<&NameOrAddress> {
        match self {
            Legacy(inner) => inner.to.as_ref(),
            Eip2930(inner) => inner.tx.to.as_ref(),
            Eip1559(inner) => inner.to.as_ref(),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.to.as_ref(),
        }
    }

    pub fn to_addr(&self) -> Option<&Address> {
        self.to().and_then(|t| t.as_address())
    }

    pub fn set_to<T: Into<NameOrAddress>>(&mut self, to: T) -> &mut Self {
        let to = to.into();
        match self {
            Legacy(inner) => inner.to = Some(to),
            Eip2930(inner) => inner.tx.to = Some(to),
            Eip1559(inner) => inner.to = Some(to),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.to = Some(to),
        };
        self
    }

    pub fn nonce(&self) -> Option<&U256> {
        match self {
            Legacy(inner) => inner.nonce.as_ref(),
            Eip2930(inner) => inner.tx.nonce.as_ref(),
            Eip1559(inner) => inner.nonce.as_ref(),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.nonce.as_ref(),
        }
    }

    pub fn set_nonce<T: Into<U256>>(&mut self, nonce: T) -> &mut Self {
        let nonce = nonce.into();
        match self {
            Legacy(inner) => inner.nonce = Some(nonce),
            Eip2930(inner) => inner.tx.nonce = Some(nonce),
            Eip1559(inner) => inner.nonce = Some(nonce),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.nonce = Some(nonce),
        };
        self
    }

    pub fn value(&self) -> Option<&U256> {
        match self {
            Legacy(inner) => inner.value.as_ref(),
            Eip2930(inner) => inner.tx.value.as_ref(),
            Eip1559(inner) => inner.value.as_ref(),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.value.as_ref(),
        }
    }

    pub fn set_value<T: Into<U256>>(&mut self, value: T) -> &mut Self {
        let value = value.into();
        match self {
            Legacy(inner) => inner.value = Some(value),
            Eip2930(inner) => inner.tx.value = Some(value),
            Eip1559(inner) => inner.value = Some(value),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.value = Some(value),
        };
        self
    }

    pub fn gas(&self) -> Option<&U256> {
        match self {
            Legacy(inner) => inner.gas.as_ref(),
            Eip2930(inner) => inner.tx.gas.as_ref(),
            Eip1559(inner) => inner.gas.as_ref(),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.gas.as_ref(),
        }
    }

    pub fn gas_mut(&mut self) -> &mut Option<U256> {
        match self {
            Legacy(inner) => &mut inner.gas,
            Eip2930(inner) => &mut inner.tx.gas,
            Eip1559(inner) => &mut inner.gas,
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => &mut inner.tx.gas,
        }
    }

    pub fn set_gas<T: Into<U256>>(&mut self, gas: T) -> &mut Self {
        let gas = gas.into();
        match self {
            Legacy(inner) => inner.gas = Some(gas),
            Eip2930(inner) => inner.tx.gas = Some(gas),
            Eip1559(inner) => inner.gas = Some(gas),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.gas = Some(gas),
        };
        self
    }

    pub fn gas_price(&self) -> Option<U256> {
        match self {
            Legacy(inner) => inner.gas_price,
            Eip2930(inner) => inner.tx.gas_price,
            Eip1559(inner) => {
                match (inner.max_fee_per_gas, inner.max_priority_fee_per_gas) {
                    (Some(max_fee), Some(_)) => Some(max_fee),
                    // this also covers the None, None case
                    (None, prio_fee) => prio_fee,
                    (max_fee, None) => max_fee,
                }
            }
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.gas_price,
        }
    }

    pub fn set_gas_price<T: Into<U256>>(&mut self, gas_price: T) -> &mut Self {
        let gas_price = gas_price.into();
        match self {
            Legacy(inner) => inner.gas_price = Some(gas_price),
            Eip2930(inner) => inner.tx.gas_price = Some(gas_price),
            Eip1559(inner) => {
                inner.max_fee_per_gas = Some(gas_price);
                inner.max_priority_fee_per_gas = Some(gas_price);
            }
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.gas_price = Some(gas_price),
        };
        self
    }

    pub fn chain_id(&self) -> Option<U64> {
        match self {
            Legacy(inner) => inner.chain_id,
            Eip2930(inner) => inner.tx.chain_id,
            Eip1559(inner) => inner.chain_id,
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.chain_id,
        }
    }

    pub fn set_chain_id<T: Into<U64>>(&mut self, chain_id: T) -> &mut Self {
        let chain_id = chain_id.into();
        match self {
            Legacy(inner) => inner.chain_id = Some(chain_id),
            Eip2930(inner) => inner.tx.chain_id = Some(chain_id),
            Eip1559(inner) => inner.chain_id = Some(chain_id),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.chain_id = Some(chain_id),
        };
        self
    }

    pub fn data(&self) -> Option<&Bytes> {
        match self {
            Legacy(inner) => inner.data.as_ref(),
            Eip2930(inner) => inner.tx.data.as_ref(),
            Eip1559(inner) => inner.data.as_ref(),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.data.as_ref(),
        }
    }

    pub fn access_list(&self) -> Option<&AccessList> {
        match self {
            Legacy(_) => None,
            Eip2930(inner) => Some(&inner.access_list),
            Eip1559(inner) => Some(&inner.access_list),
            #[cfg(feature = "optimism")]
            DepositTransaction(_) => None,
        }
    }

    pub fn set_access_list(&mut self, access_list: AccessList) -> &mut Self {
        match self {
            Legacy(_) => {}
            Eip2930(inner) => inner.access_list = access_list,
            Eip1559(inner) => inner.access_list = access_list,
            #[cfg(feature = "optimism")]
            DepositTransaction(_) => {}
        };
        self
    }

    pub fn set_data(&mut self, data: Bytes) -> &mut Self {
        match self {
            Legacy(inner) => inner.data = Some(data),
            Eip2930(inner) => inner.tx.data = Some(data),
            Eip1559(inner) => inner.data = Some(data),
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => inner.tx.data = Some(data),
        };
        self
    }

    pub fn rlp_signed(&self, signature: &Signature) -> Bytes {
        let mut encoded = vec![];
        match self {
            Legacy(ref tx) => {
                encoded.extend_from_slice(tx.rlp_signed(signature).as_ref());
            }
            Eip2930(inner) => {
                encoded.extend_from_slice(&[0x1]);
                encoded.extend_from_slice(inner.rlp_signed(signature).as_ref());
            }
            Eip1559(inner) => {
                encoded.extend_from_slice(&[0x2]);
                encoded.extend_from_slice(inner.rlp_signed(signature).as_ref());
            }
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => {
                encoded.extend_from_slice(&[0x7E]);
                encoded.extend_from_slice(inner.rlp().as_ref());
            }
        };
        encoded.into()
    }

    pub fn rlp(&self) -> Bytes {
        let mut encoded = vec![];
        match self {
            Legacy(inner) => {
                encoded.extend_from_slice(inner.rlp().as_ref());
            }
            Eip2930(inner) => {
                encoded.extend_from_slice(&[0x1]);
                encoded.extend_from_slice(inner.rlp().as_ref());
            }
            Eip1559(inner) => {
                encoded.extend_from_slice(&[0x2]);
                encoded.extend_from_slice(inner.rlp().as_ref());
            }
            #[cfg(feature = "optimism")]
            DepositTransaction(inner) => {
                encoded.extend_from_slice(&[0x7E]);
                encoded.extend_from_slice(inner.rlp().as_ref());
            }
        };

        encoded.into()
    }

    /// Hashes the transaction's data. Does not double-RLP encode
    pub fn sighash(&self) -> H256 {
        let encoded = self.rlp();
        keccak256(encoded).into()
    }

    /// Max cost of the transaction
    pub fn max_cost(&self) -> Option<U256> {
        let gas_limit = self.gas();
        let gas_price = self.gas_price();
        match (gas_limit, gas_price) {
            (Some(gas_limit), Some(gas_price)) => Some(gas_limit * gas_price),
            _ => None,
        }
    }

    /// Hashes the transaction's data with the included signature.
    pub fn hash(&self, signature: &Signature) -> H256 {
        keccak256(self.rlp_signed(signature).as_ref()).into()
    }

    /// Decodes a signed TypedTransaction from a rlp encoded byte stream
    pub fn decode_signed(rlp: &rlp::Rlp) -> Result<(Self, Signature), TypedTransactionError> {
        let data = rlp.data()?;
        let first = *data
            .first()
            .ok_or(rlp::DecoderError::Custom("empty slice"))?;
        if rlp.is_list() {
            // Legacy (0x00)
            // use the original rlp
            let decoded_request = TransactionRequest::decode_signed_rlp(rlp)?;
            return Ok((Self::Legacy(decoded_request.0), decoded_request.1));
        }

        let rest = rlp::Rlp::new(
            rlp.as_raw()
                .get(1..)
                .ok_or(TypedTransactionError::MissingTransactionPayload)?,
        );

        if first == 0x01 {
            // EIP-2930 (0x01)
            let decoded_request = Eip2930TransactionRequest::decode_signed_rlp(&rest)?;
            return Ok((Self::Eip2930(decoded_request.0), decoded_request.1));
        }
        if first == 0x02 {
            // EIP-1559 (0x02)
            let decoded_request = Eip1559TransactionRequest::decode_signed_rlp(&rest)?;
            return Ok((Self::Eip1559(decoded_request.0), decoded_request.1));
        }
        #[cfg(feature = "optimism")]
        if first == 0x7E {
            // Optimism Deposited (0x7E)
            let decoded_request = DepositTransaction::decode_signed_rlp(&rest)?;
            return Ok((
                Self::DepositTransaction(decoded_request.0),
                decoded_request.1,
            ));
        }

        Err(rlp::DecoderError::Custom("invalid tx type").into())
    }
}

/// Get a TypedTransaction directly from a rlp encoded byte stream
impl Decodable for TypedTransaction {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let tx_type: Option<U64> = match rlp.is_data() {
            true => Some(rlp.data()?.into()),
            false => None,
        };
        let rest = rlp::Rlp::new(
            rlp.as_raw()
                .get(1..)
                .ok_or(rlp::DecoderError::Custom("no transaction payload"))?,
        );

        match tx_type {
            Some(x) if x == U64::from(1) => {
                // EIP-2930 (0x01)
                Ok(Self::Eip2930(Eip2930TransactionRequest::decode(&rest)?))
            }
            Some(x) if x == U64::from(2) => {
                // EIP-1559 (0x02)
                Ok(Self::Eip1559(Eip1559TransactionRequest::decode(&rest)?))
            }
            #[cfg(feature = "optimism")]
            Some(x) if x == U64::from(0x7E) => {
                // Optimism Deposited (0x7E)
                Ok(Self::DepositTransaction(DepositTransaction::decode(&rest)?))
            }
            _ => {
                // Legacy (0x00)
                // use the original rlp
                Ok(Self::Legacy(TransactionRequest::decode(rlp)?))
            }
        }
    }
}
