//! TONGO event reader — fetches and parses on-chain events.

use crate::abi::tongo_events;
use crate::types::{AEBalance, CipherBalance};
use krusty_kms_common::{KmsError, Result};
use starknet_rust::core::types::{BlockId, BlockTag, EmittedEvent, EventFilter};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt as CoreFelt;
use std::sync::Arc;

type StarknetRsFelt = starknet_rust::core::types::Felt;

fn rs_felt_to_core(felt: StarknetRsFelt) -> CoreFelt {
    CoreFelt::from_bytes_be(&felt.to_bytes_be())
}

fn core_felt_to_rs(felt: CoreFelt) -> StarknetRsFelt {
    StarknetRsFelt::from_bytes_be(&felt.to_bytes_be())
}

// ── Event metadata ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EventMetadata {
    pub block_number: Option<u64>,
    pub tx_hash: StarknetRsFelt,
}

fn meta(e: &EmittedEvent) -> EventMetadata {
    EventMetadata {
        block_number: e.block_number,
        tx_hash: e.transaction_hash,
    }
}

// ── Typed events ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FundEvent {
    pub meta: EventMetadata,
    pub to: ProjectivePoint,
    pub nonce: u64,
    pub from: CoreFelt,
    pub amount: u128,
}

#[derive(Debug, Clone)]
pub struct OutsideFundEvent {
    pub meta: EventMetadata,
    pub to: ProjectivePoint,
    pub from: CoreFelt,
    pub amount: u128,
}

#[derive(Debug, Clone)]
pub struct WithdrawEvent {
    pub meta: EventMetadata,
    pub from: ProjectivePoint,
    pub nonce: u64,
    pub amount: u128,
    pub to: CoreFelt,
}

#[derive(Debug, Clone)]
pub struct RagequitEvent {
    pub meta: EventMetadata,
    pub from: ProjectivePoint,
    pub nonce: u64,
    pub amount: u128,
    pub to: CoreFelt,
}

#[derive(Debug, Clone)]
pub struct RolloverEvent {
    pub meta: EventMetadata,
    pub to: ProjectivePoint,
    pub nonce: u64,
    pub rollovered: CipherBalance,
}

#[derive(Debug, Clone)]
pub struct TransferEvent {
    pub meta: EventMetadata,
    pub to: ProjectivePoint,
    pub from: ProjectivePoint,
    pub nonce: u64,
    pub transfer_balance: CipherBalance,
    pub transfer_balance_self: CipherBalance,
    pub hint_transfer: AEBalance,
    pub hint_leftover: AEBalance,
}

#[derive(Debug, Clone)]
pub struct BalanceDeclaredEvent {
    pub meta: EventMetadata,
    pub from: ProjectivePoint,
    pub nonce: u64,
    pub auditor_pub_key: ProjectivePoint,
    pub declared_cipher_balance: CipherBalance,
    pub hint: AEBalance,
}

#[derive(Debug, Clone)]
pub struct TransferDeclaredEvent {
    pub meta: EventMetadata,
    pub from: ProjectivePoint,
    pub to: ProjectivePoint,
    pub nonce: u64,
    pub auditor_pub_key: ProjectivePoint,
    pub declared_cipher_balance: CipherBalance,
    pub hint: AEBalance,
}

// ── Unified enum ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum TongoEvent {
    Fund(FundEvent),
    OutsideFund(OutsideFundEvent),
    Withdraw(WithdrawEvent),
    Ragequit(RagequitEvent),
    Rollover(RolloverEvent),
    Transfer(TransferEvent),
    BalanceDeclared(BalanceDeclaredEvent),
    TransferDeclared(TransferDeclaredEvent),
}

impl TongoEvent {
    pub fn block_number(&self) -> Option<u64> {
        match self {
            Self::Fund(e) => e.meta.block_number,
            Self::OutsideFund(e) => e.meta.block_number,
            Self::Withdraw(e) => e.meta.block_number,
            Self::Ragequit(e) => e.meta.block_number,
            Self::Rollover(e) => e.meta.block_number,
            Self::Transfer(e) => e.meta.block_number,
            Self::BalanceDeclared(e) => e.meta.block_number,
            Self::TransferDeclared(e) => e.meta.block_number,
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn parse_point(felts: &[StarknetRsFelt], offset: usize) -> Result<ProjectivePoint> {
    if felts.len() < offset + 2 {
        return Err(KmsError::DeserializationError(
            "Not enough felts for point".to_string(),
        ));
    }
    ProjectivePoint::from_affine(
        rs_felt_to_core(felts[offset]),
        rs_felt_to_core(felts[offset + 1]),
    )
    .map_err(|_| KmsError::DeserializationError("Invalid point in event data".to_string()))
}

fn parse_cipher_balance(felts: &[StarknetRsFelt], offset: usize) -> Result<CipherBalance> {
    Ok(CipherBalance {
        l: parse_point(felts, offset)?,
        r: parse_point(felts, offset + 2)?,
    })
}

fn felt_to_u128(felt: &StarknetRsFelt) -> u128 {
    let bytes = felt.to_bytes_be();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[16..32]);
    u128::from_be_bytes(buf)
}

fn felt_to_u64(felt: &StarknetRsFelt) -> u64 {
    let bytes = felt.to_bytes_be();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[24..32]);
    u64::from_be_bytes(buf)
}

/// Parse AEBalance from event data: 6 felts (4 for u512 ciphertext + 2 for u256 nonce).
fn parse_ae_balance(felts: &[StarknetRsFelt], offset: usize) -> Result<AEBalance> {
    if felts.len() < offset + 6 {
        return Err(KmsError::DeserializationError(
            "Not enough felts for AEBalance".to_string(),
        ));
    }

    // Ciphertext: 4 felts → 64 bytes (each felt provides 16 bytes from low portion)
    let mut ciphertext = [0u8; 64];
    for i in 0..4 {
        let bytes = felts[offset + i].to_bytes_be();
        ciphertext[i * 16..(i + 1) * 16].copy_from_slice(&bytes[16..32]);
    }

    // Nonce: 2 felts → 24 bytes (12 bytes from each felt's low portion)
    let mut nonce = [0u8; 24];
    let n0 = felts[offset + 4].to_bytes_be();
    nonce[0..12].copy_from_slice(&n0[20..32]);
    let n1 = felts[offset + 5].to_bytes_be();
    nonce[12..24].copy_from_slice(&n1[20..32]);

    Ok(AEBalance { ciphertext, nonce })
}

// ── Reader ──────────────────────────────────────────────────────────────

/// Reads and parses TONGO events from Starknet.
pub struct TongoEventReader {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    contract_address: StarknetRsFelt,
}

impl TongoEventReader {
    pub fn new(provider: Arc<JsonRpcClient<HttpTransport>>, contract_address: CoreFelt) -> Self {
        Self {
            provider,
            contract_address: core_felt_to_rs(contract_address),
        }
    }

    /// Fetch raw events matching the given keys, paginating through all results.
    async fn fetch_events(
        &self,
        keys: Vec<Vec<StarknetRsFelt>>,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<EmittedEvent>> {
        let filter = EventFilter {
            from_block: from_block.map(BlockId::Number),
            to_block: to_block
                .map(BlockId::Number)
                .or(Some(BlockId::Tag(BlockTag::Latest))),
            address: Some(self.contract_address),
            keys: Some(keys),
        };

        let mut all_events = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let page = self
                .provider
                .get_events(filter.clone(), continuation_token, 100)
                .await
                .map_err(|e| KmsError::RpcError(e.to_string()))?;

            all_events.extend(page.events);

            match page.continuation_token {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }

        Ok(all_events)
    }

    // ── Per-type fetchers ───────────────────────────────────────────────

    /// Fetch fund events for a public key.
    pub async fn get_fund_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<FundEvent>> {
        let (kx, ky) = point_to_rs_felts(pub_key)?;
        let keys = vec![vec![*tongo_events::FUND_EVENT], vec![kx], vec![ky]];
        let raw = self.fetch_events(keys, from_block, to_block).await?;
        raw.iter().map(parse_fund_event).collect()
    }

    /// Fetch outside fund events for a public key.
    pub async fn get_outside_fund_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<OutsideFundEvent>> {
        let (kx, ky) = point_to_rs_felts(pub_key)?;
        let keys = vec![vec![*tongo_events::OUTSIDE_FUND_EVENT], vec![kx], vec![ky]];
        let raw = self.fetch_events(keys, from_block, to_block).await?;
        raw.iter().map(parse_outside_fund_event).collect()
    }

    /// Fetch withdraw events for a public key.
    pub async fn get_withdraw_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<WithdrawEvent>> {
        let (kx, ky) = point_to_rs_felts(pub_key)?;
        let keys = vec![vec![*tongo_events::WITHDRAW_EVENT], vec![kx], vec![ky]];
        let raw = self.fetch_events(keys, from_block, to_block).await?;
        raw.iter().map(parse_withdraw_event).collect()
    }

    /// Fetch ragequit events for a public key.
    pub async fn get_ragequit_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<RagequitEvent>> {
        let (kx, ky) = point_to_rs_felts(pub_key)?;
        let keys = vec![vec![*tongo_events::RAGEQUIT_EVENT], vec![kx], vec![ky]];
        let raw = self.fetch_events(keys, from_block, to_block).await?;
        raw.iter().map(parse_ragequit_event).collect()
    }

    /// Fetch rollover events for a public key.
    pub async fn get_rollover_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<RolloverEvent>> {
        let (kx, ky) = point_to_rs_felts(pub_key)?;
        let keys = vec![vec![*tongo_events::ROLLOVER_EVENT], vec![kx], vec![ky]];
        let raw = self.fetch_events(keys, from_block, to_block).await?;
        raw.iter().map(parse_rollover_event).collect()
    }

    /// Fetch transfer events where pub_key is the recipient.
    pub async fn get_transfer_in_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<TransferEvent>> {
        let (kx, ky) = point_to_rs_felts(pub_key)?;
        let keys = vec![vec![*tongo_events::TRANSFER_EVENT], vec![kx], vec![ky]];
        let raw = self.fetch_events(keys, from_block, to_block).await?;
        raw.iter().map(parse_transfer_event).collect()
    }

    /// Fetch transfer events where pub_key is the sender.
    pub async fn get_transfer_out_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<TransferEvent>> {
        let (kx, ky) = point_to_rs_felts(pub_key)?;
        // Sender keys are at positions 3,4 (skip to.x, to.y)
        let keys = vec![
            vec![*tongo_events::TRANSFER_EVENT],
            vec![],
            vec![],
            vec![kx],
            vec![ky],
        ];
        let raw = self.fetch_events(keys, from_block, to_block).await?;
        raw.iter().map(parse_transfer_event).collect()
    }

    /// Fetch balance declared events for a public key.
    pub async fn get_balance_declared_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<BalanceDeclaredEvent>> {
        let (kx, ky) = point_to_rs_felts(pub_key)?;
        let keys = vec![
            vec![*tongo_events::BALANCE_DECLARED_EVENT],
            vec![kx],
            vec![ky],
        ];
        let raw = self.fetch_events(keys, from_block, to_block).await?;
        raw.iter().map(parse_balance_declared_event).collect()
    }

    /// Fetch transfer declared events where pub_key is the sender.
    pub async fn get_transfer_declared_from_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<TransferDeclaredEvent>> {
        let (kx, ky) = point_to_rs_felts(pub_key)?;
        let keys = vec![
            vec![*tongo_events::TRANSFER_DECLARED_EVENT],
            vec![kx],
            vec![ky],
        ];
        let raw = self.fetch_events(keys, from_block, to_block).await?;
        raw.iter().map(parse_transfer_declared_event).collect()
    }

    /// Fetch transfer declared events where pub_key is the recipient.
    pub async fn get_transfer_declared_to_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<TransferDeclaredEvent>> {
        let (kx, ky) = point_to_rs_felts(pub_key)?;
        let keys = vec![
            vec![*tongo_events::TRANSFER_DECLARED_EVENT],
            vec![],
            vec![],
            vec![kx],
            vec![ky],
        ];
        let raw = self.fetch_events(keys, from_block, to_block).await?;
        raw.iter().map(parse_transfer_declared_event).collect()
    }

    /// Fetch all event types for a public key, sorted by block number (descending).
    pub async fn get_all_events(
        &self,
        pub_key: &ProjectivePoint,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<TongoEvent>> {
        let (
            fund,
            outside_fund,
            withdraw,
            ragequit,
            rollover,
            transfer_in,
            transfer_out,
            balance_declared,
            transfer_declared_from,
            transfer_declared_to,
        ) = tokio::join!(
            self.get_fund_events(pub_key, from_block, to_block),
            self.get_outside_fund_events(pub_key, from_block, to_block),
            self.get_withdraw_events(pub_key, from_block, to_block),
            self.get_ragequit_events(pub_key, from_block, to_block),
            self.get_rollover_events(pub_key, from_block, to_block),
            self.get_transfer_in_events(pub_key, from_block, to_block),
            self.get_transfer_out_events(pub_key, from_block, to_block),
            self.get_balance_declared_events(pub_key, from_block, to_block),
            self.get_transfer_declared_from_events(pub_key, from_block, to_block),
            self.get_transfer_declared_to_events(pub_key, from_block, to_block),
        );

        let mut all: Vec<TongoEvent> = Vec::new();

        for e in fund? {
            all.push(TongoEvent::Fund(e));
        }
        for e in outside_fund? {
            all.push(TongoEvent::OutsideFund(e));
        }
        for e in withdraw? {
            all.push(TongoEvent::Withdraw(e));
        }
        for e in ragequit? {
            all.push(TongoEvent::Ragequit(e));
        }
        for e in rollover? {
            all.push(TongoEvent::Rollover(e));
        }
        for e in transfer_in? {
            all.push(TongoEvent::Transfer(e));
        }
        for e in transfer_out? {
            all.push(TongoEvent::Transfer(e));
        }
        for e in balance_declared? {
            all.push(TongoEvent::BalanceDeclared(e));
        }
        for e in transfer_declared_from? {
            all.push(TongoEvent::TransferDeclared(e));
        }
        for e in transfer_declared_to? {
            all.push(TongoEvent::TransferDeclared(e));
        }

        // Sort by block number descending
        all.sort_by_key(|e| std::cmp::Reverse(e.block_number()));

        Ok(all)
    }
}

// ── Point conversion helper ─────────────────────────────────────────────

fn point_to_rs_felts(point: &ProjectivePoint) -> Result<(StarknetRsFelt, StarknetRsFelt)> {
    let affine = point
        .to_affine()
        .map_err(|_| KmsError::CryptoError("Invalid public key".to_string()))?;
    Ok((core_felt_to_rs(affine.x()), core_felt_to_rs(affine.y())))
}

// ── Event parsers ───────────────────────────────────────────────────────

fn parse_fund_event(e: &EmittedEvent) -> Result<FundEvent> {
    // keys: [selector, to.x, to.y]
    // data: [nonce, from, amount]
    let to = parse_point(&e.keys, 1)?;
    Ok(FundEvent {
        meta: meta(e),
        to,
        nonce: felt_to_u64(&e.data[0]),
        from: rs_felt_to_core(e.data[1]),
        amount: felt_to_u128(&e.data[2]),
    })
}

fn parse_outside_fund_event(e: &EmittedEvent) -> Result<OutsideFundEvent> {
    // keys: [selector, to.x, to.y]
    // data: [from, amount]
    let to = parse_point(&e.keys, 1)?;
    Ok(OutsideFundEvent {
        meta: meta(e),
        to,
        from: rs_felt_to_core(e.data[0]),
        amount: felt_to_u128(&e.data[1]),
    })
}

fn parse_withdraw_event(e: &EmittedEvent) -> Result<WithdrawEvent> {
    // keys: [selector, from.x, from.y]
    // data: [nonce, amount, to]
    let from = parse_point(&e.keys, 1)?;
    Ok(WithdrawEvent {
        meta: meta(e),
        from,
        nonce: felt_to_u64(&e.data[0]),
        amount: felt_to_u128(&e.data[1]),
        to: rs_felt_to_core(e.data[2]),
    })
}

fn parse_ragequit_event(e: &EmittedEvent) -> Result<RagequitEvent> {
    // keys: [selector, from.x, from.y]
    // data: [nonce, amount, to]
    let from = parse_point(&e.keys, 1)?;
    Ok(RagequitEvent {
        meta: meta(e),
        from,
        nonce: felt_to_u64(&e.data[0]),
        amount: felt_to_u128(&e.data[1]),
        to: rs_felt_to_core(e.data[2]),
    })
}

fn parse_rollover_event(e: &EmittedEvent) -> Result<RolloverEvent> {
    // keys: [selector, to.x, to.y]
    // data: [nonce, rollovered (4 felts)]
    let to = parse_point(&e.keys, 1)?;
    Ok(RolloverEvent {
        meta: meta(e),
        to,
        nonce: felt_to_u64(&e.data[0]),
        rollovered: parse_cipher_balance(&e.data, 1)?,
    })
}

fn parse_transfer_event(e: &EmittedEvent) -> Result<TransferEvent> {
    // keys: [selector, to.x, to.y, from.x, from.y]
    // data: [nonce, transfer_balance(4), transfer_balance_self(4), hint_transfer(6), hint_leftover(6)]
    let to = parse_point(&e.keys, 1)?;
    let from = parse_point(&e.keys, 3)?;
    Ok(TransferEvent {
        meta: meta(e),
        to,
        from,
        nonce: felt_to_u64(&e.data[0]),
        transfer_balance: parse_cipher_balance(&e.data, 1)?,
        transfer_balance_self: parse_cipher_balance(&e.data, 5)?,
        hint_transfer: parse_ae_balance(&e.data, 9)?,
        hint_leftover: parse_ae_balance(&e.data, 15)?,
    })
}

fn parse_balance_declared_event(e: &EmittedEvent) -> Result<BalanceDeclaredEvent> {
    // keys: [selector, from.x, from.y]
    // data: [nonce, auditor.x, auditor.y, declared(4), hint(6)]
    let from = parse_point(&e.keys, 1)?;
    Ok(BalanceDeclaredEvent {
        meta: meta(e),
        from,
        nonce: felt_to_u64(&e.data[0]),
        auditor_pub_key: parse_point(&e.data, 1)?,
        declared_cipher_balance: parse_cipher_balance(&e.data, 3)?,
        hint: parse_ae_balance(&e.data, 7)?,
    })
}

fn parse_transfer_declared_event(e: &EmittedEvent) -> Result<TransferDeclaredEvent> {
    // keys: [selector, from.x, from.y, to.x, to.y]
    // data: [nonce, auditor.x, auditor.y, declared(4), hint(6)]
    let from = parse_point(&e.keys, 1)?;
    let to = parse_point(&e.keys, 3)?;
    Ok(TransferDeclaredEvent {
        meta: meta(e),
        from,
        to,
        nonce: felt_to_u64(&e.data[0]),
        auditor_pub_key: parse_point(&e.data, 1)?,
        declared_cipher_balance: parse_cipher_balance(&e.data, 3)?,
        hint: parse_ae_balance(&e.data, 7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_felt(v: u64) -> StarknetRsFelt {
        StarknetRsFelt::from(v)
    }

    fn generator_rs() -> (StarknetRsFelt, StarknetRsFelt) {
        let g_x = StarknetRsFelt::from_hex(
            "0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
        )
        .unwrap();
        let g_y = StarknetRsFelt::from_hex(
            "0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f",
        )
        .unwrap();
        (g_x, g_y)
    }

    #[test]
    fn test_parse_fund_event() {
        let (gx, gy) = generator_rs();
        let event = EmittedEvent {
            from_address: make_felt(0x999),
            keys: vec![*tongo_events::FUND_EVENT, gx, gy],
            data: vec![make_felt(1), make_felt(0xABC), make_felt(500)],
            block_hash: None,
            block_number: Some(100),
            transaction_hash: make_felt(0xDEAD),
            event_index: 0,
            transaction_index: 0,
        };

        let parsed = parse_fund_event(&event).unwrap();
        assert_eq!(parsed.nonce, 1);
        assert_eq!(parsed.amount, 500);
        assert_eq!(parsed.meta.block_number, Some(100));
    }

    #[test]
    fn test_parse_outside_fund_event() {
        let (gx, gy) = generator_rs();
        let event = EmittedEvent {
            from_address: make_felt(0x999),
            keys: vec![*tongo_events::OUTSIDE_FUND_EVENT, gx, gy],
            data: vec![make_felt(0xABC), make_felt(1000)],
            block_hash: None,
            block_number: Some(200),
            transaction_hash: make_felt(0xBEEF),
            event_index: 0,
            transaction_index: 0,
        };

        let parsed = parse_outside_fund_event(&event).unwrap();
        assert_eq!(parsed.amount, 1000);
    }

    #[test]
    fn test_parse_withdraw_event() {
        let (gx, gy) = generator_rs();
        let event = EmittedEvent {
            from_address: make_felt(0x999),
            keys: vec![*tongo_events::WITHDRAW_EVENT, gx, gy],
            data: vec![make_felt(5), make_felt(250), make_felt(0x123)],
            block_hash: None,
            block_number: Some(300),
            transaction_hash: make_felt(0xCAFE),
            event_index: 0,
            transaction_index: 0,
        };

        let parsed = parse_withdraw_event(&event).unwrap();
        assert_eq!(parsed.nonce, 5);
        assert_eq!(parsed.amount, 250);
    }

    #[test]
    fn test_tongo_event_sorting() {
        let e1 = TongoEvent::Fund(FundEvent {
            meta: EventMetadata {
                block_number: Some(100),
                tx_hash: make_felt(1),
            },
            to: krusty_kms_crypto::StarkCurve::generator(),
            nonce: 0,
            from: CoreFelt::ZERO,
            amount: 0,
        });
        let e2 = TongoEvent::Fund(FundEvent {
            meta: EventMetadata {
                block_number: Some(200),
                tx_hash: make_felt(2),
            },
            to: krusty_kms_crypto::StarkCurve::generator(),
            nonce: 0,
            from: CoreFelt::ZERO,
            amount: 0,
        });

        let mut events = [e1, e2];
        events.sort_by_key(|e| std::cmp::Reverse(e.block_number()));
        assert_eq!(events[0].block_number(), Some(200));
        assert_eq!(events[1].block_number(), Some(100));
    }
}
