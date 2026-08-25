//! Resource budgets for untrusted Starknet event pagination.

use super::{StarknetRsFelt, TongoEventReader};
use krusty_kms_common::{KmsError, Result};
use starknet_rust::core::types::{AddressFilter, BlockId, BlockTag, EmittedEvent, EventFilter};
use starknet_rust::providers::Provider;
use std::collections::HashSet;
use std::fmt::Display;
use std::future::Future;
use std::io::{self, Write};
use std::time::Duration;
use tokio::time::Instant;

pub(super) const EVENT_PAGE_SIZE: u64 = 100;
const MAX_EVENT_PAGES: usize = 1_000;
const MAX_EVENTS_PER_QUERY: usize = 100_000;
const MAX_EVENT_BYTES_PER_QUERY: usize = 32 * 1024 * 1024;
const MAX_CONTINUATION_TOKEN_BYTES: usize = 4 * 1024;
const EVENT_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(super) struct EventPaginationBudget {
    pages: usize,
    events: usize,
    event_bytes: usize,
    seen_tokens: HashSet<String>,
}

impl EventPaginationBudget {
    pub(super) fn start_page(&mut self) -> Result<()> {
        if self.pages >= MAX_EVENT_PAGES {
            return Err(KmsError::RpcError(format!(
                "event pagination exceeded the {MAX_EVENT_PAGES} page limit"
            )));
        }
        self.pages += 1;
        Ok(())
    }

    pub(super) fn accept_page(
        &mut self,
        events: &[EmittedEvent],
        next_token: Option<String>,
    ) -> Result<Option<String>> {
        let total = self
            .events
            .checked_add(events.len())
            .ok_or_else(|| KmsError::RpcError("event pagination count overflowed".to_string()))?;
        if total > MAX_EVENTS_PER_QUERY {
            return Err(KmsError::RpcError(format!(
                "event query exceeded the {MAX_EVENTS_PER_QUERY} event limit"
            )));
        }
        self.events = total;

        let page_bytes = serialized_size(events)?;
        let total_bytes = self.event_bytes.checked_add(page_bytes).ok_or_else(|| {
            KmsError::RpcError("event pagination byte count overflowed".to_string())
        })?;
        if total_bytes > MAX_EVENT_BYTES_PER_QUERY {
            return Err(KmsError::RpcError(format!(
                "event query exceeded the {MAX_EVENT_BYTES_PER_QUERY} serialized-byte limit"
            )));
        }
        self.event_bytes = total_bytes;

        if let Some(token) = next_token {
            if token.len() > MAX_CONTINUATION_TOKEN_BYTES {
                return Err(KmsError::RpcError(format!(
                    "event continuation token exceeds the {MAX_CONTINUATION_TOKEN_BYTES} byte limit"
                )));
            }
            if !self.seen_tokens.insert(token.clone()) {
                return Err(KmsError::RpcError(
                    "RPC repeated an event continuation token".to_string(),
                ));
            }
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }
}

#[derive(Default)]
struct CountingWriter(usize);

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialized event size overflowed"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_size(events: &[EmittedEvent]) -> Result<usize> {
    let mut counter = CountingWriter::default();
    serde_json::to_writer(&mut counter, events)
        .map_err(|error| KmsError::RpcError(format!("failed to size event page: {error}")))?;
    Ok(counter.0)
}

async fn await_event_page<T, E, F>(deadline: Instant, future: F) -> Result<T>
where
    E: Display,
    F: Future<Output = std::result::Result<T, E>>,
{
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(KmsError::Timeout(format!(
            "event query exceeded its {}ms deadline",
            EVENT_QUERY_TIMEOUT.as_millis()
        )));
    }
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| {
            KmsError::Timeout(format!(
                "event query exceeded its {}ms deadline",
                EVENT_QUERY_TIMEOUT.as_millis()
            ))
        })?
        .map_err(|error| KmsError::RpcError(error.to_string()))
}

impl TongoEventReader {
    /// Fetch raw events matching the given keys within fixed resource budgets.
    pub(super) async fn fetch_events(
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
            address: Some(AddressFilter::Single(self.contract_address)),
            keys: Some(keys),
        };

        let mut all_events = Vec::new();
        let mut continuation_token: Option<String> = None;
        let mut budget = EventPaginationBudget::default();
        let deadline = Instant::now() + EVENT_QUERY_TIMEOUT;

        loop {
            budget.start_page()?;
            let page = await_event_page(
                deadline,
                self.provider
                    .get_events(filter.clone(), continuation_token, EVENT_PAGE_SIZE),
            )
            .await?;

            let next_token = budget.accept_page(&page.events, page.continuation_token)?;
            all_events.extend(page.events);

            match next_token {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }

        Ok(all_events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_repeated_tokens() {
        let mut budget = EventPaginationBudget::default();
        budget.start_page().unwrap();
        assert_eq!(
            budget.accept_page(&[], Some("repeat".to_string())).unwrap(),
            Some("repeat".to_string())
        );
        budget.start_page().unwrap();
        assert!(budget.accept_page(&[], Some("repeat".to_string())).is_err());
    }

    #[test]
    fn enforces_page_and_event_limits() {
        let mut page_budget = EventPaginationBudget {
            pages: MAX_EVENT_PAGES,
            ..EventPaginationBudget::default()
        };
        assert!(page_budget.start_page().is_err());

        let mut event_budget = EventPaginationBudget {
            events: MAX_EVENTS_PER_QUERY,
            ..EventPaginationBudget::default()
        };
        assert!(event_budget.accept_page(&[test_event()], None).is_err());

        let mut byte_budget = EventPaginationBudget {
            event_bytes: MAX_EVENT_BYTES_PER_QUERY,
            ..EventPaginationBudget::default()
        };
        assert!(byte_budget.accept_page(&[], None).is_err());
    }

    #[test]
    fn rejects_oversized_continuation_tokens() {
        let mut budget = EventPaginationBudget::default();
        assert!(budget
            .accept_page(&[], Some("x".repeat(MAX_CONTINUATION_TOKEN_BYTES + 1)))
            .is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn aggregate_query_deadline_bounds_in_flight_page() {
        let deadline = Instant::now() + Duration::from_millis(20);
        let result = await_event_page(deadline, async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok::<(), &str>(())
        })
        .await;

        assert!(matches!(result, Err(KmsError::Timeout(_))));
    }

    fn test_event() -> EmittedEvent {
        EmittedEvent {
            from_address: StarknetRsFelt::ONE,
            keys: Vec::new(),
            data: Vec::new(),
            block_hash: None,
            block_number: None,
            transaction_hash: StarknetRsFelt::ONE,
            transaction_index: 0,
            event_index: 0,
        }
    }
}
