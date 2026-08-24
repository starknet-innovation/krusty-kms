//! Resource budgets for untrusted Starknet event pagination.

use super::{StarknetRsFelt, TongoEventReader};
use krusty_kms_common::{KmsError, Result};
use starknet_rust::core::types::{AddressFilter, BlockId, BlockTag, EmittedEvent, EventFilter};
use starknet_rust::providers::Provider;
use std::collections::HashSet;

pub(super) const EVENT_PAGE_SIZE: u64 = 100;
const MAX_EVENT_PAGES: usize = 1_000;
const MAX_EVENTS_PER_QUERY: usize = 100_000;

#[derive(Default)]
pub(super) struct EventPaginationBudget {
    pages: usize,
    events: usize,
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
        event_count: usize,
        next_token: Option<String>,
    ) -> Result<Option<String>> {
        let total = self
            .events
            .checked_add(event_count)
            .ok_or_else(|| KmsError::RpcError("event pagination count overflowed".to_string()))?;
        if total > MAX_EVENTS_PER_QUERY {
            return Err(KmsError::RpcError(format!(
                "event query exceeded the {MAX_EVENTS_PER_QUERY} event limit"
            )));
        }
        self.events = total;

        if let Some(token) = next_token {
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

        loop {
            budget.start_page()?;
            let page = self
                .provider
                .get_events(filter.clone(), continuation_token, EVENT_PAGE_SIZE)
                .await
                .map_err(|error| KmsError::RpcError(error.to_string()))?;

            let next_token = budget.accept_page(page.events.len(), page.continuation_token)?;
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
            budget.accept_page(1, Some("repeat".to_string())).unwrap(),
            Some("repeat".to_string())
        );
        budget.start_page().unwrap();
        assert!(budget.accept_page(1, Some("repeat".to_string())).is_err());
    }

    #[test]
    fn enforces_page_and_event_limits() {
        let mut page_budget = EventPaginationBudget {
            pages: MAX_EVENT_PAGES,
            ..EventPaginationBudget::default()
        };
        assert!(page_budget.start_page().is_err());

        let mut event_budget = EventPaginationBudget::default();
        assert!(event_budget
            .accept_page(MAX_EVENTS_PER_QUERY + 1, None)
            .is_err());
    }
}
