//! Bounded, TTL-pruned store for tracked operation state.

use crate::types::OperationRetentionPolicy;
use krusty_kms_domain::{OperationId, OperationState, OperationStatus};
use std::collections::HashMap;

pub(crate) struct OperationStore {
    retention: OperationRetentionPolicy,
    entries: HashMap<OperationId, OperationEntry>,
    next_revision: u64,
}

struct OperationEntry {
    status: OperationStatus,
    updated_at_ms: u64,
    revision: u64,
}

impl OperationStore {
    pub(crate) fn new(retention: OperationRetentionPolicy) -> Self {
        Self {
            retention,
            entries: HashMap::new(),
            next_revision: 1,
        }
    }

    pub(crate) fn get(&mut self, id: &OperationId, now_ms: u64) -> Option<OperationStatus> {
        self.prune(now_ms);
        self.entries.get(id).map(|entry| entry.status.clone())
    }

    pub(crate) fn insert(&mut self, status: OperationStatus, now_ms: u64) {
        let revision = self.next_revision;
        self.next_revision = self.next_revision.saturating_add(1);
        self.entries.insert(
            status.id.clone(),
            OperationEntry {
                status,
                updated_at_ms: now_ms,
                revision,
            },
        );
        self.prune(now_ms);
    }

    fn prune(&mut self, now_ms: u64) {
        let ttl_ms = self.retention.ttl_ms();
        for entry in self.entries.values_mut() {
            if matches!(entry.status.state, OperationState::Expired) {
                continue;
            }

            if now_ms.saturating_sub(entry.updated_at_ms) > ttl_ms {
                entry.status.state = OperationState::Expired;
            }
        }

        let max_entries = self.retention.max_entries();
        if self.entries.len() <= max_entries {
            return;
        }

        let mut by_age: Vec<_> = self
            .entries
            .iter()
            .map(|(id, entry)| {
                (
                    id.clone(),
                    !matches!(entry.status.state, OperationState::Expired),
                    entry.revision,
                )
            })
            .collect();
        by_age.sort_unstable_by_key(|(_, active, revision)| (*active, *revision));

        let remove_count = self.entries.len() - max_entries;
        for (id, _, _) in by_age.into_iter().take(remove_count) {
            self.entries.remove(&id);
        }
    }
}
