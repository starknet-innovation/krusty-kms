//! Bounded, TTL-pruned store for tracked operation state.

use crate::types::OperationRetentionPolicy;
use krusty_kms_domain::{GatewayError, OperationId, OperationState, OperationStatus};
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

    pub(crate) fn insert(&mut self, mut status: OperationStatus, now_ms: u64) {
        if let OperationState::Rejected { error } = &mut status.state {
            // Defend the store invariant even if an error came from public
            // struct fields or deserialization instead of GatewayError::new.
            *error = GatewayError::new(error.code, error.retryable, error.message.take());
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use krusty_kms_domain::{GatewayErrorCode, OperationKind};

    #[test]
    fn rejected_operations_retain_bounded_utf8_error_text() {
        let mut store = OperationStore::new(OperationRetentionPolicy::default());
        let oversized = "🔒".repeat(4_096);

        for index in 0..3 {
            let id = OperationId::new(format!("synthetic-{index}")).unwrap();
            store.insert(
                OperationStatus {
                    id: id.clone(),
                    kind: OperationKind::DeployAccount,
                    state: OperationState::Rejected {
                        // Construct directly to exercise the store's own
                        // boundary, independent of GatewayError::new.
                        error: GatewayError {
                            code: GatewayErrorCode::RpcDegraded,
                            retryable: true,
                            message: Some(oversized.clone()),
                        },
                    },
                    provenance: None,
                },
                0,
            );

            let OperationState::Rejected { error } = store.get(&id, 0).unwrap().state else {
                panic!("stored operation must be rejected");
            };
            let retained = error.message.unwrap();
            assert!(retained.len() <= 1_024);
            assert!(retained.ends_with("… [truncated]"));
        }

        let retained_capacity: usize = store
            .entries
            .values()
            .map(|entry| match &entry.status.state {
                OperationState::Rejected { error } => {
                    error.message.as_ref().map_or(0, String::capacity)
                }
                _ => 0,
            })
            .sum();
        assert!(retained_capacity <= 3 * 2 * 1_024);

        // Ordinary gateway construction also bounds the immediate response.
        let returned = GatewayError::new(GatewayErrorCode::RpcDegraded, true, Some(oversized));
        assert!(returned.message.unwrap().capacity() <= 2 * 1_024);
    }
}
