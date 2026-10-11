use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use relay_wire::{RouteTag, ServerFrame, TAG_FULL_REASON, TAG_LIMIT_REASON};
use tokio::sync::{mpsc, Notify, RwLock};

pub type ConnId = u64;

const PER_CONN_OUTBOUND_CAP: usize = 256;
/// Tags one connection may hold; a client registers a few per contact.
pub const MAX_TAGS_PER_CONN: usize = 1024;
/// Holders one tag may have: its two peers, plus the stale connections a
/// reconnect leaves until the relay sees them close.
pub const MAX_HOLDERS_PER_TAG: usize = 8;

/// Why `register` refused a tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterRefusal {
    /// The connection already holds `MAX_TAGS_PER_CONN` other tags.
    ConnFull,
    /// The tag already has `MAX_HOLDERS_PER_TAG` other holders.
    TagFull,
}

impl RegisterRefusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::ConnFull => TAG_LIMIT_REASON,
            Self::TagFull => TAG_FULL_REASON,
        }
    }
}

#[derive(Clone)]
pub struct ConnHandle {
    pub id: ConnId,
    pub send: mpsc::Sender<ServerFrame>,
    /// Fires when this connection must be torn down (e.g. its outbound backlog
    /// overflowed). The owning connection task closes cleanly so the client
    /// reconnects and re-syncs rather than silently missing a routed frame.
    pub kill: Arc<Notify>,
}

#[derive(Default)]
struct Inner {
    by_tag: HashMap<RouteTag, HashSet<ConnId>>,
    by_id: HashMap<ConnId, ConnHandle>,
    tags_per_conn: HashMap<ConnId, HashSet<RouteTag>>,
}

#[derive(Clone, Default)]
pub struct RoutingTable {
    inner: Arc<RwLock<Inner>>,
    next_id: Arc<AtomicU64>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_conn_id(&self) -> ConnId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn outbound_capacity() -> usize {
        PER_CONN_OUTBOUND_CAP
    }

    pub async fn attach(&self, handle: ConnHandle) {
        let mut inner = self.inner.write().await;
        inner.by_id.insert(handle.id, handle.clone());
        inner.tags_per_conn.entry(handle.id).or_default();
    }

    /// The subscribers to tell of the arrival, or why the tag was refused.
    pub async fn register(
        &self,
        id: ConnId,
        tag: RouteTag,
    ) -> Result<Vec<ConnHandle>, RegisterRefusal> {
        let mut guard = self.inner.write().await;
        let inner = &mut *guard;
        let held = inner.tags_per_conn.entry(id).or_default();
        if !held.contains(&tag) {
            if held.len() >= MAX_TAGS_PER_CONN {
                return Err(RegisterRefusal::ConnFull);
            }
            if inner
                .by_tag
                .get(&tag)
                .is_some_and(|holders| holders.len() >= MAX_HOLDERS_PER_TAG)
            {
                return Err(RegisterRefusal::TagFull);
            }
        }
        let entry = inner.by_tag.entry(tag).or_default();
        let was_already_present = !entry.insert(id);
        let peer_ids: Vec<ConnId> = if was_already_present {
            Vec::new()
        } else {
            entry.iter().copied().filter(|other| *other != id).collect()
        };
        inner.tags_per_conn.entry(id).or_default().insert(tag);
        Ok(peer_ids
            .into_iter()
            .filter_map(|peer_id| inner.by_id.get(&peer_id).cloned())
            .chain(if !was_already_present {
                inner.by_id.get(&id).cloned()
            } else {
                None
            })
            .collect())
    }

    pub async fn unregister(&self, id: ConnId, tag: RouteTag) {
        let mut inner = self.inner.write().await;
        if let Some(set) = inner.by_tag.get_mut(&tag) {
            set.remove(&id);
            if set.is_empty() {
                inner.by_tag.remove(&tag);
            }
        }
        if let Some(set) = inner.tags_per_conn.get_mut(&id) {
            set.remove(&tag);
        }
    }

    /// Excludes `sender_id` from the result.
    pub async fn recipients(&self, sender_id: ConnId, tag: &RouteTag) -> Vec<ConnHandle> {
        let inner = self.inner.read().await;
        let Some(set) = inner.by_tag.get(tag) else {
            return Vec::new();
        };
        set.iter()
            .filter(|id| **id != sender_id)
            .filter_map(|id| inner.by_id.get(id).cloned())
            .collect()
    }

    pub async fn remove_connection(&self, id: ConnId) {
        let mut notify: Vec<(RouteTag, Vec<ConnHandle>)> = Vec::new();
        {
            let mut inner = self.inner.write().await;
            inner.by_id.remove(&id);
            let tags = inner.tags_per_conn.remove(&id).unwrap_or_default();
            for tag in tags {
                let remaining_ids: Vec<ConnId> = if let Some(set) = inner.by_tag.get_mut(&tag) {
                    set.remove(&id);
                    let ids: Vec<ConnId> = set.iter().copied().collect();
                    if set.is_empty() {
                        inner.by_tag.remove(&tag);
                    }
                    ids
                } else {
                    Vec::new()
                };
                if !remaining_ids.is_empty() {
                    let handles: Vec<ConnHandle> = remaining_ids
                        .iter()
                        .filter_map(|peer_id| inner.by_id.get(peer_id).cloned())
                        .collect();
                    if !handles.is_empty() {
                        notify.push((tag, handles));
                    }
                }
            }
        }
        for (tag, handles) in notify {
            for h in handles {
                let _ = h.send.try_send(ServerFrame::PeerGone { tag });
            }
        }
    }
}
