use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReaderGroup {
    pub tenant_id: String,
    pub log: String,
    pub group: String,
    pub last_delivered_offset: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub members: BTreeMap<String, ReaderMember>,
    pub created_at_ms: i64,
    /// Monotonic version for CAS on cursor advancement.
    pub version: u64,
}

impl ReaderGroup {
    pub fn new(
        tenant_id: String,
        log: String,
        group: String,
        start_offset: u64,
        created_at_ms: i64,
    ) -> Self {
        Self {
            tenant_id,
            log,
            group,
            last_delivered_offset: start_offset,
            members: BTreeMap::new(),
            created_at_ms,
            version: 0,
        }
    }

    pub fn touch_member(&mut self, reader_id: &str, now_ms: i64) {
        self.members
            .entry(reader_id.to_string())
            .and_modify(|m| m.last_seen_ms = now_ms)
            .or_insert_with(|| ReaderMember {
                reader_id: reader_id.to_string(),
                last_seen_ms: now_ms,
                in_flight: 0,
            });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReaderMember {
    pub reader_id: String,
    pub last_seen_ms: i64,
    pub in_flight: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_group_has_zero_version_and_no_members() {
        let g = ReaderGroup::new("t".into(), "l".into(), "g".into(), 0, 1_700_000_000_000);
        assert_eq!(g.version, 0);
        assert!(g.members.is_empty());
        assert_eq!(g.last_delivered_offset, 0);
    }

    #[test]
    fn touch_member_inserts_then_updates() {
        let mut g = ReaderGroup::new("t".into(), "l".into(), "g".into(), 0, 0);
        g.touch_member("r1", 10);
        assert_eq!(g.members.get("r1").unwrap().last_seen_ms, 10);
        g.touch_member("r1", 20);
        assert_eq!(g.members.get("r1").unwrap().last_seen_ms, 20);
        assert_eq!(g.members.len(), 1);
    }

    #[test]
    fn roundtrip() {
        let mut g = ReaderGroup::new("t".into(), "l".into(), "g".into(), 7, 42);
        g.touch_member("r1", 100);
        g.version = 3;
        let s = serde_json::to_vec(&g).unwrap();
        let parsed: ReaderGroup = serde_json::from_slice(&s).unwrap();
        assert_eq!(parsed, g);
    }
}
