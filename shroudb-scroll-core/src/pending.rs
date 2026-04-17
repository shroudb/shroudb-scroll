use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEntry {
    pub offset: u64,
    pub reader_id: String,
    pub delivered_at_ms: i64,
    pub delivery_count: u32,
}

impl PendingEntry {
    pub fn new(offset: u64, reader_id: String, delivered_at_ms: i64) -> Self {
        Self {
            offset,
            reader_id,
            delivered_at_ms,
            delivery_count: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_at_delivery_count_one() {
        let p = PendingEntry::new(5, "r".into(), 100);
        assert_eq!(p.delivery_count, 1);
        assert_eq!(p.offset, 5);
    }

    #[test]
    fn roundtrip() {
        let p = PendingEntry {
            offset: 12,
            reader_id: "r".into(),
            delivered_at_ms: 100,
            delivery_count: 3,
        };
        let s = serde_json::to_vec(&p).unwrap();
        let parsed: PendingEntry = serde_json::from_slice(&s).unwrap();
        assert_eq!(parsed, p);
    }
}
