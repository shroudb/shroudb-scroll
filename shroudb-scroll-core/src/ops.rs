use crate::entry::LogEntry;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// Capability trait for direct in-process appends from other engines via Moat.
///
/// Parallels `ChronicleOps`: engines embedded in the same process can append to
/// a Scroll log without round-tripping through RESP3. Implementations must
/// preserve offset monotonicity per `(tenant_id, log)`.
pub trait ScrollOps: Send + Sync {
    fn append(
        &self,
        tenant_id: String,
        log: String,
        payload: Vec<u8>,
        headers: BTreeMap<String, String>,
        ttl_ms: Option<i64>,
    ) -> BoxFut<'_, u64>;

    fn read(
        &self,
        tenant_id: String,
        log: String,
        from_offset: u64,
        limit: u32,
    ) -> BoxFut<'_, Vec<LogEntry>>;
}
