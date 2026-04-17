/// Identity + tracing context carried alongside every engine command.
///
/// Used for Sentry policy evaluation (`actor` → `PolicyPrincipal.id`),
/// Chronicle audit event emission (`actor` and `correlation_id`), and any
/// future contextual fields (source IP, request ID, etc.). Threading a
/// struct through once instead of growing each method signature keeps
/// additions non-breaking.
#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    pub actor: Option<String>,
    pub correlation_id: Option<String>,
}

impl AuditContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    /// Actor identifier for logging/audit/policy. Defaults to "anonymous"
    /// when no actor was attached at the call site.
    pub fn actor_or_anonymous(&self) -> &str {
        self.actor.as_deref().unwrap_or("anonymous")
    }
}
