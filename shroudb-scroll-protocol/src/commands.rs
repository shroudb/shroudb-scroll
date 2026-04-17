use shroudb_acl::{AclRequirement, Scope};

/// Parsed Scroll wire command. Every payload has already been pulled out of
/// the RESP3 bulk-string array; further decoding (base64 → bytes, JSON →
/// headers map) happens in `dispatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrollCommand {
    // ── Data plane ─────────────────────────────────────────────────────
    Append {
        log: String,
        payload_b64: String,
        headers_json: Option<String>,
        ttl_ms: Option<i64>,
    },
    Read {
        log: String,
        from_offset: u64,
        limit: u32,
    },
    CreateGroup {
        log: String,
        group: String,
        /// `"earliest"` / `"0"` → deliver from offset 0.
        /// `"latest"` / `"-1"` → resolve to the current next_offset at dispatch time.
        /// Numeric string → parsed as `u64`.
        start_offset: String,
    },
    ReadGroup {
        log: String,
        group: String,
        reader_id: String,
        limit: u32,
    },
    Ack {
        log: String,
        group: String,
        offset: u64,
    },
    DeleteLog {
        log: String,
    },
    LogInfo {
        log: String,
    },
    GroupInfo {
        log: String,
        group: String,
    },

    // ── Meta commands ──────────────────────────────────────────────────
    Auth {
        token: String,
    },
    Health,
    Ping,
    Hello,
    CommandList,
}

impl ScrollCommand {
    /// ACL requirement per SPEC §5. `scroll.<log>` resource namespace, read or
    /// write scope. Meta commands require no ACL.
    pub fn acl_requirement(&self) -> AclRequirement {
        let (log, scope) = match self {
            Self::Append { log, .. } | Self::DeleteLog { log } => (log.as_str(), Scope::Write),
            Self::CreateGroup { log, .. } => (log.as_str(), Scope::Write),
            Self::Read { log, .. }
            | Self::ReadGroup { log, .. }
            | Self::Ack { log, .. }
            | Self::LogInfo { log }
            | Self::GroupInfo { log, .. } => (log.as_str(), Scope::Read),
            Self::Auth { .. } | Self::Health | Self::Ping | Self::Hello | Self::CommandList => {
                return AclRequirement::None;
            }
        };
        AclRequirement::Namespace {
            ns: format!("scroll.{log}"),
            scope,
            tenant_override: None,
        }
    }

    /// Short uppercase name used for audit/log lines.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Append { .. } => "APPEND",
            Self::Read { .. } => "READ",
            Self::CreateGroup { .. } => "CREATE_GROUP",
            Self::ReadGroup { .. } => "READ_GROUP",
            Self::Ack { .. } => "ACK",
            Self::DeleteLog { .. } => "DELETE_LOG",
            Self::LogInfo { .. } => "LOG_INFO",
            Self::GroupInfo { .. } => "GROUP_INFO",
            Self::Auth { .. } => "AUTH",
            Self::Health => "HEALTH",
            Self::Ping => "PING",
            Self::Hello => "HELLO",
            Self::CommandList => "COMMAND",
        }
    }
}

pub fn parse_command(args: &[&str]) -> Result<ScrollCommand, String> {
    if args.is_empty() {
        return Err("empty command".into());
    }
    match args[0].to_ascii_uppercase().as_str() {
        "APPEND" => parse_append(&args[1..]),
        "READ" => parse_read(&args[1..]),
        "CREATE_GROUP" => parse_create_group(&args[1..]),
        "READ_GROUP" => parse_read_group(&args[1..]),
        "ACK" => parse_ack(&args[1..]),
        "DELETE_LOG" => parse_delete_log(&args[1..]),
        "LOG_INFO" => parse_log_info(&args[1..]),
        "GROUP_INFO" => parse_group_info(&args[1..]),
        "AUTH" => {
            let token = args
                .get(1)
                .ok_or_else(|| "AUTH requires a token".to_string())?;
            Ok(ScrollCommand::Auth {
                token: (*token).to_string(),
            })
        }
        "HEALTH" => Ok(ScrollCommand::Health),
        "PING" => Ok(ScrollCommand::Ping),
        "HELLO" => Ok(ScrollCommand::Hello),
        "COMMAND" => {
            if args.len() >= 2 && args[1].eq_ignore_ascii_case("LIST") {
                Ok(ScrollCommand::CommandList)
            } else {
                Err("unknown COMMAND subcommand (try COMMAND LIST)".into())
            }
        }
        other => Err(format!("unknown command: {other}")),
    }
}

fn parse_append(args: &[&str]) -> Result<ScrollCommand, String> {
    if args.len() < 2 {
        return Err("APPEND requires <log> <payload_b64> [HEADERS <json>] [TTL <ms>]".into());
    }
    let log = args[0].to_string();
    let payload_b64 = args[1].to_string();
    let mut headers_json: Option<String> = None;
    let mut ttl_ms: Option<i64> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].to_ascii_uppercase().as_str() {
            "HEADERS" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| "HEADERS requires a JSON value".to_string())?;
                headers_json = Some((*v).to_string());
            }
            "TTL" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| "TTL requires a millisecond value".to_string())?;
                ttl_ms = Some(
                    v.parse::<i64>()
                        .map_err(|_| format!("TTL must be an integer (got {v})"))?,
                );
            }
            other => return Err(format!("unknown APPEND option: {other}")),
        }
        i += 1;
    }
    Ok(ScrollCommand::Append {
        log,
        payload_b64,
        headers_json,
        ttl_ms,
    })
}

fn parse_read(args: &[&str]) -> Result<ScrollCommand, String> {
    if args.len() != 3 {
        return Err("READ requires <log> <from_offset> <limit>".into());
    }
    Ok(ScrollCommand::Read {
        log: args[0].to_string(),
        from_offset: args[1]
            .parse::<u64>()
            .map_err(|_| format!("from_offset must be u64 (got {})", args[1]))?,
        limit: args[2]
            .parse::<u32>()
            .map_err(|_| format!("limit must be u32 (got {})", args[2]))?,
    })
}

fn parse_create_group(args: &[&str]) -> Result<ScrollCommand, String> {
    if args.len() != 3 {
        return Err("CREATE_GROUP requires <log> <group> <start_offset>".into());
    }
    Ok(ScrollCommand::CreateGroup {
        log: args[0].to_string(),
        group: args[1].to_string(),
        start_offset: args[2].to_string(),
    })
}

fn parse_read_group(args: &[&str]) -> Result<ScrollCommand, String> {
    if args.len() != 4 {
        return Err("READ_GROUP requires <log> <group> <reader_id> <limit>".into());
    }
    Ok(ScrollCommand::ReadGroup {
        log: args[0].to_string(),
        group: args[1].to_string(),
        reader_id: args[2].to_string(),
        limit: args[3]
            .parse::<u32>()
            .map_err(|_| format!("limit must be u32 (got {})", args[3]))?,
    })
}

fn parse_ack(args: &[&str]) -> Result<ScrollCommand, String> {
    if args.len() != 3 {
        return Err("ACK requires <log> <group> <offset>".into());
    }
    Ok(ScrollCommand::Ack {
        log: args[0].to_string(),
        group: args[1].to_string(),
        offset: args[2]
            .parse::<u64>()
            .map_err(|_| format!("offset must be u64 (got {})", args[2]))?,
    })
}

fn parse_delete_log(args: &[&str]) -> Result<ScrollCommand, String> {
    if args.len() != 1 {
        return Err("DELETE_LOG requires <log>".into());
    }
    Ok(ScrollCommand::DeleteLog {
        log: args[0].to_string(),
    })
}

fn parse_log_info(args: &[&str]) -> Result<ScrollCommand, String> {
    if args.len() != 1 {
        return Err("LOG_INFO requires <log>".into());
    }
    Ok(ScrollCommand::LogInfo {
        log: args[0].to_string(),
    })
}

fn parse_group_info(args: &[&str]) -> Result<ScrollCommand, String> {
    if args.len() != 2 {
        return Err("GROUP_INFO requires <log> <group>".into());
    }
    Ok(ScrollCommand::GroupInfo {
        log: args[0].to_string(),
        group: args[1].to_string(),
    })
}

/// Resolve the `start_offset` argument of `CREATE_GROUP` against the current
/// log state. `"earliest"` / `"0"` → 0. `"latest"` / `"-1"` → `next_offset`.
/// Numeric → parsed as `u64`. Returned error messages are caller-facing.
pub fn resolve_start_offset(raw: &str, next_offset: u64) -> Result<u64, String> {
    match raw.to_ascii_lowercase().as_str() {
        "earliest" | "0" => Ok(0),
        "latest" | "-1" => Ok(next_offset),
        other => other
            .parse::<u64>()
            .map_err(|_| format!("start_offset must be u64 or 'earliest'/'latest' (got {raw})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_append_minimal() {
        let cmd = parse_command(&["APPEND", "orders", "aGVsbG8="]).unwrap();
        if let ScrollCommand::Append {
            log,
            payload_b64,
            headers_json,
            ttl_ms,
        } = cmd
        {
            assert_eq!(log, "orders");
            assert_eq!(payload_b64, "aGVsbG8=");
            assert!(headers_json.is_none());
            assert!(ttl_ms.is_none());
        } else {
            panic!("expected Append");
        }
    }

    #[test]
    fn parse_append_with_headers_and_ttl() {
        let cmd = parse_command(&[
            "APPEND",
            "orders",
            "aGVsbG8=",
            "HEADERS",
            r#"{"k":"v"}"#,
            "TTL",
            "60000",
        ])
        .unwrap();
        if let ScrollCommand::Append {
            headers_json,
            ttl_ms,
            ..
        } = cmd
        {
            assert_eq!(headers_json.as_deref(), Some(r#"{"k":"v"}"#));
            assert_eq!(ttl_ms, Some(60_000));
        } else {
            panic!("expected Append");
        }
    }

    #[test]
    fn parse_read_requires_three_args() {
        assert!(parse_command(&["READ", "log"]).is_err());
        assert!(parse_command(&["READ", "log", "0"]).is_err());
        assert!(parse_command(&["READ", "log", "0", "10"]).is_ok());
        assert!(parse_command(&["READ", "log", "0", "10", "extra"]).is_err());
    }

    #[test]
    fn parse_rejects_non_numeric_offsets() {
        assert!(parse_command(&["READ", "log", "nope", "10"]).is_err());
        assert!(parse_command(&["ACK", "log", "g", "nope"]).is_err());
    }

    #[test]
    fn meta_commands_have_no_acl() {
        for c in [
            ScrollCommand::Health,
            ScrollCommand::Ping,
            ScrollCommand::Hello,
            ScrollCommand::CommandList,
            ScrollCommand::Auth { token: "t".into() },
        ] {
            assert!(matches!(c.acl_requirement(), AclRequirement::None));
        }
    }

    #[test]
    fn data_commands_use_per_log_namespace() {
        let append = ScrollCommand::Append {
            log: "orders".into(),
            payload_b64: String::new(),
            headers_json: None,
            ttl_ms: None,
        };
        match append.acl_requirement() {
            AclRequirement::Namespace { ns, scope, .. } => {
                assert_eq!(ns, "scroll.orders");
                assert_eq!(scope, Scope::Write);
            }
            _ => panic!("expected Namespace"),
        }

        let read = ScrollCommand::Read {
            log: "orders".into(),
            from_offset: 0,
            limit: 10,
        };
        match read.acl_requirement() {
            AclRequirement::Namespace { ns, scope, .. } => {
                assert_eq!(ns, "scroll.orders");
                assert_eq!(scope, Scope::Read);
            }
            _ => panic!("expected Namespace"),
        }
    }

    #[test]
    fn resolve_start_offset_literals() {
        assert_eq!(resolve_start_offset("0", 7).unwrap(), 0);
        assert_eq!(resolve_start_offset("earliest", 7).unwrap(), 0);
        assert_eq!(resolve_start_offset("EARLIEST", 7).unwrap(), 0);
        assert_eq!(resolve_start_offset("latest", 7).unwrap(), 7);
        assert_eq!(resolve_start_offset("-1", 7).unwrap(), 7);
        assert_eq!(resolve_start_offset("5", 7).unwrap(), 5);
        assert!(resolve_start_offset("junk", 7).is_err());
    }

    #[test]
    fn unknown_command_rejected() {
        assert!(parse_command(&["FOOBAR"]).is_err());
    }

    #[test]
    fn append_rejects_unknown_option() {
        assert!(parse_command(&["APPEND", "log", "b64", "BOGUS", "x"]).is_err());
    }
}
