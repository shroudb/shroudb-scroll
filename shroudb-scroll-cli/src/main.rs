use anyhow::Context;
use base64::Engine as _;
use clap::{Parser, Subcommand};
use shroudb_scroll_client::ScrollClient;

#[derive(Parser)]
#[command(name = "shroudb-scroll-cli", version)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:7200", env = "SCROLL_ADDR")]
    addr: String,
    #[arg(long, env = "SCROLL_TOKEN")]
    token: Option<String>,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    Health,
    Ping,
    Hello,
    Append {
        log: String,
        /// Raw payload string. Pass `--b64` if already base64.
        payload: String,
        #[arg(long)]
        b64: bool,
        #[arg(long)]
        ttl_ms: Option<i64>,
    },
    Read {
        log: String,
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Tail {
        log: String,
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = 10)]
        limit: u32,
        #[arg(long)]
        timeout_ms: Option<u64>,
    },
    CreateGroup {
        log: String,
        group: String,
        /// 'earliest', 'latest', or a numeric offset.
        #[arg(long, default_value = "earliest")]
        start: String,
    },
    ReadGroup {
        log: String,
        group: String,
        reader_id: String,
        #[arg(long, default_value_t = 10)]
        limit: u32,
    },
    Ack {
        log: String,
        group: String,
        offset: u64,
    },
    Claim {
        log: String,
        group: String,
        reader_id: String,
        #[arg(long, default_value_t = 30_000)]
        min_idle_ms: i64,
    },
    TrimMaxLen {
        log: String,
        keep: u64,
    },
    TrimMaxAge {
        log: String,
        ms: i64,
    },
    DeleteLog {
        log: String,
    },
    DeleteGroup {
        log: String,
        group: String,
    },
    Replay {
        log: String,
        group: String,
        offset: u64,
    },
    LogInfo {
        log: String,
    },
    GroupInfo {
        log: String,
        group: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = ScrollClient::connect(&cli.addr)
        .await
        .context("failed to connect")?;
    if let Some(ref token) = cli.token {
        client.auth(token).await.context("auth failed")?;
    }

    match cli.cmd {
        Command::Health => {
            let v = client.health().await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Command::Ping => {
            println!("{}", client.ping().await?);
        }
        Command::Hello => {
            let v = client.hello().await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Command::Append {
            log,
            payload,
            b64,
            ttl_ms,
        } => {
            let bytes = if b64 {
                base64::engine::general_purpose::STANDARD
                    .decode(&payload)
                    .context("--b64 was set but payload is not valid base64")?
            } else {
                payload.into_bytes()
            };
            let off = client.append(&log, &bytes, None, ttl_ms).await?;
            println!("{{\"offset\": {off}}}");
        }
        Command::Read { log, from, limit } => {
            let entries = client.read(&log, from, limit).await?;
            print_entries(&entries)?;
        }
        Command::Tail {
            log,
            from,
            limit,
            timeout_ms,
        } => {
            let entries = client.tail(&log, from, limit, timeout_ms).await?;
            print_entries(&entries)?;
        }
        Command::CreateGroup { log, group, start } => {
            client.create_group(&log, &group, &start).await?;
            println!("ok");
        }
        Command::ReadGroup {
            log,
            group,
            reader_id,
            limit,
        } => {
            let entries = client.read_group(&log, &group, &reader_id, limit).await?;
            print_entries(&entries)?;
        }
        Command::Ack { log, group, offset } => {
            client.ack(&log, &group, offset).await?;
            println!("ok");
        }
        Command::Claim {
            log,
            group,
            reader_id,
            min_idle_ms,
        } => {
            let claimed = client.claim(&log, &group, &reader_id, min_idle_ms).await?;
            println!("{}", serde_json::to_string_pretty(&claimed)?);
        }
        Command::TrimMaxLen { log, keep } => {
            let n = client.trim_max_len(&log, keep).await?;
            println!("{{\"deleted\": {n}}}");
        }
        Command::TrimMaxAge { log, ms } => {
            let n = client.trim_max_age_ms(&log, ms).await?;
            println!("{{\"deleted\": {n}}}");
        }
        Command::DeleteLog { log } => {
            client.delete_log(&log).await?;
            println!("ok");
        }
        Command::DeleteGroup { log, group } => {
            client.delete_group(&log, &group).await?;
            println!("ok");
        }
        Command::Replay { log, group, offset } => {
            client.replay(&log, &group, offset).await?;
            println!("ok");
        }
        Command::LogInfo { log } => {
            let v = client.log_info(&log).await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Command::GroupInfo { log, group } => {
            let v = client.group_info(&log, &group).await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
    }

    Ok(())
}

fn print_entries(entries: &[shroudb_scroll_core::LogEntry]) -> anyhow::Result<()> {
    let view: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&e.payload);
            serde_json::json!({
                "offset": e.offset,
                "tenant_id": e.tenant_id,
                "log": e.log,
                "payload_b64": b64,
                "headers": e.headers,
                "appended_at_ms": e.appended_at_ms,
                "expires_at_ms": e.expires_at_ms,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&view)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn append_subcommand_parses() {
        let parsed =
            Cli::try_parse_from(["shroudb-scroll-cli", "append", "mylog", "hello"]).unwrap();
        match parsed.cmd {
            Command::Append { log, payload, .. } => {
                assert_eq!(log, "mylog");
                assert_eq!(payload, "hello");
            }
            _ => panic!("expected Append"),
        }
    }

    #[test]
    fn read_subcommand_with_flags() {
        let parsed = Cli::try_parse_from([
            "shroudb-scroll-cli",
            "read",
            "l",
            "--from",
            "5",
            "--limit",
            "20",
        ])
        .unwrap();
        match parsed.cmd {
            Command::Read { log, from, limit } => {
                assert_eq!(log, "l");
                assert_eq!(from, 5);
                assert_eq!(limit, 20);
            }
            _ => panic!("expected Read"),
        }
    }
}
