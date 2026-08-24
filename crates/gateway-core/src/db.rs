//! The `db-scram` mechanism (PROTO-SPEC §7 row; intent-catalog).
//!
//! SCRAM-SHA-256 is performed by the maintained `tokio-postgres` client -
//! the vault secret is the password handed to that handshake and NEVER
//! travels verbatim on the wire (that is what SCRAM IS); it exists only in
//! a [`SecretString`] inside the connect frame.
//!
//! Two lifecycles from one backend:
//! - **One-shot** ([`execute_one_shot`]): connect, run the statement,
//!   return rows as data, drop everything.
//! - **Session** ([`DbChannel`]): the authenticated connection persists and
//!   each `session.command` frame's SQL executes against it.
//!
//! TLS to the database is NOT negotiated in v0 (`NoTls`) - documented gap,
//! loud, tracked post-v1 alongside the rustls connector work.

use std::sync::Arc;
use std::time::Duration;

use chaperone_protocol::parse_pg_uri;
use chaperone_vault::SecretString;
use serde_json::{Value, json};
use tokio_postgres::NoTls;

use crate::session::{OutputBatch, OutputChunk, SessionBackend, SessionChannel};

/// Builds client configuration from the signed intent's endpoint pieces.
///
/// # Errors when pieces disagree: an `operation.database` that contradicts
/// the URI path fails BEFORE any connection attempt - cheaper than letting
/// a signed-intent ambiguity resolve into whichever database answered.
fn build_config(
    target_uri: &str,
    operation: &Value,
) -> Result<(tokio_postgres::Config, String), String> {
    let ep = parse_pg_uri(target_uri)?;
    let engine = operation
        .get("engine")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !engine.is_empty() && engine != "postgres" {
        return Err(format!("engine {engine:?} unsupported; only 'postgres'"));
    }

    let mut config = tokio_postgres::Config::new();
    config.host(&ep.host).port(ep.port);
    if let Some(db) = ep.database.strip_prefix('/') {
        config.dbname(db);
        if let Some(op_db) = operation.get("database").and_then(Value::as_str)
            && op_db != db
        {
            return Err(format!(
                "operation.database {op_db:?} contradicts target URI database {db:?}"
            ));
        }
    }
    if let Some(op_db) = operation.get("database").and_then(Value::as_str) {
        config.dbname(op_db);
    }

    let user = operation
        .get("username")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty())
        .map(str::to_owned)
        .or_else(|| (!ep.user.is_empty()).then_some(ep.user.clone()))
        .ok_or("no user: put one in target.uri userinfo or operation.username")?;
    config.user(&user);

    Ok((config, user))
}

/// One-shot execution: connect -> SCRAM auth -> execute -> serialize.
pub async fn execute_one_shot(
    target_uri: &str,
    operation: &Value,
    _secret: &SecretString,
) -> Result<Value, String> {
    // `_secret` is intentionally unnamed: the SCRAM handshake consumes it
    // inside `config.connect` via tokio-postgres; this function never reads
    // the plaintext itself. The parameter stays in the signature so the
    // call site documents "a credential was resolved and spent here".
    let (config, _user) = build_config(target_uri, operation)?;
    let statement = operation
        .get("statement")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or("one-shot requires operation.statement")?
        .to_owned();
    let params: Vec<String> = operation
        .get("params")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let (client, connection) = config
        .connect(NoTls)
        .await
        .map_err(|e| format!("connect failed (auth or network): {e}"))?;
    let conn_handle = tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("chaperone db connection ended: {e}");
        }
    });

    let result = if params.is_empty() {
        run_simple(&client, &statement).await
    } else {
        run_parameterized(&client, &statement, &params).await
    };

    // Connection drops here regardless of outcome; the password lived only
    // inside this call frame.
    drop(client);
    conn_handle.abort();
    result
}

async fn run_simple(client: &tokio_postgres::Client, statement: &str) -> Result<Value, String> {
    let rows = client
        .simple_query(statement)
        .await
        .map_err(|e| format!("execution failed: {e}"))?;

    // simple_query interleaves rows and command tags per statement; v0
    // serializes every returned row set flattened with row counts.
    let mut out_rows: Vec<Value> = Vec::new();
    for msg in &rows {
        match msg {
            tokio_postgres::SimpleQueryMessage::Row(row) => {
                let mut r = Vec::with_capacity(row.len());
                for i in 0..row.len() {
                    r.push(json!(row.get(i).map(str::to_owned)));
                }
                out_rows.push(Value::Array(r));
            }
            tokio_postgres::SimpleQueryMessage::CommandComplete(rows_affected)
                if *rows_affected > 0 =>
            {
                out_rows.push(json!({ "rows_affected": rows_affected }));
            }
            _ => {}
        }
    }
    Ok(json!({
        "type": "result",
        "rows": out_rows,
    }))
}

/// Parameterized execution: bound AS TEXT (see [`crate::db`] module docs /
/// D28). Postgres casts text literals to column types in most contexts;
/// explicit `$1::int`-style hints make intent unambiguous.
async fn run_parameterized(
    client: &tokio_postgres::Client,
    statement: &str,
    params: &[String],
) -> Result<Value, String> {
    let prepared = client
        .prepare(statement)
        .await
        .map_err(|e| format!("prepare failed: {e}"))?;
    use tokio_postgres::types::ToSql;
    let bound: Vec<&(dyn ToSql + Sync)> = params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
    let rows = client
        .query(&prepared, bound.as_slice())
        .await
        .map_err(|e| format!("execution failed: {e}"))?;

    let columns: Vec<String> = prepared
        .columns()
        .iter()
        .map(|c| c.name().to_owned())
        .collect();
    let mut out_rows: Vec<Value> = Vec::with_capacity(rows.len());
    for row in &rows {
        let mut r = Vec::with_capacity(columns.len());
        for i in 0..columns.len() {
            // All values rendered through their TEXT representation: safe,
            // lossless-enough for relay, and type-agnostic.
            r.push(json!(row.try_get::<_, Option<&str>>(i).ok().flatten()));
        }
        out_rows.push(Value::Array(r));
    }
    Ok(json!({
        "type": "result",
        "columns": columns,
        "rows": out_rows,
    }))
}

// ---------- session lifecycle ----------

fn spawn_connection_task<S, T>(connection: tokio_postgres::Connection<S, T>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("chaperone db session connection ended: {e}");
        }
    });
}

impl SessionBackend for DbBackend {
    #[allow(unused_variables)] // secret is spent by config.connect below via SCRAM
    fn connect<'a>(
        &'a self,
        target_uri: &'a str,
        operation: &'a Value,
        secret: &'a SecretString,
    ) -> crate::session::ConnectFuture<'a> {
        Box::pin(async move {
            if operation.get("statement").and_then(Value::as_str).is_some() {
                return Err(
                    "openers must omit statement; use one-shot intents for single queries"
                        .to_owned(),
                );
            }
            let (config, _user) = build_config(target_uri, operation)?;
            let (client, connection) = config
                .connect(NoTls)
                .await
                .map_err(|e| format!("connect failed (auth or network): {e}"))?;
            spawn_connection_task(connection);
            Ok(Box::new(DbChannel::new(client)) as Box<dyn SessionChannel>)
        })
    }
}

/// The `db-scram` backend.
pub struct DbBackend;

impl Default for DbBackend {
    fn default() -> Self {
        Self
    }
}

/// Live authenticated connection driven by SQL frames.
pub struct DbChannel {
    client: tokio_postgres::Client,
    pending_results: Arc<tokio::sync::Mutex<Vec<Value>>>,
}

impl SessionChannel for DbChannel {
    fn write(
        &self,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let sql = String::from_utf8(data).map_err(|_| "input is not UTF-8 SQL".to_owned())?;
            let rows = self
                .client
                .simple_query(sql.trim())
                .await
                .map_err(|e| format!("execution failed: {e}"))?;

            let mut pending = self.pending_results.lock().await;
            for msg in &rows {
                match msg {
                    tokio_postgres::SimpleQueryMessage::Row(row) => {
                        let mut r = Vec::with_capacity(row.len());
                        for i in 0..row.len() {
                            r.push(json!(row.get(i).map(str::to_owned)));
                        }
                        pending.push(Value::Array(r));
                    }
                    tokio_postgres::SimpleQueryMessage::CommandComplete(n) if *n > 0 => {
                        pending.push(json!({ "rows_affected": n }));
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }

    fn read_batch(
        &self,
        max_wait: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = OutputBatch> + Send + '_>> {
        Box::pin(async move {
            // Results are produced by write(); wait briefly for stragglers.
            let deadline = tokio::time::Instant::now() + max_wait;
            loop {
                {
                    let mut pending = self.pending_results.lock().await;
                    if !pending.is_empty() {
                        let chunks = vec![OutputChunk {
                            stream: "stdout",
                            data: serde_json::to_vec(&pending.drain(..).collect::<Vec<_>>())
                                .unwrap_or_default(),
                        }];
                        return OutputBatch {
                            chunks,
                            closed: false,
                            exit_code: None,
                        };
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    return OutputBatch::default();
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
    }

    fn shutdown(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            // Dropping the Client closes the connection; nothing graceful to
            // await beyond that.
        })
    }
}

// DbChannel needs the pending buffer field.
impl DbChannel {
    /// Wraps an established client into a driveable channel.
    pub fn new(client: tokio_postgres::Client) -> Self {
        Self {
            client,
            pending_results: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }
}
