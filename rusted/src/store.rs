use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub token: String,
    pub source_urls: Vec<String>,
    pub manual_yaml: String,
    pub rules_text: String,
    pub nodes_yaml: String,
    pub last_error: String,
    pub updated_at: i64,
    /// Monotonic mutation counter used to reject stale asynchronous refreshes.
    pub revision: i64,
}

#[derive(Deserialize)]
pub struct SubscriptionInput {
    pub name: String,
    #[serde(default, alias = "urls")]
    pub source_urls: Vec<String>,
    #[serde(default)]
    pub manual_yaml: String,
    #[serde(default)]
    pub rules_text: String,
}

pub fn random_token() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    if path != Path::new(":memory:") {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(err))
            })?;
        }
    }
    let db = Connection::open(path)?;
    db.pragma_update(None, "journal_mode", "WAL")?;
    db.pragma_update(None, "busy_timeout", 5000)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS subscriptions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            sources_json TEXT NOT NULL,
            manual_yaml TEXT NOT NULL DEFAULT '',
            rules_text TEXT NOT NULL DEFAULT '',
            nodes_yaml TEXT NOT NULL DEFAULT '',
            last_error TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL,
            revision INTEGER NOT NULL DEFAULT 0
        );",
    )?;
    // Upgrade v0.1 databases in place without resetting any subscriptions.
    let mut columns = db.prepare("PRAGMA table_info(subscriptions)")?;
    let has_revision = columns.query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .iter().any(|column| column == "revision");
    drop(columns);
    if !has_revision {
        db.execute_batch("ALTER TABLE subscriptions ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;")?;
    }
    crate::templates::initialize(&db)?;
    crate::schedule::initialize(&db)?;
    crate::filter::initialize(&db)?;
    Ok(db)
}

fn parse_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Subscription> {
    let source_json: String = row.get(3)?;
    let sources = serde_json::from_str::<Vec<String>>(&source_json)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(
            3, rusqlite::types::Type::Text, Box::new(err)))?;
    Ok(Subscription {
        id: row.get(0)?,
        name: row.get(1)?,
        token: row.get(2)?,
        source_urls: sources,
        manual_yaml: row.get(4)?,
        rules_text: row.get(5)?,
        nodes_yaml: row.get(6)?,
        last_error: row.get(7)?,
        updated_at: row.get(8)?,
        revision: row.get(9)?,
    })
}

const SELECT: &str = "SELECT id, name, token, sources_json, manual_yaml, rules_text,
                             nodes_yaml, last_error, updated_at, revision FROM subscriptions";

pub fn list(db: &Connection) -> rusqlite::Result<Vec<Subscription>> {
    let mut stmt = db.prepare(&format!("{SELECT} ORDER BY updated_at DESC, id"))?;
    let rows = stmt.query_map([], parse_row)?;
    rows.collect()
}

pub fn by_id(db: &Connection, id: &str) -> rusqlite::Result<Option<Subscription>> {
    db.query_row(&format!("{SELECT} WHERE id = ?1"), params![id], parse_row).optional()
}

pub fn by_token(db: &Connection, token: &str) -> rusqlite::Result<Option<Subscription>> {
    db.query_row(&format!("{SELECT} WHERE token = ?1"), params![token], parse_row).optional()
}

pub fn create(db: &Connection, input: SubscriptionInput) -> rusqlite::Result<Subscription> {
    let id = random_token()[..18].to_string();
    let token = random_token();
    db.execute(
        "INSERT INTO subscriptions (id, name, token, sources_json, manual_yaml, rules_text, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, input.name, token, serde_json::to_string(&input.source_urls).unwrap(),
                input.manual_yaml, input.rules_text, now()],
    )?;
    by_id(db, &id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)
}

pub fn update(db: &Connection, id: &str, input: SubscriptionInput) -> rusqlite::Result<bool> {
    Ok(db.execute(
        "UPDATE subscriptions SET name=?2, sources_json=?3, manual_yaml=?4,
             rules_text=?5,
             nodes_yaml=CASE WHEN sources_json=?3 THEN nodes_yaml ELSE '' END,
             last_error=CASE WHEN sources_json=?3 THEN last_error ELSE '' END,
             updated_at=?6, revision=revision+1 WHERE id=?1",
        params![id, input.name, serde_json::to_string(&input.source_urls).unwrap(),
                input.manual_yaml, input.rules_text, now()],
    )? != 0)
}

pub fn save_refresh(db: &Connection, id: &str, nodes_yaml: &str, error: &str) -> rusqlite::Result<()> {
    db.execute("UPDATE subscriptions SET nodes_yaml=?2, last_error=?3, updated_at=?4 WHERE id=?1",
        params![id, nodes_yaml, error, now()])?;
    Ok(())
}


/// Compare-and-swap the entire profile revision, not just its source URLs.
/// A second refresh with the same source list and even a same-second edit
/// must not overwrite a fresher snapshot.
pub fn save_refresh_if_revision(
    db: &Connection, id: &str, expected_revision: i64,
    nodes_yaml: &str, error: &str,
) -> rusqlite::Result<bool> {
    Ok(db.execute(
        "UPDATE subscriptions SET nodes_yaml=?3,last_error=?4,updated_at=?5,
         revision=revision+1
         WHERE id=?1 AND revision=?2",
        params![id,expected_revision,nodes_yaml,error,now()]
    )? == 1)
}

pub fn delete(db: &Connection, id: &str) -> rusqlite::Result<bool> {
    Ok(db.execute("DELETE FROM subscriptions WHERE id=?1", params![id])? != 0)
}

pub fn rotate(db: &Connection, id: &str) -> rusqlite::Result<bool> {
    Ok(db.execute("UPDATE subscriptions SET token=?2, updated_at=?3, revision=revision+1 WHERE id=?1",
        params![id, random_token(), now()])? != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sqlite_roundtrip_and_rotation() {
        let db = open(Path::new(":memory:")).unwrap();
        let sub = create(&db, SubscriptionInput {
            name: "Demo".into(), source_urls: vec!["https://example.org/sub".into()],
            manual_yaml: "".into(), rules_text: "MATCH,Proxy".into(),
        }).unwrap();
        assert_eq!(list(&db).unwrap().len(), 1);
        assert!(by_token(&db, &sub.token).unwrap().is_some());
        save_refresh(&db, &sub.id, "proxies: []", "").unwrap();
        update(&db, &sub.id, SubscriptionInput {
            name: "Edit".into(), source_urls: sub.source_urls.clone(),
            manual_yaml: "".into(), rules_text: "MATCH,Proxy".into(),
        }).unwrap();
        assert!(by_id(&db, &sub.id).unwrap().unwrap().nodes_yaml.contains("proxies"));
        update(&db, &sub.id, SubscriptionInput {
            name: "Edit".into(), source_urls: vec!["https://new.example/sub".into()],
            manual_yaml: "".into(), rules_text: "".into(),
        }).unwrap();
        assert_eq!(by_id(&db, &sub.id).unwrap().unwrap().nodes_yaml, "");
        save_refresh(&db, &sub.id, "proxies: []", "").unwrap();
        assert!(by_id(&db, &sub.id).unwrap().unwrap().nodes_yaml.contains("proxies"));
        let before = by_id(&db,&sub.id).unwrap().unwrap();
        assert!(save_refresh_if_revision(&db,&sub.id,before.revision,"- {name: Fresh}", "").unwrap());
        assert!(!save_refresh_if_revision(&db,&sub.id,before.revision,"- {name: Stale}", "").unwrap());
        assert!(by_id(&db,&sub.id).unwrap().unwrap().nodes_yaml.contains("Fresh"));
        let before_edit = by_id(&db,&sub.id).unwrap().unwrap();
        update(&db,&sub.id,SubscriptionInput {
            name:"Edited".into(),source_urls:before_edit.source_urls.clone(),
            manual_yaml:"dns:\n  enable: false".into(),rules_text:"MATCH,DIRECT".into()
        }).unwrap();
        assert!(!save_refresh_if_revision(&db,&sub.id,before_edit.revision,"- {name: Race}", "").unwrap());
        assert!(by_id(&db,&sub.id).unwrap().unwrap().nodes_yaml.contains("Fresh"));
        rotate(&db, &sub.id).unwrap();
        assert!(by_token(&db, &sub.token).unwrap().is_none());
        assert!(delete(&db, &sub.id).unwrap());
        assert!(list(&db).unwrap().is_empty());
    }
}
