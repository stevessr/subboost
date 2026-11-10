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
    db.execute_batch("CREATE TABLE IF NOT EXISTS subscription_source_cache(
        subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
        source_hash TEXT NOT NULL,
        nodes_yaml TEXT NOT NULL,
        info_json TEXT NOT NULL DEFAULT '{}',
        fetched_at INTEGER NOT NULL,
        PRIMARY KEY(subscription_id,source_hash)
    );
    CREATE TABLE IF NOT EXISTS subscription_info(
        subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
        info_json TEXT NOT NULL DEFAULT '{}'
    );")?;
    // Keep developer databases created with the earlier per-source cache schema.
    let mut columns=db.prepare("PRAGMA table_info(subscription_source_cache)")?;
    let has_info=columns.query_map([],|row|row.get::<_,String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?.iter()
        .any(|name|name=="info_json");
    drop(columns);
    if !has_info {
        db.execute_batch("ALTER TABLE subscription_source_cache ADD COLUMN info_json TEXT NOT NULL DEFAULT '{}';")?;
    }
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
    let sources_json=serde_json::to_string(&input.source_urls)
        .map_err(|e|rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let tx=db.unchecked_transaction()?;
    let previous:Option<String>=tx.query_row(
        "SELECT sources_json FROM subscriptions WHERE id=?1",params![id],|r|r.get(0)
    ).optional()?;
    let Some(previous)=previous else {tx.rollback()?;return Ok(false);};
    let changed=tx.execute(
        "UPDATE subscriptions SET name=?2, sources_json=?3, manual_yaml=?4,
             rules_text=?5,
             nodes_yaml=CASE WHEN sources_json=?3 THEN nodes_yaml ELSE '' END,
             last_error=CASE WHEN sources_json=?3 THEN last_error ELSE '' END,
             updated_at=?6, revision=revision+1 WHERE id=?1",
        params![id, input.name, sources_json,
                input.manual_yaml, input.rules_text, now()],
    )?!=0;
    if changed && previous!=sources_json {
        // Removed or replaced URLs must not leave stale node caches behind.
        tx.execute("DELETE FROM subscription_source_cache WHERE subscription_id=?1",params![id])?;
        tx.execute("DELETE FROM subscription_info WHERE subscription_id=?1",params![id])?;
    }
    tx.commit()?;
    Ok(changed)
}

pub fn save_refresh(db: &Connection, id: &str, nodes_yaml: &str, error: &str) -> rusqlite::Result<()> {
    db.execute("UPDATE subscriptions SET nodes_yaml=?2, last_error=?3, updated_at=?4 WHERE id=?1",
        params![id, nodes_yaml, error, now()])?;
    Ok(())
}


fn source_hash(source: &str) -> String {
    use sha2::{Digest,Sha256};
    Sha256::digest(source.as_bytes()).iter().map(|v| format!("{v:02x}")).collect()
}

/// Read a single provider's last successful snapshot. Source URL/token
/// is not copied into cache indexes or diagnostic logs.
pub fn source_nodes(db:&Connection, id:&str, source:&str)->rusqlite::Result<Option<String>> {
    db.query_row(
        "SELECT nodes_yaml FROM subscription_source_cache
         WHERE subscription_id=?1 AND source_hash=?2",
        params![id,source_hash(source)],|r|r.get(0)
    ).optional()
}

pub fn source_info(
    db:&Connection,id:&str,source:&str
)->rusqlite::Result<crate::metadata::SubscriptionInfo>{
    let raw:Option<String>=db.query_row(
        "SELECT info_json FROM subscription_source_cache
         WHERE subscription_id=?1 AND source_hash=?2",
        params![id,source_hash(source)],|row|row.get(0)
    ).optional()?;
    raw.map(|v|serde_json::from_str(&v).map_err(|e|
        rusqlite::Error::ToSqlConversionFailure(Box::new(e))))
        .transpose().map(|v|v.unwrap_or_default())
}

pub fn info(
    db:&Connection,id:&str
)->rusqlite::Result<crate::metadata::SubscriptionInfo>{
    let raw:Option<String>=db.query_row(
        "SELECT info_json FROM subscription_info WHERE subscription_id=?1",
        params![id],|row|row.get(0)
    ).optional()?;
    raw.map(|v|serde_json::from_str(&v).map_err(|e|
        rusqlite::Error::ToSqlConversionFailure(Box::new(e))))
        .transpose().map(|v|v.unwrap_or_default())
}

/// Atomically commit a complete profile snapshot AND any successful source
/// cache updates, guarded by the revision. A rejected stale refresh does
/// not modify the aggregate, error state, source cache or revision.
pub fn commit_refresh_if_revision(
    db:&Connection,id:&str,revision:i64,
    nodes_yaml:&str,error:&str,
    updates:&[(String,String,crate::metadata::SubscriptionInfo)],
    aggregate:Option<&crate::metadata::SubscriptionInfo>
)->rusqlite::Result<bool>{
    let transaction=db.unchecked_transaction()?;
    let applied=transaction.execute(
        "UPDATE subscriptions SET nodes_yaml=?3,last_error=?4,
         updated_at=?5,revision=revision+1
         WHERE id=?1 AND revision=?2",
        params![id,revision,nodes_yaml,error,now()])?==1;
    if !applied {transaction.rollback()?;return Ok(false);}
    for (source,yaml,metadata) in updates {
        let json=serde_json::to_string(metadata).map_err(|e|
            rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        transaction.execute(
            "INSERT INTO subscription_source_cache
             (subscription_id,source_hash,nodes_yaml,info_json,fetched_at)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(subscription_id,source_hash)
             DO UPDATE SET nodes_yaml=excluded.nodes_yaml,
             info_json=excluded.info_json,fetched_at=excluded.fetched_at",
            params![id,source_hash(source),yaml,json,now()]
        )?;
    }
    if let Some(metadata)=aggregate {
        let json=serde_json::to_string(metadata).map_err(|e|
            rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        transaction.execute(
            "INSERT INTO subscription_info(subscription_id,info_json)
             VALUES(?1,?2) ON CONFLICT(subscription_id)
             DO UPDATE SET info_json=excluded.info_json",
            params![id,json]
        )?;
    }
    transaction.commit()?;
    Ok(true)
}

/// Compare-and-swap the entire profile revision, not just its source URLs.
/// A second refresh with the same source list and even a same-second edit
/// must not overwrite a fresher snapshot.
pub fn save_refresh_if_revision(
    db: &Connection, id: &str, expected_revision: i64,
    nodes_yaml: &str, error: &str,
) -> rusqlite::Result<bool> {
    commit_refresh_if_revision(db,id,expected_revision,nodes_yaml,error,&[],None)
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
    fn upgrades_released_v01_sqlite_without_losing_profiles() {
        let path=std::env::temp_dir()
            .join(format!("subboost-upgrade-{}.sqlite",random_token()));
        {
            let old=Connection::open(&path).unwrap();
            old.execute_batch("
                CREATE TABLE subscriptions(
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    sources_json TEXT NOT NULL,
                    manual_yaml TEXT NOT NULL DEFAULT '',
                    rules_text TEXT NOT NULL DEFAULT '',
                    nodes_yaml TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT '',
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE subscription_source_cache(
                    subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
                    source_hash TEXT NOT NULL,
                    nodes_yaml TEXT NOT NULL,
                    fetched_at INTEGER NOT NULL,
                    PRIMARY KEY(subscription_id,source_hash)
                );
                INSERT INTO subscriptions
                    (id,name,token,sources_json,manual_yaml,rules_text,
                     nodes_yaml,last_error,updated_at)
                VALUES('legacy','Old profile','old-token','[]','','MATCH,Proxy',
                    '- {name: Old}', '',100);
            ").unwrap();
        }
        let db=open(&path).unwrap();
        let profile=by_id(&db,"legacy").unwrap().unwrap();
        assert_eq!(profile.name,"Old profile");
        assert_eq!(profile.revision,0);
        assert_eq!(profile.nodes_yaml,"- {name: Old}");
        assert!(crate::templates::list(&db).unwrap().len()>=3);
        assert!(crate::schedule::get(&db,"legacy").unwrap().is_none());
        assert_eq!(info(&db,"legacy").unwrap().header(),None);
        assert!(save_refresh_if_revision(&db,"legacy",0,"- {name: New}","").unwrap());
        assert!(!save_refresh_if_revision(&db,"legacy",0,"- {name: Stale}","").unwrap());
        assert_eq!(by_token(&db,"old-token").unwrap().unwrap().nodes_yaml,
            "- {name: New}");
        drop(db);
        for suffix in ["","-wal","-shm"] {
            let file=std::path::PathBuf::from(format!("{}{}",path.display(),suffix));
            let _=std::fs::remove_file(file);
        }
    }
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
        let before_cache=by_id(&db,&sub.id).unwrap().unwrap();
        let cached_url=before_cache.source_urls[0].clone();
        let metadata=crate::metadata::SubscriptionInfo::parse("upload=1024; total=8192");
        assert!(commit_refresh_if_revision(&db,&sub.id,before_cache.revision,
            "- {name: Live}","",
            &[(cached_url.clone(),"- {name: Source}".into(),metadata.clone())],
            Some(&metadata)).unwrap());
        assert_eq!(info(&db,&sub.id).unwrap().upload,Some(1024));
        assert_eq!(source_info(&db,&sub.id,&cached_url).unwrap().total,Some(8192));
        assert_eq!(source_nodes(&db,&sub.id,&cached_url).unwrap().as_deref(),
            Some("- {name: Source}"));
        assert!(!commit_refresh_if_revision(&db,&sub.id,before_cache.revision,
            "- {name: Stale}","",
            &[(cached_url.clone(),"- {name: Old}".into(),
               crate::metadata::SubscriptionInfo::default())],None).unwrap());
        assert_eq!(source_nodes(&db,&sub.id,&cached_url).unwrap().as_deref(),
            Some("- {name: Source}"));
        let before_edit = by_id(&db,&sub.id).unwrap().unwrap();
        update(&db,&sub.id,SubscriptionInput {
            name:"Edited".into(),source_urls:before_edit.source_urls.clone(),
            manual_yaml:"dns:\n  enable: false".into(),rules_text:"MATCH,DIRECT".into()
        }).unwrap();
        assert!(!save_refresh_if_revision(&db,&sub.id,before_edit.revision,"- {name: Race}", "").unwrap());
        assert!(by_id(&db,&sub.id).unwrap().unwrap().nodes_yaml.contains("Live"));
        assert!(source_nodes(&db,&sub.id,&cached_url).unwrap().is_some());
        let latest=by_id(&db,&sub.id).unwrap().unwrap();
        update(&db,&sub.id,SubscriptionInput {
            name:"New source".into(),source_urls:vec!["https://another.example/sub".into()],
            manual_yaml:latest.manual_yaml.clone(),rules_text:latest.rules_text.clone(),
        }).unwrap();
        assert!(source_nodes(&db,&sub.id,&cached_url).unwrap().is_none());
        assert_eq!(info(&db,&sub.id).unwrap().upload,None);
        rotate(&db, &sub.id).unwrap();
        assert!(by_token(&db, &sub.token).unwrap().is_none());
        assert!(delete(&db, &sub.id).unwrap());
        assert!(list(&db).unwrap().is_empty());
    }
}
