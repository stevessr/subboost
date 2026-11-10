//! Local subscription refresh scheduler with persistent, bounded backoff.
//! One worker handles due subscriptions sequentially to keep ARM64 RSS bounded.
use crate::store::now;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize,Serialize};

pub const MIN_INTERVAL: i64 = 360; // matches original 0.1h minimum
pub const MAX_INTERVAL: i64 = 604_800;

#[derive(Clone,Serialize,Deserialize,Debug)]
pub struct Schedule {
    pub subscription_id:String,
    pub interval_seconds:i64,
    pub next_refresh_at:i64,
    pub consecutive_failures:i64,
    pub last_attempted_at:Option<i64>,
    pub last_succeeded_at:Option<i64>,
}

fn parse_row(row:&rusqlite::Row<'_>)->rusqlite::Result<Schedule>{
    Ok(Schedule{subscription_id:row.get(0)?,
        interval_seconds:row.get(1)?,next_refresh_at:row.get(2)?,
        consecutive_failures:row.get(3)?,last_attempted_at:row.get(4)?,
        last_succeeded_at:row.get(5)?})
}
const SELECT:&str="SELECT subscription_id,interval_seconds,next_refresh_at,
 consecutive_failures,last_attempted_at,last_succeeded_at FROM refresh_schedules";

pub fn initialize(db:&Connection)->rusqlite::Result<()> {
    db.execute_batch("PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS refresh_schedules(
            subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
            interval_seconds INTEGER NOT NULL CHECK(interval_seconds>=360 AND interval_seconds<=604800),
            next_refresh_at INTEGER NOT NULL,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            last_attempted_at INTEGER,
            last_succeeded_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_refresh_schedules_due ON refresh_schedules(next_refresh_at);")
}

pub fn get(db:&Connection,id:&str)->rusqlite::Result<Option<Schedule>> {
    db.query_row(&format!("{SELECT} WHERE subscription_id=?1"),params![id],parse_row).optional()
}

pub fn set(db:&Connection,id:&str, interval:i64)->rusqlite::Result<Option<Schedule>> {
    if !(MIN_INTERVAL..=MAX_INTERVAL).contains(&interval) {
        return Err(rusqlite::Error::InvalidParameterName("interval_seconds".into()));
    }
    let changed=db.execute(
        "INSERT INTO refresh_schedules(subscription_id,interval_seconds,next_refresh_at)
         SELECT id,?2,?3 FROM subscriptions WHERE id=?1
         ON CONFLICT(subscription_id) DO UPDATE SET
         interval_seconds=excluded.interval_seconds,
         next_refresh_at=excluded.next_refresh_at,
         consecutive_failures=0",
        params![id,interval,now()+interval])?;
    if changed==0{return Ok(None);}
    get(db,id)
}

pub fn disable(db:&Connection,id:&str)->rusqlite::Result<bool>{
    Ok(db.execute("DELETE FROM refresh_schedules WHERE subscription_id=?1",params![id])?!=0)
}

/// Claim a bounded batch before network I/O, preventing repeated dispatch.
pub fn claim_due(db:&Connection,limit:usize)->rusqlite::Result<Vec<String>>{
    let now=now();
    let limit=limit.min(8) as i64;
    let mut stmt=db.prepare(
        "SELECT subscription_id FROM refresh_schedules
         WHERE next_refresh_at<=?1 ORDER BY next_refresh_at LIMIT ?2")?;
    let ids=stmt.query_map(params![now,limit],|r|r.get::<_,String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let mut claimed=Vec::new();
    for id in ids {
        let n=db.execute(
            "UPDATE refresh_schedules SET next_refresh_at=?3
             WHERE subscription_id=?1 AND next_refresh_at<=?2",
            params![id,now,now+120])?;
        if n!=0 {claimed.push(id);}
    }
    Ok(claimed)
}

pub fn complete(db:&Connection,id:&str,success:bool)->rusqlite::Result<()> {
    let Some(current)=get(db,id)? else {return Ok(());};
    let failures=if success {0}else{(current.consecutive_failures+1).min(20)};
    let multiplier=1_i64 << failures.min(4);
    let next=now()+current.interval_seconds.saturating_mul(multiplier);
    db.execute(
        "UPDATE refresh_schedules SET consecutive_failures=?2,next_refresh_at=?3,
         last_attempted_at=?4,last_succeeded_at=CASE WHEN ?5=1 THEN ?4
         ELSE last_succeeded_at END WHERE subscription_id=?1",
        params![id,failures,next,now(),if success{1}else{0}])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{self,SubscriptionInput};
    #[test]
    fn supports_minimum_interval_backoff_and_deletion() {
        let db=store::open(std::path::Path::new(":memory:")).unwrap();
        let s=store::create(&db,SubscriptionInput{
            name:"Example".into(),source_urls:vec!["https://example.org".into()],
            manual_yaml:String::new(),rules_text:String::new(),
        }).unwrap();
        assert!(set(&db,&s.id,100).is_err());
        assert!(set(&db,&s.id,MIN_INTERVAL).unwrap().is_some());
        complete(&db,&s.id,false).unwrap();
        let failed=get(&db,&s.id).unwrap().unwrap();
        assert_eq!(failed.consecutive_failures,1);
        assert!(failed.next_refresh_at>=now()+MIN_INTERVAL*2-2);
        complete(&db,&s.id,true).unwrap();
        assert_eq!(get(&db,&s.id).unwrap().unwrap().consecutive_failures,0);
        store::delete(&db,&s.id).unwrap();
        assert!(get(&db,&s.id).unwrap().is_none());
    }
}
