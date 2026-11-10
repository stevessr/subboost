//! Upstream SubBoost group/module catalog and per-profile selection.
//! The JSON is generated from packages/core/src/generator/proxy-group-modules.ts
//! at development time; no JavaScript runtime is needed on OpenWrt.
use rusqlite::{params,Connection,OptionalExtension};
use serde::{Deserialize,Serialize};
use std::sync::OnceLock;

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ModuleRule {
    pub id:String,
    pub name:String,
    pub behavior:String,
    pub path:String,
    #[serde(rename="noResolve",default)]
    pub no_resolve:bool,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Module {
    pub id:String,
    pub name:String,
    pub emoji:String,
    pub category:String,
    pub description:String,
    #[serde(rename="groupType")]
    pub group_type:String,
    pub rules:Vec<ModuleRule>,
}
static ALL:OnceLock<Vec<Module>>=OnceLock::new();
pub fn all()->&'static [Module] {
    ALL.get_or_init(||serde_json::from_str(include_str!("../data/proxy-group-modules.json"))
        .expect("Embedded proxy group registry is valid")).as_slice()
}
const DEFAULT_MINIMAL:&[&str]=&["select","auto","ad","private","cn","global","final"];
const DEFAULT_STANDARD:&[&str]=&[
    "select","auto","ad","private","cn","global","ai","youtube",
    "google","microsoft","apple","github","telegram","final"];
pub fn preset(name:&str)->Option<Vec<String>>{
    match name{
        "minimal"=>Some(DEFAULT_MINIMAL.iter().map(|s|s.to_string()).collect()),
        "standard"=>Some(DEFAULT_STANDARD.iter().map(|s|s.to_string()).collect()),
        "full"=>Some(all().iter().filter(|m|
            !matches!(m.id.as_str(),"adult"|"gemini"|"google-scholar"))
            .map(|m|m.id.clone()).collect()),
        _=>None,
    }
}
pub fn validate(ids:&[String])->Result<(),String>{
    if ids.len()>all().len(){return Err("Too many policy modules".into());}
    let mut seen=std::collections::HashSet::<&str>::new();
    for id in ids{
        if !all().iter().any(|m|m.id==*id){
            return Err(format!("Unknown policy module: {id}"));
        }
        if !seen.insert(id.as_str()){
            return Err(format!("Duplicate policy module: {id}"));
        }
    }
    Ok(())
}
pub fn initialize(db:&Connection)->rusqlite::Result<()>{
    db.execute_batch("CREATE TABLE IF NOT EXISTS subscription_modules(
       subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
       modules_json TEXT NOT NULL DEFAULT '[]'
    );")
}
pub fn get(db:&Connection,id:&str)->rusqlite::Result<Vec<String>>{
    let stored:Option<String>=db.query_row(
        "SELECT modules_json FROM subscription_modules WHERE subscription_id=?1",
        params![id],|r|r.get(0)).optional()?;
    stored.map(|v|serde_json::from_str(&v).map_err(|e|
        rusqlite::Error::ToSqlConversionFailure(Box::new(e))))
        .transpose().map(|v|v.unwrap_or_default())
}
pub fn put(db:&Connection,id:&str,ids:&[String])->rusqlite::Result<bool>{
    let json=serde_json::to_string(ids)
        .map_err(|e|rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    Ok(db.execute(
        "INSERT INTO subscription_modules(subscription_id,modules_json)
         SELECT id,?2 FROM subscriptions WHERE id=?1
         ON CONFLICT(subscription_id) DO UPDATE SET
         modules_json=excluded.modules_json",params![id,json])?!=0)
}
/// Maintain the original rule priority, not the UI selection order.
const ORDER:&[&str]=&["ad","private","gemini","ai","cn","youtube",
    "google-scholar","education","cloud","google","telegram","github",
    "microsoft","apple","twitter","meta","discord","social-other",
    "netflix","disney","streaming-west","streaming-asia",
    "steam","gaming-pc","gaming-console","dev-tools","storage",
    "payment","crypto","news","shopping","adult","global"];
pub fn ordered<'a>(ids:&'a [String])->Vec<&'static Module>{
    let mut mods:Vec<_>=all().iter().filter(|m|ids.contains(&m.id)).collect();
    mods.sort_by_key(|m|ORDER.iter().position(|p|*p==m.id)
        .unwrap_or(ORDER.len()));
    mods
}
#[cfg(test)]
mod tests{
    use super::*;
    use crate::store::{self,SubscriptionInput};
    #[test]
    fn all_upstream_modules_are_embedded(){
        assert_eq!(all().len(),36);
        assert_eq!(all().iter().map(|m|m.rules.len()).sum::<usize>(),94);
        for m in all(){assert!(!m.name.is_empty());}
        assert_eq!(preset("minimal").unwrap().len(),7);
        assert_eq!(preset("standard").unwrap().len(),14);
        assert!(!preset("full").unwrap().contains(&"adult".to_owned()));
    }
    #[test]
    fn profile_module_selection_is_persistent(){
        let db=store::open(std::path::Path::new(":memory:")).unwrap();
        let p=store::create(&db,SubscriptionInput{
            name:"Test".into(),source_urls:vec![],manual_yaml:String::new(),
            rules_text:String::new()}).unwrap();
        assert!(get(&db,&p.id).unwrap().is_empty());
        let ids=preset("minimal").unwrap();
        validate(&ids).unwrap();
        assert!(put(&db,&p.id,&ids).unwrap());
        assert_eq!(get(&db,&p.id).unwrap(),ids);
        assert!(validate(&["nonexistent".into()]).is_err());
        store::delete(&db,&p.id).unwrap();
        assert!(get(&db,&p.id).unwrap().is_empty());
    }
}
