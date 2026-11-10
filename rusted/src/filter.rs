//! Bounded, linear-time include/exclude node-name regex filters.
//! Mirrors core SubBoost's 20-pattern/200-character limits and uses the Rust
//! regex engine to avoid catastrophic backtracking on router hardware.
use regex::RegexBuilder;
use rusqlite::{params,Connection,OptionalExtension};
use serde::{Deserialize,Serialize};
use serde_yaml::Value;

#[derive(Clone,Serialize,Deserialize,Debug,Default)]
#[serde(rename_all="camelCase")]
pub struct NodeNameFilter {
    #[serde(default)]
    pub enabled:bool,
    #[serde(default)]
    pub include_enabled:Option<bool>,
    #[serde(default)]
    pub exclude_enabled:Option<bool>,
    #[serde(default)]
    pub include_regexes:Vec<String>,
    #[serde(default)]
    pub exclude_regexes:Vec<String>,
}

pub fn initialize(db:&Connection)->rusqlite::Result<()>{
    db.execute_batch("CREATE TABLE IF NOT EXISTS node_name_filters(
        subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
        options_json TEXT NOT NULL
    );")
}
pub fn get(db:&Connection,id:&str)->rusqlite::Result<NodeNameFilter>{
    let value:Option<String>=db.query_row(
        "SELECT options_json FROM node_name_filters WHERE subscription_id=?1",
        params![id],|r|r.get(0)).optional()?;
    match value {
        Some(s)=>serde_json::from_str(&s).map_err(|e|
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))),
        None=>Ok(NodeNameFilter::default())
    }
}
pub fn put(db:&Connection,id:&str,value:&NodeNameFilter)->rusqlite::Result<bool>{
    let count=db.execute(
        "INSERT INTO node_name_filters(subscription_id,options_json)
         SELECT id,?2 FROM subscriptions WHERE id=?1
         ON CONFLICT(subscription_id) DO UPDATE SET options_json=excluded.options_json",
        params![id,serde_json::to_string(value).map_err(|e|
            rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?])?;
    Ok(count!=0)
}
pub fn delete(db:&Connection,id:&str)->rusqlite::Result<bool>{
    Ok(db.execute("DELETE FROM node_name_filters WHERE subscription_id=?1",params![id])?!=0)
}

pub fn validate(options:&NodeNameFilter)->Result<(),String>{
    for (name,patterns) in [("include", &options.include_regexes),
                            ("exclude", &options.exclude_regexes)]{
        if patterns.len()>20{return Err(format!("{name}: maximum 20 regexes"));}
        for (i,expr) in patterns.iter().enumerate(){
            if expr.chars().count()>200 {
                return Err(format!("{name}: regex {} exceeds 200 characters",i+1));
            }
            if expr.is_empty() {continue;}
            RegexBuilder::new(expr).case_insensitive(true)
                .size_limit(1024*1024)
                .build().map_err(|e|format!("{name}: invalid regex: {e}"))?;
        }
    }
    Ok(())
}
pub fn apply(nodes:Vec<Value>,options:&NodeNameFilter)->Result<Vec<Value>,String>{
    if !options.enabled{return Ok(nodes);}
    validate(options)?;
    let compile=|expr:&str|RegexBuilder::new(expr)
        .case_insensitive(true).size_limit(1024*1024).build()
        .map_err(|e|e.to_string());
    let included=if options.include_enabled!=Some(false) {
        options.include_regexes.iter().filter(|s|!s.is_empty())
            .map(|s|compile(s)).collect::<Result<Vec<_>,_>>()?
    }else{Vec::new()};
    let excluded=if options.exclude_enabled!=Some(false){
        options.exclude_regexes.iter().filter(|s|!s.is_empty())
            .map(|s|compile(s)).collect::<Result<Vec<_>,_>>()?
    }else{Vec::new()};
    let count=nodes.len();
    let filtered:Vec<_>=nodes.into_iter().filter(|node|{
        let name=node["name"].as_str().unwrap_or("");
        (included.is_empty()||included.iter().any(|re|re.is_match(name))) &&
        !excluded.iter().any(|re|re.is_match(name))
    }).collect();
    if filtered.is_empty() && count>0{
        return Err("Node-name filters excluded every proxy".into());
    }
    Ok(filtered)
}
#[cfg(test)]
mod tests{
    use super::*;
    use crate::store::{self,SubscriptionInput};
    #[test]
    fn filters_names_case_insensitively_without_redos(){
        let config=NodeNameFilter{
            enabled:true,include_enabled:None,exclude_enabled:None,
            include_regexes:vec!["us|jp".into()],
            exclude_regexes:vec!["expired".into()]
        };
        let values:Vec<Value>=serde_yaml::from_str(
            "- {name: US-1}\n- {name: jp-expired}\n- {name: EU}\n").unwrap();
        let filtered=apply(values,&config).unwrap();
        assert_eq!(filtered.len(),1);
        assert_eq!(filtered[0]["name"].as_str(),Some("US-1"));
        assert!(validate(&NodeNameFilter{include_regexes:vec!["(".into()],..config.clone()}).is_err());
        assert!(validate(&NodeNameFilter{include_regexes:vec!["a".repeat(201)],..config.clone()}).is_err());
    }
    #[test]
    fn sqlite_options_are_preserved_and_deleted_with_subscription(){
        let db=store::open(std::path::Path::new(":memory:")).unwrap();
        let sub=store::create(&db,SubscriptionInput{
            name:"Example".into(),source_urls:Vec::new(),
            manual_yaml:String::new(),rules_text:String::new()}).unwrap();
        let opts=NodeNameFilter{enabled:true,exclude_regexes:vec!["test".into()],..Default::default()};
        assert!(put(&db,&sub.id,&opts).unwrap());
        assert_eq!(get(&db,&sub.id).unwrap().exclude_regexes,vec!["test"]);
        store::delete(&db,&sub.id).unwrap();
        assert!(!get(&db,&sub.id).unwrap().enabled);
    }
}
