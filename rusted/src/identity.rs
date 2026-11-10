//! Upstream-compatible stable proxy identity. Name changes and internal
//! metadata do not affect a node's content key; secrets are never logged.
use serde::{Deserialize,Serialize};
use serde_json::{Map,Value};

#[derive(Clone,Copy,Default,Debug,Deserialize,Serialize)]
#[serde(rename_all="camelCase")]
pub struct NodeContentKeyOptions {
    #[serde(default)] pub ignore_server:bool,
    #[serde(default)] pub ignore_port:bool,
    #[serde(default)] pub ignore_sni:bool,
    #[serde(default)] pub ignore_servername:bool,
}

fn normalize(value:&Value,top:bool,opts:NodeContentKeyOptions)->Value {
    match value {
        Value::Object(fields)=>{
            let mut sorted=Map::new();
            for (name,value) in fields {
                if name.starts_with('_') || top && (
                    name=="name" ||
                    opts.ignore_server && name=="server" ||
                    opts.ignore_port && name=="port" ||
                    opts.ignore_sni && name=="sni" ||
                    opts.ignore_servername && name=="servername"
                ){continue;}
                sorted.insert(name.clone(),normalize(value,false,opts));
            }
            Value::Object(sorted)
        },
        Value::Array(items)=>Value::Array(items.iter()
            .map(|v|normalize(v,false,opts)).collect()),
        scalar=>scalar.clone(),
    }
}

pub fn content_key(node:&Value,opts:NodeContentKeyOptions)->String {
    serde_json::to_string(&normalize(node,true,opts))
        .expect("Valid serde_json::Value serializes successfully")
}
pub fn scoped_key(scope:&str,node:&Value)->String {
    format!("{}\0{}",scope.trim(),content_key(node,NodeContentKeyOptions::default()))
}

/// Opaque identifiers derived from the scoped content key. Never expose
/// credentials or raw canonical identity strings through the API.
pub fn hash(scope:&str,node:&serde_yaml::Value)->Result<String,String> {
    use sha2::{Digest,Sha256};
    let json=serde_json::to_value(node).map_err(|e|e.to_string())?;
    let digest=Sha256::digest(scoped_key(scope,&json).as_bytes());
    Ok(digest.iter().map(|byte|format!("{byte:02x}")).collect())
}

pub fn initialize(db:&rusqlite::Connection)->rusqlite::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS subscription_node_aliases(
        subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
        identity_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        PRIMARY KEY(subscription_id, identity_hash)
    );")
}

pub fn aliases(db:&rusqlite::Connection,profile_id:&str)
    ->rusqlite::Result<std::collections::HashMap<String,String>> {
    let mut query=db.prepare("SELECT identity_hash,display_name FROM subscription_node_aliases
        WHERE subscription_id=?1 ORDER BY identity_hash")?;
    let rows=query.query_map([profile_id],|row|Ok((
        row.get::<_,String>(0)?,row.get::<_,String>(1)?
    )))?;
    rows.collect()
}

pub fn validate_alias(key:&str,name:&str)->Result<(),String>{
    if key.len()!=64||!key.bytes().all(|c|c.is_ascii_hexdigit()){
        return Err("Node identity must be a SHA-256 hex key".into());
    }
    if name.trim().is_empty()||name.len()>128{
        return Err("Node alias name must be between 1 and 128 bytes".into());
    }
    Ok(())
}

pub fn put_alias(db:&rusqlite::Connection,id:&str,key:&str,name:&str)
    ->rusqlite::Result<bool> {
    Ok(db.execute("INSERT INTO subscription_node_aliases(
        subscription_id,identity_hash,display_name)
        SELECT id,?2,?3 FROM subscriptions WHERE id=?1
        ON CONFLICT(subscription_id,identity_hash) DO UPDATE SET
        display_name=excluded.display_name",
        rusqlite::params![id,key,name.trim()])?!=0)
}

pub fn delete_alias(db:&rusqlite::Connection,id:&str,key:&str)
    ->rusqlite::Result<bool>{
    Ok(db.execute("DELETE FROM subscription_node_aliases
        WHERE subscription_id=?1 AND identity_hash=?2",
        rusqlite::params![id,key])?!=0)
}

pub fn apply(nodes:Vec<serde_yaml::Value>,id:&str,
    aliases:&std::collections::HashMap<String,String>)
    ->Result<Vec<serde_yaml::Value>,String>{
    if aliases.is_empty(){return Ok(nodes);}
    let mut out=Vec::with_capacity(nodes.len());
    for mut node in nodes {
        let key=hash(id,&node)?;
        if let Some(name)=aliases.get(&key) {
            let map=node.as_mapping_mut().ok_or("Proxy node must be a mapping")?;
            map.insert(serde_yaml::Value::String("name".into()),
                serde_yaml::Value::String(name.clone()));
        }
        out.push(node);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_survive_node_renames_and_are_scoped_per_profile(){
        let db=crate::store::open(std::path::Path::new(":memory:")).unwrap();
        let profile=crate::store::create(&db,crate::store::SubscriptionInput{
            name:"test".into(),source_urls:vec![],manual_yaml:String::new(),
            rules_text:String::new()
        }).unwrap();
        let node:serde_yaml::Value=serde_yaml::from_str(
            "{name: Original, type: ss, server: example.org, port: 443, cipher: aes-128-gcm, password: secret}"
        ).unwrap();
        let key=hash(&profile.id,&node).unwrap();
        validate_alias(&key,"Changed").unwrap();
        assert!(put_alias(&db,&profile.id,&key,"Changed").unwrap());
        let result=apply(vec![node.clone()],&profile.id,
            &aliases(&db,&profile.id).unwrap()).unwrap();
        assert_eq!(result[0]["name"].as_str(),Some("Changed"));
        assert_eq!(hash(&profile.id,&result[0]).unwrap(),key);
        assert_ne!(hash("different-profile",&node).unwrap(),key);
        assert!(delete_alias(&db,&profile.id,&key).unwrap());
        assert!(aliases(&db,&profile.id).unwrap().is_empty());
    }
    #[test]
    fn shared_upstream_node_identity_contract() {
        let fixtures:Value=serde_json::from_str(
            include_str!("../data/node-identity-fixtures.json")).unwrap();
        for fixture in fixtures.as_array().unwrap() {
            let node=&fixture["node"];
            let opts:NodeContentKeyOptions=serde_json::from_value(
                fixture["opts"].clone()).unwrap();
            let actual=content_key(node,opts);
            assert_eq!(actual,fixture["expected"].as_str().unwrap(),
                "Node identity mismatch: {}",fixture["id"]);
        }
    }
    #[test]
    fn name_and_internal_metadata_do_not_change_identity() {
        let first=serde_json::json!({
            "type":"vless","name":"Before","server":"edge.example.org",
            "port":443,"uuid":"demo",
            "reality-opts":{"public-key":"abc","_spider-x":"/old"},
            "_meta":{"source":"one"}
        });
        let second=serde_json::json!({
            "type":"vless","name":"After","server":"edge.example.org",
            "port":443,"uuid":"demo",
            "reality-opts":{"public-key":"abc","_spider-x":"/new"},
            "_meta":{"source":"two"}
        });
        assert_eq!(content_key(&first,NodeContentKeyOptions::default()),
            content_key(&second,NodeContentKeyOptions::default()));
        assert_ne!(scoped_key("upstream-A",&first),scoped_key("upstream-B",&first));
    }
    #[test]
    fn optional_ignores_are_explicit_and_endpoint_sensitive_by_default() {
        let first=serde_json::json!({"name":"A","type":"ss","server":"a","port":80,
            "sni":"a","servername":"a","password":"token"});
        let second=serde_json::json!({"name":"B","type":"ss","server":"b","port":81,
            "sni":"b","servername":"b","password":"token"});
        assert_ne!(content_key(&first,Default::default()),
            content_key(&second,Default::default()));
        let opts=NodeContentKeyOptions{ignore_server:true,ignore_port:true,
            ignore_sni:true,ignore_servername:true};
        assert_eq!(content_key(&first,opts),content_key(&second,opts));
    }
}
