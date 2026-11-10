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

#[cfg(test)]
mod tests {
    use super::*;
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
