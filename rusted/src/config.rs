//! Safe generated Clash configuration with clash-rs / Nikki RS adaptation.
use crate::{store::Subscription,modules};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

fn key(s: &str) -> Value { Value::String(s.to_string()) }
fn get<'a>(map: &'a Mapping, k: &str) -> Option<&'a Value> { map.get(key(k)) }
fn get_mut<'a>(map: &'a mut Mapping, k: &str) -> Option<&'a mut Value> { map.get_mut(key(k)) }
fn set(map: &mut Mapping, k: &str, value: Value) { map.insert(key(k), value); }

pub fn namespace(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn id(s: &str) -> String {
    let cleaned: String = s.chars().map(|c| {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }
    }).take(48).collect();
    if cleaned.is_empty() { "unnamed".into() } else { cleaned }
}

fn geo(map: &mut Mapping, rule: &str, path_field: &str, url_field: &str,
       fallback_file: &str, download_url: &str) {
    let uses = get(map,"rules").and_then(Value::as_sequence).map(|seq| seq.iter().any(
        |v| v.as_str().map(|s| s.to_ascii_uppercase().starts_with(&format!("{rule},")))
            .unwrap_or(false))).unwrap_or(false);
    if uses {
        if get(map,path_field).is_none() { set(map,path_field,key(fallback_file)); }
        if get(map,url_field).is_none() { set(map,url_field,key(download_url)); }
    }
}

fn rename_ruleset_matcher(raw: &str, names: &HashMap<String, String>) -> String {
    if let Some(name) = raw.strip_prefix("rule-set:") {
        if let Some(replacement) = names.get(name) {
            return format!("rule-set:{replacement}");
        }
    }
    raw.to_owned()
}

fn rewrite_dns_names(config: &mut Mapping, names: &HashMap<String, String>) {
    if let Some(dns) = get_mut(config,"dns").and_then(Value::as_mapping_mut) {
        if let Some(policy) = get_mut(dns,"nameserver-policy").and_then(Value::as_mapping_mut) {
            let original = std::mem::take(policy);
            for (matcher, value) in original {
                let label = matcher.as_str()
                    .map(|s| rename_ruleset_matcher(s,names))
                    .unwrap_or_else(|| matcher.as_str().unwrap_or("").to_owned());
                policy.insert(key(&label),value);
            }
        }
        if let Some(filters) = get_mut(dns,"fake-ip-filter").and_then(Value::as_sequence_mut) {
            for matcher in filters {
                if let Some(name) = matcher.as_str() {
                    *matcher = key(&rename_ruleset_matcher(name,names));
                }
            }
        }
    }
    if let Some(dns2) = get_mut(config,"dns2").and_then(Value::as_mapping_mut) {
        if let Some(rules) = get_mut(dns2,"rules").and_then(Value::as_sequence_mut) {
            for rule in rules {
                if let Some(map) = rule.as_mapping_mut() {
                    if let Some(ids) = get_mut(map,"rule-set").and_then(Value::as_sequence_mut) {
                        for id in ids {
                            if let Some(original) = id.as_str() {
                                if let Some(replacement) = names.get(original) {
                                    *id = key(replacement);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn has_geo_dns_matcher(config: &Mapping, prefix: &str) -> bool {
    let Some(dns) = get(config,"dns").and_then(Value::as_mapping) else { return false; };
    if let Some(policy) = get(dns,"nameserver-policy").and_then(Value::as_mapping) {
        if policy.keys().any(|s| s.as_str().map(|name| name.starts_with(prefix))
            .unwrap_or(false)) { return true; }
    }
    if prefix == "geosite:" {
        return get(dns,"fallback-filter").and_then(Value::as_mapping)
            .and_then(|m| get(m,"geosite"))
            .and_then(Value::as_sequence).map(|list| !list.is_empty()).unwrap_or(false);
    }
    false
}

fn adapt_clash_rs(config: &mut Mapping, token: &str) {
    for field in ["geodata-mode","geo-auto-update","geodata-loader",
                  "geo-update-interval","geox-url","tun","ebpf","mixed-port",
                  "port","socks-port","redir-port","tproxy-port","allow-lan",
                  "bind-address","external-controller","secret","external-ui",
                  "external-ui-url"] {
        config.remove(key(field));
    }
    if let Some(groups) = get_mut(config,"proxy-groups").and_then(Value::as_sequence_mut) {
        for group in groups {
            if let Some(map) = group.as_mapping_mut() {
                if get(map,"type").and_then(Value::as_str) == Some("load-balance") &&
                   get(map,"strategy").and_then(Value::as_str) == Some("sticky-sessions") {
                    set(map,"strategy", key("sticky-session"));
                }
            }
        }
    }
    let mut renamed = HashMap::<String,String>::new();
    let cache_ns = namespace(token);
    if let Some(providers) = get_mut(config,"rule-providers").and_then(Value::as_mapping_mut) {
        let original = std::mem::take(providers);
        let mut entries:Vec<_>=original.into_iter().collect();
        entries.sort_by(|a,b|a.0.as_str().cmp(&b.0.as_str()));
        let mut used = HashSet::<String>::new();
        for (source_name, mut item) in entries {
            let old = source_name.as_str().unwrap_or("").to_owned();
            let stem = format!("subboost-{}", id(&old));
            let mut new_name = stem.clone();
            let mut sequence = 2;
            while !used.insert(new_name.clone()) {
                new_name = format!("{stem}-{sequence}");
                sequence += 1;
            }
            if let Some(provider) = item.as_mapping_mut() {
                if get(provider,"type").and_then(Value::as_str) == Some("http") {
                    let extension = match get(provider,"format").and_then(Value::as_str) {
                        Some("mrs") => "mrs", Some("text") => "txt", _ => "yaml",
                    };
                    set(provider,"path",key(&format!(
                        "/etc/nikki-rs/providers/rule/subboost-{cache_ns}-{}.{}",
                        new_name.trim_start_matches("subboost-"), extension)));
                }
            }
            renamed.insert(old,new_name.clone());
            providers.insert(key(&new_name), item);
        }
    }
    if let Some(rules) = get_mut(config,"rules").and_then(Value::as_sequence_mut) {
        for rule in rules {
            if let Some(s) = rule.as_str() {
                if let Some(rest) = s.strip_prefix("RULE-SET,") {
                    if let Some((name, tail)) = rest.split_once(',') {
                        if let Some(new_name) = renamed.get(name) {
                            *rule = key(&format!("RULE-SET,{new_name},{tail}"));
                        }
                    }
                }
            }
        }
    }
    rewrite_dns_names(config, &renamed);
    if let Some(providers) = get_mut(config,"proxy-providers").and_then(Value::as_mapping_mut) {
        let original=std::mem::take(providers);
        let mut entries:Vec<_>=original.into_iter().collect();
        entries.sort_by(|a,b|a.0.as_str().cmp(&b.0.as_str()));
        let mut used=HashSet::<String>::new();
        for (name,mut value) in entries {
            let mut basename=format!("subboost-{}",id(name.as_str().unwrap_or("unnamed")));
            let stem=basename.clone();
            let mut suffix=2;
            while !used.insert(basename.clone()){
                basename=format!("{stem}-{suffix}");
                suffix+=1;
            }
            if let Some(provider)=value.as_mapping_mut() {
                if get(provider,"type").and_then(Value::as_str)==Some("http"){
                    set(provider,"path",key(&format!(
                        "/etc/nikki-rs/providers/proxy/subboost-{cache_ns}-{}.yaml",
                        basename.trim_start_matches("subboost-"))));
                }
            }
            providers.insert(name,value);
        }
    }
    geo(config,"GEOSITE","geosite","geosite-download-url","geosite.dat",
        "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-geodata/geosite-lite.dat");
    geo(config,"GEOIP","mmdb","mmdb-download-url","Country.mmdb",
        "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-geodata/Country.mmdb");
    if has_geo_dns_matcher(config,"geosite:") {
        if get(config,"geosite").is_none() { set(config,"geosite", key("geosite.dat")); }
        if get(config,"geosite-download-url").is_none() {
            set(config,"geosite-download-url",key(
                "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-geodata/geosite-lite.dat"));
        }
    }
    geo(config,"IP-ASN","asn-mmdb","asn-mmdb-download-url","Country-ASN.mmdb",
        "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-geodata/Country-ASN.mmdb");
}

/// Add the canonical upstream modules as opt-in policy groups and rule-set
/// providers. Disabled for existing profiles to keep v0.1 configuration
/// behavior unchanged. The source catalog contains 36 modules / 94 rules.
fn add_policy_modules(config:&mut Mapping,enabled:&[String])->Result<(),String>{
    modules::validate(enabled)?;
    if enabled.is_empty(){return Ok(());}
    let ordered=modules::ordered(enabled);
    let proxies=config.get(key("proxies")).and_then(Value::as_sequence)
        .ok_or("No proxies for enabled modules")?;
    let names:Vec<Value>=proxies.iter().filter_map(|p|p["name"].as_str().map(key)).collect();
    let mut groups=config.get(key("proxy-groups"))
        .and_then(Value::as_sequence).cloned().unwrap_or_default();
    let mut group_names:HashSet<String>=groups.iter()
        .filter_map(|v|v["name"].as_str().map(str::to_owned)).collect();
    let mut providers=config.get(key("rule-providers"))
        .and_then(Value::as_mapping).cloned().unwrap_or_default();
    let mut generated=Vec::<Value>::new();
    let mut used_rules=HashSet::<String>::new();
    for module in ordered{
        if group_names.insert(module.name.clone()){
            let primary=match module.group_type.as_str(){
                "reject-first"=>vec![key("REJECT"),key("DIRECT"),key("Proxy")],
                "direct-first"=>vec![key("DIRECT"),key("Proxy")],
                "select" if module.id=="select"=>{
                    let mut entries=vec![key("Auto")];
                    entries.extend(names.iter().cloned());
                    entries.push(key("DIRECT"));
                    entries
                },
                _=>vec![key("Proxy"),key("DIRECT")]
            };
            let group=if matches!(module.group_type.as_str(),"url-test"|"fallback"|"load-balance"){
                serde_yaml::to_value(serde_json::json!({
                    "name":module.name,"type":module.group_type,
                    "proxies":names,"url":"https://www.gstatic.com/generate_204",
                    "interval":300
                })).map_err(|e|e.to_string())?
            }else{
                serde_yaml::to_value(serde_json::json!({
                    "name":module.name,"type":"select","proxies":primary
                })).map_err(|e|e.to_string())?
            };
            groups.push(group);
        }
        for rule in &module.rules{
            if !used_rules.insert(rule.id.clone()){continue;}
            if !providers.contains_key(key(&rule.id)){
                let url=format!(
                    "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/{}",
                    rule.path);
                providers.insert(key(&rule.id),
                    serde_yaml::to_value(serde_json::json!({
                        "type":"http","format":"mrs","behavior":rule.behavior,
                        "url":url,"path":format!("./rules/{}",rule.path),
                        "interval":86400
                    })).map_err(|e|e.to_string())?);
            }
            let mut text=format!("RULE-SET,{},{name}",rule.id,name=module.name);
            if rule.no_resolve{text.push_str(",no-resolve");}
            generated.push(key(&text));
        }
    }
    let current=config.get(key("rules")).and_then(Value::as_sequence)
        .cloned().unwrap_or_default();
    let mut trailing=Vec::<Value>::new();
    for rule in current{
        if rule.as_str().map(|v|v.starts_with("MATCH,")).unwrap_or(false){
            trailing.push(rule);
        }else{generated.push(rule);}
    }
    generated.extend(trailing);
    set(config,"proxy-groups",Value::Sequence(groups));
    set(config,"rule-providers",Value::Mapping(providers));
    set(config,"rules",Value::Sequence(generated));
    Ok(())
}

pub fn generate(subscription: &Subscription, target: &str) -> Result<String, String> {
    generate_filtered(subscription,target,&crate::filter::NodeNameFilter::default())
}
pub fn generate_filtered(subscription: &Subscription, target: &str,
    name_filter:&crate::filter::NodeNameFilter) -> Result<String,String> {
    generate_with_modules(subscription,target,name_filter,&[])
}
pub fn generate_with_modules(subscription: &Subscription, target: &str,
    name_filter:&crate::filter::NodeNameFilter, enabled_modules:&[String]
) -> Result<String,String> {
    if !matches!(target,"mihomo"|"clash-rs"|"nikki-rs") {
        return Err("Unsupported target (mihomo or clash-rs)".into());
    }
    let mut manual = if subscription.manual_yaml.trim().is_empty() { Mapping::new() }
        else {
            let input: Value = serde_yaml::from_str(&subscription.manual_yaml)
                .map_err(|e| format!("Manual YAML: {e}"))?;
            input.as_mapping().cloned().ok_or("Manual YAML must be a mapping")?
        };
    let mut proxies = get(&manual,"proxies").and_then(Value::as_sequence)
        .cloned().unwrap_or_default();
    if !subscription.nodes_yaml.trim().is_empty() {
        let cached = serde_yaml::from_str::<Vec<Value>>(&subscription.nodes_yaml)
            .map_err(|e| format!("Cached proxies: {e}"))?;
        proxies.extend(cached);
    }
    let proxies = crate::parser::validate_nodes(proxies)?;
    let proxies = crate::filter::apply(proxies,name_filter)?;
    // Nikki RS ships clash-rs-minimal, not standard/plus.
    // A valid link does not imply that the runtime implements its protocol.
    if target != "mihomo" {
        for proxy in &proxies {
            match proxy["type"].as_str().unwrap_or("") {
                "ssr" | "hysteria" | "snell" | "wireguard" | "ssh" |
                "shadowquic" | "tailscale" | "tor" => {
                    return Err(format!(
                        "clash-rs-minimal cannot run {} proxies; use Mihomo or remove this node",
                        proxy["type"].as_str().unwrap_or("unknown")
                    ));
                }
                _ => {}
            }
        }
    }
    if proxies.is_empty() { return Err("No proxy nodes: import/refresh a subscription first".into()); }
    let names: Vec<Value> = proxies.iter().filter_map(|p| p["name"].as_str().map(key)).collect();
    set(&mut manual,"proxies",Value::Sequence(proxies));
    let mut selector = vec![key("Auto")];
    selector.extend(names.clone());
    selector.push(key("DIRECT"));
    let default_proxy=serde_yaml::to_value(serde_json::json!({
        "name":"Proxy","type":"select","proxies":selector
    })).map_err(|e|e.to_string())?;
    let default_auto=serde_yaml::to_value(serde_json::json!({
        "name":"Auto","type":"url-test","proxies":names,
        "url":"https://www.gstatic.com/generate_204","interval":300
    })).map_err(|e|e.to_string())?;
    // Preserve explicit user-defined Proxy / Auto policy groups, including
    // load balancing, fallback, provider references and health checks.
    let existing=get(&manual,"proxy-groups").and_then(Value::as_sequence)
        .cloned().unwrap_or_default();
    let mut seen=HashSet::<String>::new();
    for group in &existing {
        let name=group["name"].as_str().unwrap_or("");
        if name.is_empty() {return Err("Proxy-group name must not be empty".into());}
        if !seen.insert(name.to_owned()){
            return Err(format!("Duplicate proxy-group name: {name}"));
        }
    }
    let mut groups=Vec::new();
    if !seen.contains("Proxy"){groups.push(default_proxy);}
    if !seen.contains("Auto"){groups.push(default_auto);}
    groups.extend(existing);
    set(&mut manual,"proxy-groups",Value::Sequence(groups));
    let rules: Vec<Value> = subscription.rules_text.lines()
        .map(str::trim).filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(key).collect();
    let mut rules = if rules.is_empty() {
        get(&manual,"rules").and_then(Value::as_sequence).cloned().unwrap_or_default()
    } else { rules };
    // Ensure a safe fallback without changing user-supplied custom rules.
    if !rules.iter().any(|v| v.as_str().map(|s| s.starts_with("MATCH,")).unwrap_or(false)) {
        rules.push(key("MATCH,Proxy"));
    }
    set(&mut manual,"rules",Value::Sequence(rules));
    set(&mut manual,"mode", key("rule"));
    add_policy_modules(&mut manual,enabled_modules)?;
    if target != "mihomo" { adapt_clash_rs(&mut manual, &subscription.token); }
    serde_yaml::to_string(&Value::Mapping(manual)).map_err(|e|e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn subscription() -> Subscription {
        Subscription {id:"one".into(),name:"Demo".into(),token:"token".into(),
            source_urls:vec![], manual_yaml: "rule-providers:\n  cn:\n    type: http\n    behavior: domain\n    format: mrs\n    url: https://example.org/cn.mrs\n".into(),
            rules_text:"RULE-SET,cn,DIRECT\n".into(),
            nodes_yaml:"- {name: Node, type: ss, server: example.org, port: 8388, cipher: aes-128-gcm, password: pwd}\n".into(),
            last_error:String::new(),updated_at:0,revision:0}
    }
    #[test]
    fn clash_rs_provider_path_and_rules_are_namespaced() {
        let sub = subscription();
        let yaml = generate(&sub,"clash-rs").unwrap();
        let parsed: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed["rules"][0].as_str(),Some("RULE-SET,subboost-cn,DIRECT"));
        let path = parsed["rule-providers"]["subboost-cn"]["path"].as_str().unwrap();
        assert!(path.starts_with("/etc/nikki-rs/providers/rule/subboost-"));
        assert!(path.ends_with("-cn.mrs"));
        let default = generate(&sub,"mihomo").unwrap();
        assert!(default.contains("RULE-SET,cn,DIRECT"));
    }
    #[test]
    fn bad_target_and_missing_nodes_fail() {
        assert!(generate(&subscription(),"unknown").is_err());
        let mut sub=subscription();sub.nodes_yaml.clear();
        assert!(generate(&sub,"clash-rs").is_err());
    }
    #[test]
    fn dns_and_dns2_ruleset_labels_are_rewritten() {
        let mut sub = subscription();
        sub.manual_yaml = r#"
rule-providers:
  cn: {type: http, behavior: domain, format: mrs, url: "https://example.org/cn.mrs"}
dns:
  nameserver-policy:
    "rule-set:cn": ["https://1.1.1.1/dns-query"]
    "geosite:private": ["https://223.5.5.5/dns-query"]
  fake-ip-filter:
    - "rule-set:cn"
dns2:
  rules:
    - rule-set: [cn]
"#.to_owned();
        let yaml = generate(&sub,"clash-rs").unwrap();
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        assert!(doc["dns"]["nameserver-policy"]["rule-set:subboost-cn"].is_sequence());
        assert_eq!(doc["dns"]["fake-ip-filter"][0].as_str(),Some("rule-set:subboost-cn"));
        assert_eq!(doc["dns2"]["rules"][0]["rule-set"][0].as_str(),Some("subboost-cn"));
        assert_eq!(doc["geosite"].as_str(),Some("geosite.dat"));
    }

    #[test]
    fn minimal_runtime_rejects_unsupported_proxy_protocols() {
        let mut sub=subscription();
        sub.manual_yaml.clear();
        for kind in ["ssr","wireguard","snell"]{
            sub.nodes_yaml=format!("- {{name: Example, type: {kind}, server: host.example, port: 443}}\n");
            let err=generate(&sub,"clash-rs").unwrap_err();
            assert!(err.contains("clash-rs-minimal"),"{err}");
            assert!(generate(&sub,"mihomo").is_ok());
        }
    }
    #[test]
    fn colliding_rule_provider_names_never_share_a_cache_file() {
        let mut sub=subscription();
        sub.manual_yaml=r#"
rule-providers:
  "us/east": {type: http, behavior: domain, format: mrs, url: "https://example.org/a.mrs"}
  "us_east": {type: http, behavior: domain, format: mrs, url: "https://example.org/b.mrs"}
proxy-providers:
  "HK/A": {type: http, url: "https://example.org/a"}
  "HK_A": {type: http, url: "https://example.org/b"}
"#.to_owned();
        let v:Value=serde_yaml::from_str(&generate(&sub,"clash-rs").unwrap()).unwrap();
        let rules=v["rule-providers"].as_mapping().unwrap();
        let mut paths=std::collections::HashSet::new();
        for (_,p) in rules{
            assert!(paths.insert(p["path"].as_str().unwrap().to_owned()));
        }
        let proxies=v["proxy-providers"].as_mapping().unwrap();
        paths.clear();
        for (_,p) in proxies{
            assert!(paths.insert(p["path"].as_str().unwrap().to_owned()));
        }
    }

    #[test]
    fn opt_in_full_upstream_modules_generate_policy_groups_and_mrs_paths() {
        let sub=subscription();
        let ids=modules::preset("standard").unwrap();
        let generated=generate_with_modules(&sub,"clash-rs",
            &crate::filter::NodeNameFilter::default(),&ids).unwrap();
        let v:Value=serde_yaml::from_str(&generated).unwrap();
        let groups=v["proxy-groups"].as_sequence().unwrap();
        for expected in ["🤖 AI 服务","📹 油管视频","🛑 广告拦截",
                         "🚀 节点选择","⚡ 自动选择"]{
            assert!(groups.iter().any(|g|g["name"].as_str()==Some(expected)), "{expected}");
        }
        let provider=&v["rule-providers"]["subboost-openai"];
        assert_eq!(provider["format"].as_str(),Some("mrs"));
        assert!(provider["path"].as_str().unwrap().starts_with(
            "/etc/nikki-rs/providers/rule/subboost-"));
        let rules=v["rules"].as_sequence().unwrap();
        assert!(rules.iter().any(|r|r.as_str().unwrap_or("")
            .starts_with("RULE-SET,subboost-openai,")));
        let custom=generate(&sub,"clash-rs").unwrap();
        assert!(!custom.contains("🤖 AI 服务"));
    }

    #[test]
    fn rejects_unknown_policy_module_ids() {
        let sub=subscription();
        let error=generate_with_modules(&sub,"mihomo",
            &crate::filter::NodeNameFilter::default(),
            &["not-in-catalog".to_owned()]).unwrap_err();
        assert!(error.contains("Unknown policy module"),"{error}");
    }

    #[test]
    fn preserves_explicit_manual_advanced_proxy_groups() {
        let mut sub=subscription();
        sub.manual_yaml=r#"
proxy-groups:
  - name: Proxy
    type: select
    proxies: [Auto, DIRECT]
  - name: Auto
    type: load-balance
    proxies: [Node]
    strategy: sticky-sessions
  - name: Custom
    type: fallback
    proxies: [Node, DIRECT]
    interval: 120
"#.to_owned();
        let v:Value=serde_yaml::from_str(&generate(&sub,"clash-rs").unwrap()).unwrap();
        let groups=v["proxy-groups"].as_sequence().unwrap();
        assert_eq!(groups.len(),3);
        assert_eq!(groups[1]["strategy"].as_str(),Some("sticky-session"));
        assert_eq!(groups[2]["interval"].as_i64(),Some(120));
        assert_eq!(groups[0]["proxies"][0].as_str(),Some("Auto"));
    }

}
