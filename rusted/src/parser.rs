//! Proxy import from Clash YAML or common URI subscriptions.
//! Imports only proxy nodes, never applies arbitrary remote firewall/DNS settings.
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use serde_yaml::{Mapping, Value};
use url::Url;

fn as_string(value: &Value) -> Option<&str> { value.as_str() }

fn get<'a>(map: &'a Mapping, name: &str) -> Option<&'a Value> {
    map.get(Value::String(name.into()))
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let cleaned = input.trim();
    let mut padded = cleaned.to_string();
    while padded.len() % 4 != 0 { padded.push('='); }
    STANDARD.decode(&padded).or_else(|_| URL_SAFE_NO_PAD.decode(cleaned)).ok()
}

fn fragment_name(url: &Url, fallback: &str) -> String {
    url.fragment().filter(|s| !s.is_empty()).unwrap_or(fallback).to_owned()
}

fn endpoint(url: &Url) -> Result<(String, u16), String> {
    let host = url.host_str().filter(|v| !v.is_empty()).ok_or("Missing server host")?;
    let port = url.port().ok_or("Missing server port")?;
    Ok((host.into(), port))
}

fn node(value: serde_json::Value) -> Result<Value, String> {
    serde_yaml::to_value(value).map_err(|e| e.to_string())
}

fn parse_ss(raw: &str) -> Result<Value, String> {
    // A completely base64-encoded SS URI has no parseable host until
    // credentials and endpoint have been decoded.
    let encoded = raw.trim_start_matches("ss://").split(['#','?']).next().unwrap_or("");
    let fully_encoded = !encoded.contains('@');
    let url = if fully_encoded {
        Url::parse("ss://placeholder.example:8388").map_err(|e| e.to_string())?
    } else {
        Url::parse(raw).map_err(|e| e.to_string())?
    };
    // Some subscriptions use ss://BASE64(method:password@host:port) with no
    // explicit @ in the outer URL. Url::parse may mistake it for a hostname.
    let outer_auth = raw.trim_start_matches("ss://").split(['#','?']).next().unwrap_or("");
    let (userinfo, server, port) = if fully_encoded || url.host_str().is_none() {
        let encoded = raw.trim_start_matches("ss://").split(['#','?']).next().unwrap_or("");
        let decoded = decode_base64(encoded).ok_or("Invalid Shadowsocks base64")?;
        let inner = String::from_utf8(decoded).map_err(|_| "Invalid Shadowsocks UTF-8")?;
        let (auth, remote) = inner.rsplit_once('@').ok_or("Missing Shadowsocks endpoint")?;
        let target = Url::parse(&format!("ss://{remote}")).map_err(|e| e.to_string())?;
        let (server, port) = endpoint(&target)?;
        (auth.to_owned(), server, port)
    } else {
        let (server, port) = endpoint(&url)?;
        let auth = url.username();
        let auth = if auth.contains(':') { auth.to_owned() }
            else if let Some(decoded) = decode_base64(auth) {
                String::from_utf8(decoded).map_err(|_| "Invalid Shadowsocks credentials")?
            } else { auth.to_owned() };
        (auth, server, port)
    };
    let (cipher, password) = userinfo.split_once(':').ok_or("Missing Shadowsocks cipher/password")?;
    if cipher.is_empty() || password.is_empty() { return Err("Empty Shadowsocks credentials".into()); }
    let name = if fully_encoded {
        raw.split_once('#').map(|(_,n)| n.to_owned()).filter(|n| !n.is_empty())
            .unwrap_or_else(|| server.clone())
    } else { fragment_name(&url, &server) };
    node(serde_json::json!({
        "name": name, "type": "ss",
        "server": server, "port": port, "cipher": cipher, "password": password,
    }))
}

fn parse_trojan(raw: &str) -> Result<Value, String> {
    let url = Url::parse(raw).map_err(|e| e.to_string())?;
    let (server, port) = endpoint(&url)?;
    if url.username().is_empty() { return Err("Missing Trojan password".into()); }
    let sni = url.query_pairs().find(|(k,_)| k == "sni").map(|(_,v)| v.into_owned());
    let mut proxy = serde_json::json!({
        "name": fragment_name(&url, &server), "type": "trojan", "server": server,
        "port": port, "password": url.username(), "tls": true,
    });
    if let Some(sni) = sni { proxy["sni"] = serde_json::json!(sni); }
    node(proxy)
}

fn parse_vless(raw: &str) -> Result<Value, String> {
    let url = Url::parse(raw).map_err(|e| e.to_string())?;
    let (server, port) = endpoint(&url)?;
    if url.username().is_empty() { return Err("Missing VLESS UUID".into()); }
    let query = url.query_pairs().collect::<std::collections::HashMap<_,_>>();
    let security = query.get("security").map(|v| v.as_ref()).unwrap_or("");
    let network = query.get("type").map(|v| v.as_ref()).unwrap_or("tcp");
    let mut proxy = serde_json::json!({
        "name": fragment_name(&url, &server), "type": "vless",
        "server": server, "port": port, "uuid": url.username(),
        "tls": matches!(security, "tls" | "reality"),
        "network": network,
    });
    if let Some(sni) = query.get("sni") { proxy["servername"] = serde_json::json!(sni); }
    if let Some(flow) = query.get("flow") { proxy["flow"] = serde_json::json!(flow); }
    if network == "ws" {
        let path = query.get("path").map(|v| v.as_ref()).unwrap_or("/");
        let host = query.get("host").map(|v| v.as_ref()).unwrap_or("");
        proxy["ws-opts"] = serde_json::json!({"path":path, "headers":{"Host":host}});
    }
    if security == "reality" {
        proxy["reality-opts"] = serde_json::json!({
            "public-key":query.get("pbk").map(|v| v.as_ref()).unwrap_or(""),
            "short-id":query.get("sid").map(|v| v.as_ref()).unwrap_or(""),
        });
        if let Some(fp) = query.get("fp") { proxy["client-fingerprint"] = serde_json::json!(fp); }
    }
    node(proxy)
}

fn parse_vmess(raw: &str) -> Result<Value, String> {
    let encoded = raw.trim_start_matches("vmess://").trim();
    let bytes = decode_base64(encoded).ok_or("Invalid VMess base64")?;
    let settings: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let server = settings["add"].as_str().ok_or("VMess missing server")?;
    let port = settings["port"].as_u64().or_else(|| settings["port"].as_str().and_then(|v| v.parse().ok()))
        .ok_or("VMess missing port")?;
    if port == 0 || port > 65535 { return Err("VMess port out of range".into()); }
    let id = settings["id"].as_str().ok_or("VMess missing id")?;
    let name = settings["ps"].as_str().unwrap_or(server);
    let network = settings["net"].as_str().unwrap_or("tcp");
    let mut proxy = serde_json::json!({
        "name":name, "type":"vmess", "server":server, "port":port,
        "uuid":id, "alterId": settings["aid"].as_u64().unwrap_or(0),
        "cipher": settings["scy"].as_str().filter(|v| !v.is_empty()).unwrap_or("auto"),
        "tls": settings["tls"].as_str().map(|s| s == "tls").unwrap_or(false),
        "network": network,
    });
    if network == "ws" {
        proxy["ws-opts"] = serde_json::json!({
            "path": settings["path"].as_str().unwrap_or("/"),
            "headers": {"Host":settings["host"].as_str().unwrap_or(server)}
        });
    }
    if let Some(sni) = settings["sni"].as_str().filter(|v| !v.is_empty()) {
        proxy["servername"] = serde_json::json!(sni);
    }
    node(proxy)
}

pub fn parse_uri(uri: &str) -> Result<Value, String> {
    let s = uri.trim();
    if s.starts_with("ss://") { parse_ss(s) }
    else if s.starts_with("trojan://") { parse_trojan(s) }
    else if s.starts_with("vless://") { parse_vless(s) }
    else if s.starts_with("vmess://") { parse_vmess(s) }
    else { crate::protocols::parse(s) }
}

pub fn validate_nodes(nodes: Vec<Value>) -> Result<Vec<Value>, String> {
    if nodes.len() > 10000 { return Err("Too many nodes (max 10000)".into()); }
    let mut seen = std::collections::HashSet::<String>::new();
    let mut output = Vec::new();
    for (i, mut node) in nodes.into_iter().enumerate() {
        let map = node.as_mapping_mut().ok_or("Proxy node must be a YAML mapping")?;
        let name = get(map, "name").and_then(as_string).unwrap_or("").trim().to_string();
        let server = get(map, "server").and_then(as_string).unwrap_or("");
        let kind = get(map, "type").and_then(as_string).unwrap_or("");
        let port = get(map, "port").and_then(|value| value.as_i64()
            .or_else(|| value.as_str().and_then(|s| s.parse().ok()))).unwrap_or(0);
        if name.is_empty() || server.is_empty() || kind.is_empty() || !(1..=65535).contains(&port) {
            return Err(format!("Proxy node {} requires name/type/server/valid port", i+1));
        }
        let mut unique = name.clone();
        let mut suffix = 2;
        while !seen.insert(unique.clone()) {
            unique = format!("{name} ({suffix})");
            suffix += 1;
        }
        map.insert(Value::String("name".into()), Value::String(unique));
        output.push(node);
    }
    Ok(output)
}

pub fn parse_document(body: &str) -> Result<Vec<Value>, String> {
    if body.len() > 3 * 1024 * 1024 { return Err("Subscription content too large".into()); }
    let content = body.trim();
    if content.is_empty() { return Ok(Vec::new()); }
    if let Ok(doc) = serde_yaml::from_str::<Value>(content) {
        let proxy_seq = match &doc {
            Value::Mapping(map) => get(map,"proxies").and_then(Value::as_sequence),
            Value::Sequence(seq) => Some(seq),
            _ => None,
        };
        if let Some(proxies) = proxy_seq { return validate_nodes(proxies.clone()); }
    }
    let mut source = content.to_string();
    if !source.contains("://") {
        if let Some(decoded) = decode_base64(content) {
            source = String::from_utf8(decoded).map_err(|_| "Invalid subscription UTF-8")?;
        }
    }
    let uris: Vec<&str> = source.lines().map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#')).collect();
    if uris.len() > 10000 { return Err("Too many nodes".into()); }
    let mut nodes = Vec::new();
    for uri in uris { nodes.push(parse_uri(uri)?); }
    validate_nodes(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_clash_yaml_and_renames_duplicate_proxies() {
        let content = "proxies:\n  - {name: One, type: ss, server: example.org, port: 8388, cipher: aes-128-gcm, password: pass}\n  - {name: One, type: ss, server: example.net, port: 443, cipher: aes-128-gcm, password: pass}\n";
        let parsed = parse_document(content).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1]["name"].as_str(), Some("One (2)"));
    }
    #[test]
    fn parses_trojan_and_base64_uri_list() {
        let uri = "trojan://secret@example.org:443?sni=example.org#Hello";
        let content = STANDARD.encode(format!("{uri}\n"));
        assert_eq!(parse_document(&content).unwrap()[0]["name"].as_str(),Some("Hello"));
    }
    #[test]
    fn parses_fully_base64_encoded_shadowsocks_link() {
        let encoded = STANDARD.encode("aes-128-gcm:password@example.net:8388");
        let node = parse_uri(&format!("ss://{encoded}#Encoded")).unwrap();
        assert_eq!(node["name"].as_str(), Some("Encoded"));
        assert_eq!(node["server"].as_str(), Some("example.net"));
    }

    #[test]
    fn rejects_invalid_nodes_and_source_schemes() {
        assert!(parse_document("proxies:\n  - {name: A, type: ss, server: example.org, port: 0}").is_err());
        assert!(parse_uri("file:///etc/passwd").is_err());
    }
}
