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
    url.fragment().filter(|s| !s.is_empty()).map(|s| percent_encoding::percent_decode_str(s).decode_utf8_lossy().to_string()).unwrap_or_else(|| fallback.to_owned())
}

fn endpoint(url: &Url) -> Result<(String, u16), String> {
    let host = url.host_str().filter(|v| !v.is_empty()).ok_or("Missing server host")?;
    let port = url.port().ok_or("Missing server port")?;
    Ok((host.into(), port))
}

fn endpoint_with_default(url: &Url, default_port: u16) -> Result<(String, u16), String> {
    let host = url.host_str().filter(|v| !v.is_empty()).ok_or("Missing server host")?;
    let port = url.port().unwrap_or(default_port);
    if port == 0 { return Err("Missing server port".into()); }
    Ok((host.into(), port))
}

fn node(value: serde_json::Value) -> Result<Value, String> {
    serde_yaml::to_value(value).map_err(|e| e.to_string())
}

/// Parse SIP002 plugin segments. Backslash only unescapes semicolon,
/// equals or backslash; all other escapes are preserved like upstream.
fn ss_plugin_segments(value: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek().copied() {
                Some(';' | '=' | '\\') => { current.push(chars.next().unwrap()); }
                _ => current.push('\\'),
            },
            ';' => { segments.push(std::mem::take(&mut current)); },
            _ => current.push(c),
        }
    }
    segments.push(current);
    segments
}

fn ss_plugin_opts(url: &Url, proxy: &mut serde_json::Value) {
    let Some(plugin) = url.query_pairs().find(|(k, _)| k == "plugin")
        .map(|(_,v)|v.into_owned()) else { return; };
    let mut segments = ss_plugin_segments(&plugin).into_iter();
    let Some(raw_name) = segments.next() else { return; };
    let raw_name = raw_name.trim();
    if raw_name.is_empty() { return; }
    let name = raw_name.to_ascii_lowercase();
    let is_obfs = matches!(name.as_str(), "obfs" | "obfs-local" | "simple-obfs");
    let mut opts = serde_json::Map::new();
    for segment in segments {
        let segment = segment.trim();
        if segment.is_empty() { continue; }
        let (key, value) = match segment.split_once('=') {
            Some((key, value)) => (key.trim(), if value.trim().is_empty() { serde_json::json!(true) } else { serde_json::json!(value.trim()) }),
            None => (segment, serde_json::json!(true)),
        };
        if !key.is_empty() { opts.insert(key.to_owned(), value); }
    }
    if is_obfs {
        let mode = opts.get("mode").or_else(|| opts.get("obfs"))
            .and_then(serde_json::Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned);
        let host = opts.get("host").or_else(|| opts.get("obfs-host"))
            .or_else(|| opts.get("obfs_host"))
            .and_then(serde_json::Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned);
        opts.clear();
        if let Some(mode) = mode { opts.insert("mode".into(), serde_json::json!(mode)); }
        if let Some(host) = host { opts.insert("host".into(), serde_json::json!(host)); }
        proxy["plugin"] = serde_json::json!("obfs");
    } else {
        proxy["plugin"] = serde_json::json!(raw_name);
    }
    if !opts.is_empty() { proxy["plugin-opts"] = serde_json::Value::Object(opts); }
}

fn parse_ss(raw: &str) -> Result<Value, String> {
    // Match the upstream SIP002 and legacy base64 encodings. Splitting at the
    // last '@' preserves ':' characters in plaintext credentials/passwords.
    let payload = raw.strip_prefix("ss://").ok_or("Invalid Shadowsocks scheme")?;
    let main = payload.split(['?', '#']).next().unwrap_or("");
    let fully_encoded = !main.contains('@');
    let (credentials, server, port) = if fully_encoded {
        let encoded = percent_encoding::percent_decode_str(main)
            .decode_utf8().map_err(|_| "Invalid Shadowsocks encoding")?;
        let decoded = decode_base64(&encoded).ok_or("Invalid Shadowsocks base64")?;
        let inner = String::from_utf8(decoded).map_err(|_| "Invalid Shadowsocks UTF-8")?;
        let (auth, remote) = inner.rsplit_once('@').ok_or("Missing Shadowsocks endpoint")?;
        let target = Url::parse(&format!("ss://{remote}")).map_err(|e| e.to_string())?;
        let (server, port) = endpoint(&target)?;
        (auth.to_owned(), server, port)
    } else {
        let url = Url::parse(raw).map_err(|e| e.to_string())?;
        let (server, port) = endpoint(&url)?;
        let (raw_auth, _) = main.rsplit_once('@').ok_or("Missing Shadowsocks credentials")?;
        let auth = percent_encoding::percent_decode_str(raw_auth)
            .decode_utf8().map_err(|_| "Invalid Shadowsocks credentials")?;
        let credentials = if auth.contains(':') {
            auth.into_owned()
        } else {
            let decoded = decode_base64(&auth).ok_or("Invalid Shadowsocks credentials base64")?;
            String::from_utf8(decoded).map_err(|_| "Invalid Shadowsocks credentials UTF-8")?
        };
        (credentials, server, port)
    };
    let (cipher, password) = credentials.split_once(':')
        .ok_or("Missing Shadowsocks cipher/password")?;
    if cipher.is_empty() || password.is_empty() {
        return Err("Empty Shadowsocks credentials".into());
    }
    let name = raw.split_once('#').and_then(|(_, fragment)| {
        (!fragment.is_empty()).then(|| percent_encoding::percent_decode_str(fragment)
            .decode_utf8_lossy().into_owned())
    }).unwrap_or_else(|| server.clone());
    let mut proxy = serde_json::json!({
        "name": name, "type": "ss", "server": server, "port": port,
        "cipher": cipher, "password": password, "udp": true,
    });
    if let Ok(url) = Url::parse(raw) {
        ss_plugin_opts(&url, &mut proxy);
        for (query, field) in [("uot", "udp-over-tcp"), ("tfo", "tfo")] {
            if let Some(value) = query_param(&url, query) {
                let value = value.trim().to_ascii_lowercase();
                if value.is_empty() || matches!(value.as_str(), "1" | "true" | "yes" | "on") {
                    proxy[field] = serde_json::json!(true);
                }
            }
        }
    }
    node(proxy)
}

fn query_param(url: &Url, key: &str) -> Option<String> {
    url.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned())
}
fn query_bool(url: &Url, key: &str) -> bool {
    query_param(url, key).is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}
/// Mirror the upstream splitWsPathEarlyData contract: only positive, safe
/// decimal ed values in the embedded path query are consumed.
fn ws_path_early_data(raw: &str) -> (String, Option<u64>) {
    let path = if raw.trim().is_empty() { "/" } else { raw.trim() };
    let Some((base, query)) = path.split_once('?') else {
        return (path.to_owned(), None);
    };
    let base = if base.is_empty() { "/" } else { base };
    let mut kept = Vec::new();
    let mut early_data = None;
    for segment in query.split('&').filter(|s| !s.is_empty()) {
        if let Some(value) = segment.strip_prefix("ed=") {
            if early_data.is_none() && !value.is_empty()
                && value.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(num) = value.parse::<u64>() {
                    if num > 0 && num <= 9_007_199_254_740_991 {
                        early_data = Some(num);
                        continue;
                    }
                }
            }
        }
        kept.push(segment);
    }
    if early_data.is_none() {
        return (path.to_owned(), None);
    }
    if kept.is_empty() {
        (base.to_owned(), early_data)
    } else {
        (format!("{}?{}", base, kept.join("&")), early_data)
    }
}

fn transport_options(url: &Url, proxy: &mut serde_json::Value, network: &str) -> Result<(), String> {
    match network {
        "tcp" | "none" => {},
        "ws" => {
            let raw_path = query_param(url, "path").unwrap_or_else(|| "/".into());
            let (path, early_data) = ws_path_early_data(&raw_path);
            let mut opts = serde_json::json!({"path": path});
            if let Some(host) = query_param(url, "host").filter(|s| !s.is_empty()) {
                if let Some(first) = csv_list(&host).first() {
                    opts["headers"] = serde_json::json!({"Host": first});
                }
            }
            if let Some(max) = early_data {
                opts["max-early-data"] = serde_json::json!(max);
                opts["early-data-header-name"] = serde_json::json!("Sec-WebSocket-Protocol");
            }
            proxy["ws-opts"] = opts;
        },
        "grpc" => {
            let service = query_param(url, "serviceName")
                .or_else(|| query_param(url, "service_name"))
                .or_else(|| query_param(url, "service-name"))
                .unwrap_or_else(|| query_param(url, "path").unwrap_or_default()
                    .trim_start_matches('/').to_owned());
            let mut opts=serde_json::json!({"grpc-service-name": service});
            if let Some(mode)=query_param(url,"mode").filter(|s|!s.is_empty()) {
                opts["_grpcType"]=serde_json::json!(mode);
            }
            if let Some(authority)=query_param(url,"authority").filter(|s|!s.is_empty()) {
                opts["_grpcAuthority"]=serde_json::json!(authority);
            }
            proxy["grpc-opts"] = opts;
        },
        "h2" => {
            let path=query_param(url,"path").unwrap_or_else(||"/".into());
            let mut opts=serde_json::json!({"path":path});
            if let Some(host)=query_param(url,"host").filter(|s|!s.is_empty()) {
                opts["host"]=serde_json::json!(csv_list(&host));
            }
            proxy["h2-opts"]=opts;
        },
        "http" => {
            let path = query_param(url, "path").unwrap_or_else(|| "/".into());
            let paths = csv_list(&path);
            let mut opts = serde_json::json!({
                "method":query_param(url,"method").unwrap_or_else(||"GET".into()).to_ascii_uppercase(),
                "path": if paths.is_empty() { vec!["/".to_owned()] } else { paths }
            });
            let host = query_param(url, "host").filter(|s| !s.is_empty())
                .or_else(||{
                    let sni=query_param(url,"sni")?;
                    let server=url.host_str()?;
                    (sni!=server).then_some(sni)
                });
            if let Some(host) = host {
                let hosts=csv_list(&host);
                if !hosts.is_empty() { opts["headers"]=serde_json::json!({"Host":hosts}); }
            }
            proxy["http-opts"] = opts;
        },
        other => return Err(format!("Unsupported transport: {other}")),
    }
    Ok(())
}
fn tls_options(url: &Url, proxy: &mut serde_json::Value) {
    if let Some(sni) = query_param(url, "sni").or_else(|| query_param(url, "peer")).filter(|s| !s.is_empty()) {
        proxy["servername"] = serde_json::json!(sni);
    }
    if let Some(fp) = query_param(url, "fp").or_else(|| query_param(url, "fingerprint")).or_else(|| query_param(url, "client-fingerprint")).filter(|s| !s.is_empty()) {
        proxy["client-fingerprint"] = serde_json::json!(fp);
    }
    if query_bool(url, "allowInsecure") || query_bool(url, "allow_insecure") || query_bool(url, "allow-insecure") || query_bool(url, "insecure") {
        proxy["skip-cert-verify"] = serde_json::json!(true);
    }
    if let Some(alpn) = query_param(url, "alpn") {
        let entries: Vec<_> = alpn.split(',').filter(|s| !s.is_empty()).collect();
        if !entries.is_empty() { proxy["alpn"] = serde_json::json!(entries); }
    }
}
fn parse_trojan(raw: &str) -> Result<Value, String> {
    let url = Url::parse(raw).map_err(|e| e.to_string())?;
    let (server, port) = endpoint_with_default(&url, 443)?;
    let password = match url.password() {
        Some(suffix) => format!("{}:{}", url.username(), suffix),
        None => url.username().to_owned(),
    };
    let password = percent_encoding::percent_decode_str(&password).decode_utf8_lossy().to_string();
    if password.is_empty() { return Err("Missing Trojan password".into()); }
    let network = query_param(&url, "type").unwrap_or_else(|| {
        if query_bool(&url, "ws") { "ws" } else { "tcp" }.into()
    }).to_ascii_lowercase();
    let upgrade=network=="httpupgrade";
    let network=if upgrade { "ws".to_owned() } else { network };
    let mut proxy = serde_json::json!({
        "name": fragment_name(&url, &server), "type": "trojan", "server": server,
        "port": port, "password": password, "udp": true, "sni": server,
        "network":network,
    });
    if let Some(sni) = query_param(&url, "sni").or_else(||query_param(&url, "peer")) {
        proxy["sni"] = serde_json::json!(sni);
    }
    tls_options(&url, &mut proxy);
    transport_options(&url, &mut proxy, &network)?;
    if upgrade {
        proxy["ws-opts"]["v2ray-http-upgrade"]=serde_json::json!(true);
        proxy["ws-opts"]["v2ray-http-upgrade-fast-open"]=serde_json::json!(true);
    }
    node(proxy)
}
fn vless_uri(raw: &str) -> Result<(Url,bool),String> {
    let tail=raw.strip_prefix("vless://").ok_or("Invalid VLESS scheme")?;
    let authority=tail.split(['?','#']).next().unwrap_or("");
    if authority.contains('@') {
        return Url::parse(raw).map(|url|(url,false)).map_err(|e|e.to_string());
    }
    // Shadowrocket exports vless://BASE64(cipher:uuid@server:port)?params#name.
    let (encoded, suffix)=tail.split_once('?').ok_or("VLESS encoded authority missing query")?;
    let encoded=percent_encoding::percent_decode_str(encoded)
        .decode_utf8().map_err(|_|"Invalid encoded VLESS authority")?;
    let decoded=decode_base64(&encoded).ok_or("Invalid Shadowrocket VLESS base64")?;
    let decoded=String::from_utf8(decoded).map_err(|_|"Invalid Shadowrocket VLESS UTF-8")?;
    let url=Url::parse(&format!("vless://{decoded}?{suffix}"))
        .map_err(|e|e.to_string())?;
    Ok((url,true))
}

fn parse_vless(raw: &str) -> Result<Value, String> {
    let (url,shadowrocket)=vless_uri(raw)?;
    let (server, port) = endpoint_with_default(&url, 443)?;
    let mut uuid = percent_encoding::percent_decode_str(url.username())
        .decode_utf8_lossy().to_string();
    if shadowrocket {
        if let Some(password)=url.password(){
            uuid=format!("{}:{}",uuid,percent_encoding::percent_decode_str(password).decode_utf8_lossy());
        }
        uuid=uuid.rsplit(':').next().unwrap_or("").to_owned();
    }
    if uuid.is_empty() { return Err("Missing VLESS UUID".into()); }
    let pbk=query_param(&url,"pbk")
        .or_else(||query_param(&url,"public-key"))
        .or_else(||query_param(&url,"public_key"));
    let security=query_param(&url,"security").filter(|s|!s.is_empty())
        .unwrap_or_else(||{
            if pbk.is_some() { "reality".into() }
            else if shadowrocket && query_bool(&url,"tls") { "tls".into() }
            else { "none".into() }
        });
    if !matches!(security.as_str(), "none" | "tls" | "reality") {
        return Err(format!("Unsupported VLESS security: {security}"));
    }
    let input_network=query_param(&url,"type")
        .or_else(||(shadowrocket).then(||query_param(&url,"obfs")).flatten())
        .unwrap_or_else(||"tcp".into()).to_ascii_lowercase();
    let http_upgrade=input_network=="httpupgrade";
    let network=match input_network.as_str() {
        "none" | "tcp" => if query_param(&url,"headerType").as_deref()==Some("http") {"http"}else{"tcp"},
        "websocket" | "httpupgrade" | "ws" => "ws",
        "grpc" => "grpc", "http" => "http", "h2" => "h2",
        other => return Err(format!("Unsupported VLESS transport: {other}")),
    };
    let name=fragment_name(&url,"VLESS 节点");
    let mut proxy=serde_json::json!({
        "name": name, "type": "vless", "server": server, "port": port,
        "uuid": uuid, "udp": true,
        "tls": matches!(security.as_str(), "tls" | "reality"),
        "network":network,
    });
    tls_options(&url, &mut proxy);
    if let Some(flow)=query_param(&url,"flow").filter(|s|!s.is_empty()) {
        proxy["flow"]=serde_json::json!(flow);
    }
    if let Some(encoding)=query_param(&url,"encryption").filter(|s|!s.is_empty()) {
        proxy["encryption"]=serde_json::json!(encoding);
    }
    if shadowrocket && security=="tls" && proxy.get("client-fingerprint").is_none() {
        proxy["client-fingerprint"]=serde_json::json!("chrome");
    }
    transport_options(&url,&mut proxy,network)?;
    if http_upgrade {
        proxy["ws-opts"]["v2ray-http-upgrade"]=serde_json::json!(true);
        proxy["ws-opts"]["v2ray-http-upgrade-fast-open"]=serde_json::json!(true);
    }
    if security=="reality" {
        if proxy.get("client-fingerprint").is_none() {
            proxy["client-fingerprint"]=serde_json::json!("chrome");
        }
        let public_key=pbk.filter(|s|!s.is_empty()).ok_or("Reality public key required")?;
        let mut reality=serde_json::json!({"public-key":public_key});
        if let Some(id)=query_param(&url,"sid").filter(|s|!s.is_empty()) {
            reality["short-id"]=serde_json::json!(id);
        }
        proxy["reality-opts"]=reality;
    }
    node(proxy)
}

fn json_string<'a>(object: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    object.get(key).and_then(serde_json::Value::as_str)
}
fn json_number(object: &serde_json::Value, key: &str) -> Option<u64> {
    object.get(key).and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
}
fn json_bool(value: &serde_json::Value) -> Option<bool> {
    match value {
        serde_json::Value::Bool(v) => Some(*v),
        serde_json::Value::Number(n) => match n.as_i64() { Some(1) => Some(true), Some(0) => Some(false), _ => None },
        serde_json::Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        },
        _ => None,
    }
}
fn csv_list(raw: &str) -> Vec<String> {
    raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}
fn parse_vmess_config(settings: &serde_json::Value) -> Result<Value, String> {
    let server = json_string(settings, "add").filter(|s| !s.is_empty()).ok_or("VMess missing server")?;
    let port = json_number(settings, "port").ok_or("VMess missing port")?;
    if port == 0 || port > 65535 { return Err("VMess port out of range".into()); }
    let uuid = json_string(settings, "id").filter(|s| !s.is_empty()).ok_or("VMess missing id")?;
    let name = json_string(settings, "ps").filter(|s| !s.is_empty()).unwrap_or("VMess 节点");
    let network = json_string(settings, "net").unwrap_or("tcp").to_ascii_lowercase();
    let network = match network.as_str() {
        "tcp" | "none" => "tcp", "ws" | "websocket" => "ws",
        "grpc" => "grpc", "h2" => "h2", "http" => "http",
        "httpupgrade" => "ws",
        other => return Err(format!("Unsupported VMess transport: {other}")),
    };
    let http_obfs = network == "tcp" && json_string(settings, "type") == Some("http");
    let transport = if http_obfs { "http" } else { network };
    let tls = json_string(settings, "tls") == Some("tls");
    let host = json_string(settings, "host").unwrap_or("");
    let path = json_string(settings, "path").unwrap_or("/");
    let alter_id = json_number(settings, "aid").unwrap_or(0);
    let cipher = json_string(settings, "scy")
        .or_else(|| json_string(settings, "encryption"))
        .filter(|v| !v.is_empty()).unwrap_or("auto");
    let mut proxy = serde_json::json!({
        "name":name, "type":"vmess", "server":server, "port":port,
        "uuid":uuid, "alterId":alter_id, "cipher":cipher,
        "udp":true, "tls":tls, "network":transport,
    });
    let sni = json_string(settings, "sni").filter(|s| !s.is_empty())
        .unwrap_or_else(|| host.split(',').next().unwrap_or("").trim());
    if !sni.is_empty() { proxy["servername"] = serde_json::json!(sni); }
    if let Some(fp) = json_string(settings, "fp").filter(|s| !s.is_empty()) {
        proxy["client-fingerprint"] = serde_json::json!(fp);
    }
    if let Some(alpn) = json_string(settings, "alpn") {
        let items = csv_list(alpn);
        if !items.is_empty() { proxy["alpn"] = serde_json::json!(items); }
    }
    if settings.get("allowInsecure").and_then(json_bool) == Some(true) {
        proxy["skip-cert-verify"] = serde_json::json!(true);
    }
    if let Some(encoding) = json_string(settings, "packet-encoding")
        .or_else(|| json_string(settings, "packetEncoding")) {
        if !encoding.is_empty() { proxy["packet-encoding"] = serde_json::json!(encoding); }
    }
    for (input, alt, output) in [
        ("authenticated-length", "authenticatedLength", "authenticated-length"),
        ("global-padding", "globalPadding", "global-padding"),
    ] {
        if let Some(value) = settings.get(input).or_else(||settings.get(alt)).and_then(json_bool) {
            proxy[output] = serde_json::json!(value);
        }
    }
    match transport {
        "ws" => {
            let (path, early_data) = ws_path_early_data(path);
            let mut opts = serde_json::json!({"path":path});
            if let Some(host) = csv_list(host).first() {
                opts["headers"] = serde_json::json!({"Host":host});
            }
            if let Some(value) = early_data {
                opts["max-early-data"] = serde_json::json!(value);
                opts["early-data-header-name"] = serde_json::json!("Sec-WebSocket-Protocol");
            }
            if json_string(settings, "net") == Some("httpupgrade") {
                opts["v2ray-http-upgrade"] = serde_json::json!(true);
                opts["v2ray-http-upgrade-fast-open"] = serde_json::json!(true);
            }
            if path != "/" || opts.get("headers").is_some() || early_data.is_some()
                || json_string(settings,"net")==Some("httpupgrade") {
                proxy["ws-opts"] = opts;
            }
        },
        "grpc" => {
            let service = json_string(settings, "serviceName").filter(|s| !s.is_empty())
                .or_else(||json_string(settings, "path").filter(|s|!s.is_empty()))
                .unwrap_or("");
            let mut opts = serde_json::json!({"grpc-service-name":service});
            if let Some(mode) = json_string(settings, "mode").filter(|s| !s.is_empty()) {
                opts["_grpcType"] = serde_json::json!(mode);
            }
            if let Some(authority) = json_string(settings, "authority").filter(|s| !s.is_empty()) {
                opts["_grpcAuthority"] = serde_json::json!(authority);
            }
            proxy["grpc-opts"] = opts;
        },
        "h2" => {
            let mut opts = serde_json::json!({"path":path});
            let hosts = csv_list(host);
            if !hosts.is_empty() { opts["host"] = serde_json::json!(hosts); }
            proxy["h2-opts"] = opts;
        },
        "http" => {
            let paths = csv_list(path);
            let mut opts = serde_json::json!({
                "method":json_string(settings, "method").unwrap_or("GET").to_ascii_uppercase(),
                "path":if paths.is_empty() {vec!["/".to_string()]} else {paths},
            });
            let hosts = csv_list(host);
            if !hosts.is_empty() { opts["headers"] = serde_json::json!({"Host":hosts}); }
            proxy["http-opts"] = opts;
        },
        _ => {},
    }
    node(proxy)
}
fn parse_vmess(raw: &str) -> Result<Value, String> {
    // Standard JSON links and URI-style VMess are both emitted by upstream clients.
    let raw = raw.trim_start_matches("vmess://");
    if raw.contains('@') {
        let url = Url::parse(&format!("vmess://{raw}")).map_err(|e| e.to_string())?;
        let secure = query_param(&url, "security").as_deref() == Some("tls")
            || query_bool(&url, "tls");
        let port = url.port().unwrap_or(if secure {443} else {80});
        if port == 0 { return Err("VMess port out of range".into()); }
        let mut settings = serde_json::json!({
            "add":url.host_str().ok_or("VMess missing server")?,
            "port":port,
            "id":percent_encoding::percent_decode_str(url.username()).decode_utf8_lossy(),
            "ps":fragment_name(&url,"VMess 节点"),
            "aid":query_param(&url,"aid").unwrap_or_else(||"0".into()),
            "scy":query_param(&url,"encryption").unwrap_or_else(||"auto".into()),
            "net":query_param(&url,"type").unwrap_or_else(||"tcp".into()),
            "host":query_param(&url,"host").unwrap_or_default(),
            "path":query_param(&url,"path").unwrap_or_else(||"/".into()),
            "tls":if secure {"tls"} else {""},
        });
        for (param, field) in [
            ("sni","sni"),("alpn","alpn"),("fp","fp"),
            ("serviceName","serviceName"),("method","method"),
        ] {
            if let Some(v) = query_param(&url,param) { settings[field]=serde_json::json!(v); }
        }
        if query_bool(&url,"allowInsecure") { settings["allowInsecure"]=serde_json::json!(true); }
        return parse_vmess_config(&settings);
    }
    let encoded = raw.split('#').next().unwrap_or("").trim();
    let bytes = decode_base64(encoded).ok_or("Invalid VMess base64")?;
    let mut settings: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if let Some(fragment) = raw.split_once('#').map(|(_,v)|v).filter(|s|!s.is_empty()) {
        settings["ps"] = serde_json::json!(
            percent_encoding::percent_decode_str(fragment).decode_utf8_lossy().to_string());
    }
    parse_vmess_config(&settings)
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

fn strip_imported_controls(mut nodes:Vec<Value>)->Vec<Value>{
    // Imported subscriptions cannot set local relay/group routing controls.
    // Keep deliberate dialer-proxy in user-authored manual YAML unchanged.
    for node in &mut nodes {
        if let Some(map)=node.as_mapping_mut() {
            map.remove(Value::String("dialer-proxy".into()));
            map.remove(Value::String("dialer_proxy".into()));
        }
    }
    nodes
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
        if let Some(proxies) = proxy_seq { return validate_nodes(proxies.clone()).map(strip_imported_controls); }
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
    validate_nodes(nodes).map(strip_imported_controls)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_upstream_uri_contract() {
        let fixtures: serde_json::Value = serde_json::from_str(
            include_str!("../data/uri-parity-fixtures.json")).unwrap();
        for fixture in fixtures.as_array().unwrap() {
            let uri = fixture["uri"].as_str().unwrap();
            let node = parse_uri(uri).unwrap_or_else(|err| panic!("{}: {err}", fixture["id"]));
            let mut actual = serde_json::Map::new();
            for key in ["name", "type", "server", "port", "network", "cipher", "password", "udp", "sni", "client-fingerprint", "plugin", "tfo", "tls", "uuid", "alterId", "servername", "skip-cert-verify"] {
                if let Some(value) = node.get(key) {
                    actual.insert(key.into(), serde_json::to_value(value).unwrap());
                }
            }
            if let Some(opts) = node.get("plugin-opts") {
                for (field, renamed) in [("mode", "plugin_mode"), ("host", "plugin_host")] {
                    if let Some(value) = opts.get(field) {
                        actual.insert(renamed.into(), serde_json::to_value(value).unwrap());
                    }
                }
            }
            if let Some(value) = node.get("udp-over-tcp") {
                actual.insert("udp_over_tcp".into(), serde_json::to_value(value).unwrap());
            }
            if let Some(ws) = node.get("ws-opts") {
                for (source, target) in [
                    ("path", "ws_path"),
                    ("max-early-data", "ws_early_data"),
                    ("early-data-header-name", "ws_header"),
                    ("v2ray-http-upgrade", "ws_upgrade"),
                ] {
                    if let Some(value) = ws.get(source) {
                        actual.insert(target.into(), serde_json::to_value(value).unwrap());
                    }
                }
                if let Some(host) = ws.get("headers").and_then(|headers| headers.get("Host")) {
                    actual.insert("ws_host".into(), serde_json::to_value(host).unwrap());
                }
            }
            if let Some(h2) = node.get("h2-opts") {
                for (source,target) in [("path","h2_path"),("host","h2_hosts")] {
                    if let Some(value)=h2.get(source) {
                        actual.insert(target.into(),serde_json::to_value(value).unwrap());
                    }
                }
            }
            if let Some(http) = node.get("http-opts") {
                for (source, target) in [("method","http_method"),("path","http_paths")] {
                    if let Some(value) = http.get(source) {
                        actual.insert(target.into(), serde_json::to_value(value).unwrap());
                    }
                }
                if let Some(hosts) = http.get("headers").and_then(|v|v.get("Host")) {
                    actual.insert("http_hosts".into(),serde_json::to_value(hosts).unwrap());
                }
            }
            if let Some(grpc)=node.get("grpc-opts") {
                for (source,target) in [
                    ("grpc-service-name","grpc_service"),
                    ("_grpcType","grpc_mode"),
                    ("_grpcAuthority","grpc_authority")
                ] {
                    if let Some(value)=grpc.get(source) {
                        actual.insert(target.into(),serde_json::to_value(value).unwrap());
                    }
                }
            }
            let mut selected = serde_json::Map::new();
            let expected = fixture["expected"].as_object().unwrap();
            for key in expected.keys() {
                if let Some(value) = actual.get(key) {
                    selected.insert(key.clone(), value.clone());
                }
            }
            assert_eq!(serde_json::Value::Object(selected), fixture["expected"],
                "Parity mismatch for {}", fixture["id"]);
        }
    }
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
    fn normalizes_sip002_obfs_plugin_and_flags() {
        let parsed = parse_uri("ss://aes-128-gcm:pass@example.org:443?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dcdn.example.org&uot=1&tfo=yes#SS").unwrap();
        assert_eq!(parsed["plugin"].as_str(), Some("obfs"));
        assert_eq!(parsed["plugin-opts"]["mode"].as_str(), Some("tls"));
        assert_eq!(parsed["plugin-opts"]["host"].as_str(), Some("cdn.example.org"));
        assert_eq!(parsed["udp-over-tcp"].as_bool(), Some(true));
        assert_eq!(parsed["tfo"].as_bool(), Some(true));
    }
    #[test]
    fn parses_plaintext_and_encoded_sip002_shadowsocks_credentials() {
        let plaintext = parse_uri("ss://aes-128-gcm:hello%3Aworld@example.org:8388#%E6%B5%8B%E8%AF%95").unwrap();
        assert_eq!(plaintext["cipher"].as_str(), Some("aes-128-gcm"));
        assert_eq!(plaintext["password"].as_str(), Some("hello:world"));
        assert_eq!(plaintext["name"].as_str(), Some("测试"));
        let encoded = STANDARD.encode("aes-256-gcm:secret");
        let encoded = encoded.replace('=', "%3D");
        let uri = format!("ss://{encoded}@example.org:443#SIP002");
        let node = parse_uri(&uri).unwrap();
        assert_eq!(node["cipher"].as_str(), Some("aes-256-gcm"));
        assert_eq!(node["password"].as_str(), Some("secret"));
    }
    #[test]
    fn parses_fully_base64_encoded_shadowsocks_link() {
        let encoded = STANDARD.encode("aes-128-gcm:password@example.net:8388");
        let node = parse_uri(&format!("ss://{encoded}#Encoded")).unwrap();
        assert_eq!(node["name"].as_str(), Some("Encoded"));
        assert_eq!(node["server"].as_str(), Some("example.net"));
    }

    #[test]
    fn vless_grpc_reality_and_tls_parameters() {
        let link="vless://uuid@example.org:443?security=reality&pbk=publickey&sid=abcd&type=grpc&serviceName=hello&fp=chrome&sni=example.com&alpn=h2%2Chttp%2F1.1#Node";
        let parsed=parse_uri(link).unwrap();
        assert_eq!(parsed["grpc-opts"]["grpc-service-name"].as_str(),Some("hello"));
        assert_eq!(parsed["reality-opts"]["public-key"].as_str(),Some("publickey"));
        assert_eq!(parsed["client-fingerprint"].as_str(),Some("chrome"));
        assert_eq!(parsed["alpn"].as_sequence().unwrap().len(),2);
        assert!(parse_uri("vless://uuid@example.org:443?security=reality").is_err());
    }
    #[test]
    fn websocket_early_data_matches_upstream_split_semantics() {
        for (path, expected_path, expected_ed) in [
            ("/live?ed=2048&x=1", "/live?x=1", Some(2048u64)),
            ("/?ed=123", "/", Some(123u64)),
            ("/live?ed=0&x=1", "/live?ed=0&x=1", None),
            ("/live?ed=-1", "/live?ed=-1", None),
            ("/live?ed=9007199254740992", "/live?ed=9007199254740992", None),
            ("/live?foo=1", "/live?foo=1", None),
            ("/live?ed=3&ed=5", "/live?ed=5", Some(3u64)),
        ] {
            let (actual_path, actual_ed) = ws_path_early_data(path);
            assert_eq!(actual_path, expected_path);
            assert_eq!(actual_ed, expected_ed);
        }
        let parsed = parse_uri("trojan://secret@example.org:443?type=ws&path=%2Flive%3Fed%3D1024%26x%3D1").unwrap();
        assert_eq!(parsed["ws-opts"]["path"].as_str(), Some("/live?x=1"));
        assert_eq!(parsed["ws-opts"]["max-early-data"].as_i64(), Some(1024));
        assert_eq!(parsed["ws-opts"]["early-data-header-name"].as_str(), Some("Sec-WebSocket-Protocol"));
    }
    #[test]
    fn grpc_aliases_and_tls_parameter_aliases() {
        let parsed = parse_uri("vless://uuid@example.org:443?type=grpc&service_name=chat&peer=edge.example.org&fingerprint=chrome&allow_insecure=1").unwrap();
        assert_eq!(parsed["grpc-opts"]["grpc-service-name"].as_str(), Some("chat"));
        assert_eq!(parsed["servername"].as_str(), Some("edge.example.org"));
        assert_eq!(parsed["client-fingerprint"].as_str(), Some("chrome"));
        assert_eq!(parsed["skip-cert-verify"].as_bool(), Some(true));
    }
    #[test]
    fn accepts_upstream_default_tls_ports() {
        assert_eq!(parse_uri("trojan://secret@example.org").unwrap()["port"].as_i64(), Some(443));
        assert_eq!(parse_uri("vless://uuid@example.org?security=tls").unwrap()["port"].as_i64(), Some(443));
    }
    #[test]
    fn percent_encoded_trojan_password_and_chinese_name() {
        let parsed=parse_uri("trojan://a%3Ab@example.org:443#%E6%B5%8B%E8%AF%95").unwrap();
        assert_eq!(parsed["password"].as_str(),Some("a:b"));
        assert_eq!(parsed["name"].as_str(),Some("测试"));
        let parsed=parse_uri("trojan://first:second@example.org:443").unwrap();
        assert_eq!(parsed["password"].as_str(),Some("first:second"));
    }
    #[test]
    fn trojan_websocket_transport_and_unsupported_transport() {
        let parsed=parse_uri("trojan://secret@example.org:443?type=ws&path=%2Fchat&host=cdn.example.org&allowInsecure=1#Hello").unwrap();
        assert_eq!(parsed["ws-opts"]["path"].as_str(),Some("/chat"));
        assert_eq!(parsed["ws-opts"]["headers"]["Host"].as_str(),Some("cdn.example.org"));
        assert_eq!(parsed["skip-cert-verify"].as_bool(),Some(true));
        assert!(parse_uri("trojan://secret@example.org:443?type=splithttp").is_err());
    }
    #[test]
    fn rejects_invalid_nodes_and_source_schemes() {
        assert!(parse_document("proxies:\n  - {name: A, type: ss, server: example.org, port: 0}").is_err());
        assert!(parse_uri("file:///etc/passwd").is_err());
    }
    #[test]
    fn drops_remote_dialer_proxy_controls_but_keeps_other_fields() {
        let doc="proxies:\n  - {name: Relay, type: ss, server: example.org, port: 8388, cipher: aes-128-gcm, password: pass, dialer-proxy: Evil}\n";
        let parsed=parse_document(doc).unwrap();
        assert!(parsed[0].get("dialer-proxy").is_none());
        assert_eq!(parsed[0]["cipher"].as_str(),Some("aes-128-gcm"));
    }

}
