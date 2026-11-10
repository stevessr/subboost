//! Native URI compatibility for additional upstream SubBoost protocols.
//! Reject unsupported transports rather than silently producing broken nodes.
use base64::{engine::general_purpose::{STANDARD,URL_SAFE_NO_PAD}, Engine};
use serde_json::{json,Value as Json};
use serde_yaml::Value;
use url::Url;

fn node(value:Json)->Result<Value,String>{
    serde_yaml::to_value(value).map_err(|e|e.to_string())
}
fn decode(input:&str)->String{
    percent_encoding::percent_decode_str(input).decode_utf8_lossy().to_string()
}
fn url_name(url:&Url)->String {
    url.fragment().map(decode).filter(|s|!s.is_empty())
        .unwrap_or_else(||url.host_str().unwrap_or("Proxy").to_string())
}
fn endpoint(url:&Url,default:u16)->Result<(String,u16),String>{
    let server=url.host_str().filter(|s|!s.is_empty()).ok_or("Missing hostname")?;
    let port=url.port().unwrap_or(default);
    if port==0{return Err("Zero port".into());}
    Ok((server.into(),port))
}
fn param(url:&Url,keys:&[&str])->Option<String>{
    let query=url.query_pairs();
    for key in keys{
        if let Some((_,v))=query.clone().find(|(k,_)|k==*key && !v.is_empty()){
            return Some(v.to_string());
        }
    }
    None
}
fn insecure(url:&Url)->bool{
    param(url,&["insecure","allowInsecure","allow_insecure","skip-cert-verify"])
        .map(|v|matches!(v.to_ascii_lowercase().as_str(),"1"|"true"|"yes")).unwrap_or(false)
}
fn alpn(url:&Url)->Option<Vec<String>>{
    param(url,&["alpn"]).map(|list|list.split(',').map(str::trim)
        .filter(|s|!s.is_empty()).map(str::to_string).collect())
}
fn put(obj:&mut Json,key:&str,value:Option<String>){
    if let Some(s)=value.filter(|s|!s.is_empty()) {obj[key]=json!(s);}
}
fn uri(url:&str,canonical:&str,alias:&str)->Result<Url,String>{
    let fixed=if let Some(rest)=url.strip_prefix(alias){
        format!("{canonical}{rest}")
    } else {url.to_string()};
    Url::parse(&fixed).map_err(|e|e.to_string())
}
fn hysteria2(raw:&str)->Result<Value,String>{
    let url=uri(raw,"hysteria2://","hy2://")?;
    let (server,port)=endpoint(&url,443)?;
    let password=decode(url.username());
    let password=if password.is_empty(){
        param(&url,&["password","auth","auth_str","auth-str"]).unwrap_or_default()
    }else{password};
    if password.is_empty(){return Err("Hysteria2 password required".into());}
    let mut data=json!({"name":url_name(&url),"type":"hysteria2",
        "server":server,"port":port,"password":password});
    put(&mut data,"sni",param(&url,&["sni","peer"]));
    if insecure(&url){data["skip-cert-verify"]=json!(true);}
    if let Some(alpn)=alpn(&url){data["alpn"]=json!(alpn);}
    if let Some(obfs)=param(&url,&["obfs"]){
        if !matches!(obfs.as_str(),"salamander"|"gecko"|"none"){
            return Err(format!("Unsupported Hysteria2 obfs: {obfs}"));
        }
        if obfs!="none" {
            let password=param(&url,&["obfs-password","obfs_password"])
                .ok_or("Hysteria2 obfs password required")?;
            data["obfs"]=json!(obfs);
            data["obfs-password"]=json!(password);
        }
    }
    put(&mut data,"ports",param(&url,&["ports","mport"]));
    put(&mut data,"up",param(&url,&["up","upmbps"]));
    put(&mut data,"down",param(&url,&["down","downmbps"]));
    node(data)
}
fn tuic(raw:&str)->Result<Value,String>{
    let url=Url::parse(raw).map_err(|e|e.to_string())?;
    let (server,port)=endpoint(&url,443)?;
    let username=decode(url.username());
    let password=url.password().map(decode).or_else(||param(&url,&["password","passwd"]));
    let mut data=json!({"name":url_name(&url),"type":"tuic",
        "server":server,"port":port});
    if let Some(password)=password {
        if username.is_empty()||password.is_empty(){return Err("TUIC credentials required".into());}
        data["uuid"]=json!(username);
        data["password"]=json!(password);
    }else if let Some(token)=param(&url,&["token","auth"]).or_else(||(!username.is_empty()).then_some(username)){
        data["token"]=json!(token);
    }else{return Err("TUIC token or uuid/password required".into());}
    put(&mut data,"sni",param(&url,&["sni","peer"]));
    put(&mut data,"congestion-controller",param(&url,&["congestion_control","congestion-control"]));
    put(&mut data,"udp-relay-mode",param(&url,&["udp_relay_mode","udp-relay-mode"]));
    if insecure(&url){data["skip-cert-verify"]=json!(true);}
    if let Some(alpn)=alpn(&url){data["alpn"]=json!(alpn);}
    node(data)
}
fn anytls(raw:&str)->Result<Value,String>{
    let url=Url::parse(raw).map_err(|e|e.to_string())?;
    let (server,port)=endpoint(&url,443)?;
    let security=param(&url,&["security"]).unwrap_or_else(||"tls".into());
    let transport=param(&url,&["type","network","transport"]).unwrap_or_else(||"tcp".into());
    if security=="reality" || !matches!(security.as_str(),"tls"|"none"){
        return Err("AnyTLS supports TLS only".into());
    }
    if !matches!(transport.as_str(),"tcp"|"none"){
        return Err("AnyTLS supports raw TCP only".into());
    }
    let password=if let Some(pass)=url.password(){
        format!("{}:{}",decode(url.username()),decode(pass))
    }else{decode(url.username())};
    let password=if password.is_empty(){
        param(&url,&["password","auth","auth_str"]).unwrap_or_default()
    }else{password};
    if password.is_empty(){return Err("AnyTLS password required".into());}
    let mut data=json!({"name":url_name(&url),"type":"anytls",
        "server":server,"port":port,"password":password});
    put(&mut data,"sni",param(&url,&["sni","peer"]));
    put(&mut data,"client-fingerprint",param(&url,&["fp","fingerprint"]));
    if let Some(alpn)=alpn(&url){data["alpn"]=json!(alpn);}
    if insecure(&url){data["skip-cert-verify"]=json!(true);}
    node(data)
}
fn ssr(raw:&str)->Result<Value,String>{
    let encoded=raw.strip_prefix("ssr://").unwrap_or("");
    let mut padded=encoded.to_string();
    while padded.len()%4!=0{padded.push('=');}
    let bytes=STANDARD.decode(&padded)
        .or_else(|_|URL_SAFE_NO_PAD.decode(encoded)).map_err(|e|e.to_string())?;
    let payload=String::from_utf8(bytes).map_err(|e|e.to_string())?;
    let (info,query)=payload.split_once("/?").unwrap_or((&payload,""));
    let mut parts:Vec<&str>=info.split(':').collect();
    if parts.len()<6{return Err("Invalid SSR payload".into());}
    let raw_pass=parts.pop().unwrap_or("");
    let obfs=parts.pop().unwrap_or("");
    let cipher=parts.pop().unwrap_or("");
    let protocol=parts.pop().unwrap_or("");
    let port=parts.pop().unwrap_or("").parse::<u16>().map_err(|_|"Invalid SSR port")?;
    let server=parts.join(":").trim_matches(['[',']']).to_string();
    if server.is_empty()||port==0{return Err("Invalid SSR endpoint".into());}
    let decode_b64=|input:&str|->Result<String,String>{
        let mut encoded=input.to_string();
        while encoded.len()%4!=0{encoded.push('=');}
        let raw=STANDARD.decode(&encoded)
            .or_else(|_|URL_SAFE_NO_PAD.decode(input)).map_err(|e|e.to_string())?;
        String::from_utf8(raw).map_err(|e|e.to_string())
    };
    let password=decode_b64(raw_pass)?;
    let query_pairs=url::form_urlencoded::parse(query.as_bytes())
        .into_owned().collect::<std::collections::HashMap<_,_>>();
    let remarks=query_pairs.get("remarks").and_then(|v|decode_b64(v).ok())
        .filter(|v|!v.is_empty()).unwrap_or_else(||server.clone());
    let mut data=json!({"name":remarks,"type":"ssr","server":server,
        "port":port,"cipher":cipher,"password":password,
        "protocol":protocol,"obfs":obfs,"udp":true});
    for (query,field) in [("protoparam","protocol-param"),("obfsparam","obfs-param")]{
        if let Some(value)=query_pairs.get(query).and_then(|v|decode_b64(v).ok()){
            data[field]=json!(value);
        }
    }
    node(data)
}
fn wireguard(raw:&str)->Result<Value,String>{
    let url=uri(raw,"wireguard://","wg://")?;
    let (server,port)=endpoint(&url,51820)?;
    let private=decode(url.username());
    let private=if private.is_empty(){
        param(&url,&["private-key","private_key","privateKey"]).unwrap_or_default()
    }else{private};
    if private.is_empty(){return Err("WireGuard private-key required".into());}
    let mut data=json!({"name":url_name(&url),"type":"wireguard","server":server,
        "port":port,"private-key":private,"udp":true});
    put(&mut data,"public-key",param(&url,&["public-key","publickey","peer-public-key"]));
    put(&mut data,"pre-shared-key",param(&url,&["pre-shared-key","preshared-key"]));
    if let Some(address)=param(&url,&["address","ip"]){
        for value in address.split(','){
            let raw=value.split('/').next().unwrap_or("").trim_matches(['[',']']);
            if raw.contains(':'){data["ipv6"]=json!(raw);}
            else if !raw.is_empty(){data["ip"]=json!(raw);}
        }
    }
    if let Some(mtu)=param(&url,&["mtu"]).and_then(|v|v.parse::<u16>().ok()){
        data["mtu"]=json!(mtu);
    }
    node(data)
}
pub fn parse(raw:&str)->Result<Value,String>{
    if raw.starts_with("hysteria2://")||raw.starts_with("hy2://"){hysteria2(raw)}
    else if raw.starts_with("tuic://"){tuic(raw)}
    else if raw.starts_with("anytls://"){anytls(raw)}
    else if raw.starts_with("ssr://"){ssr(raw)}
    else if raw.starts_with("wireguard://")||raw.starts_with("wg://"){wireguard(raw)}
    else {Err("Unsupported node URI protocol".into())}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imports_hysteria2_tuic_anytls_wireguard() {
        for (uri,kind) in [
            ("hy2://secret@example.org:443?sni=www.example.org#HY2","hysteria2"),
            ("tuic://uuid:password@example.org:443#TUIC","tuic"),
            ("anytls://password@example.org:443#AnyTLS","anytls"),
            ("wg://private@example.org:51820?public-key=pub&address=10.0.0.2#WG","wireguard"),
        ]{
            let node=parse(uri).unwrap();
            assert_eq!(node["type"].as_str(),Some(kind));
            assert_eq!(node["server"].as_str(),Some("example.org"));
        }
        assert!(parse("anytls://password@example.org:443?security=reality").is_err());
    }
    #[test]
    fn decodes_standard_ssr_url() {
        let password=STANDARD.encode("secret");
        let payload=format!("example.org:443:origin:aes-256-cfb:plain:{password}");
        let uri=format!("ssr://{}",STANDARD.encode(payload));
        let node=parse(&uri).unwrap();
        assert_eq!(node["type"].as_str(),Some("ssr"));
        assert_eq!(node["password"].as_str(),Some("secret"));
    }
}
