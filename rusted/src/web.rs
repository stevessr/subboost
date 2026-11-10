use crate::{config, filter, identity, metadata, modules, parser, schedule, store, templates, State};
use axum::{
    body::Body,
    extract::{Path, Query, State as AppState},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize};
use serde_json::{json, Value as JsonValue};
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}};
use subtle::ConstantTimeEq;
use url::Url;

type ApiError = (StatusCode, Json<JsonValue>);
type ApiResult<T> = Result<Json<T>, ApiError>;

fn error(status: StatusCode, message: impl std::fmt::Display) -> ApiError {
    (status, Json(json!({"error": message.to_string()})))
}

fn bad(message: impl std::fmt::Display) -> ApiError { error(StatusCode::BAD_REQUEST, message) }

fn authorized(state: &State, headers: &HeaderMap) -> Result<(), ApiError> {
    let received = headers.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let expected = state.admin_token.as_bytes();
    if received.len() == expected.len() &&
        received.as_bytes().ct_eq(expected).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(error(StatusCode::UNAUTHORIZED, "Invalid admin token"))
    }
}

fn lock(state: &State) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, ApiError> {
    state.db.lock().map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"))
}
fn sql<T>(r: rusqlite::Result<T>) -> Result<T, ApiError> {
    r.map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, format!("SQLite: {e}")))
}
fn validate(input: &store::SubscriptionInput) -> Result<(), ApiError> {
    if input.name.trim().is_empty() || input.name.len() > 128 { return Err(bad("Name must be 1-128 characters")); }
    if input.source_urls.len() > 16 || input.manual_yaml.len() > 512*1024 ||
       input.rules_text.len() > 128*1024 { return Err(bad("Input exceeds limits")); }
    for s in &input.source_urls {
        let url = Url::parse(s).map_err(|_| bad("Invalid source URL"))?;
        if !matches!(url.scheme(),"http"|"https") || url.host_str().is_none()
            || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
            || s.len() > 4096 {
            return Err(bad("Source must be an HTTP(S) URL without embedded credentials or fragment"));
        }
    }
    if !input.manual_yaml.trim().is_empty() {
        let value: serde_yaml::Value = serde_yaml::from_str(&input.manual_yaml)
            .map_err(|e|bad(format!("Invalid manual YAML: {e}")))?;
        if value.as_mapping().is_none() {return Err(bad("Manual YAML must be a mapping"));}
    }
    Ok(())
}

fn html(title: &'static str, source: &'static str, content_type: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        .header("x-subboost-asset", title)
        .body(Body::from(source))
        .unwrap()
}
async fn index() -> Response {
    html("index",include_str!("../ui/index.html"),"text/html; charset=utf-8")
}
async fn js() -> Response {
    html("script",include_str!("../ui/app.js"),"text/javascript; charset=utf-8")
}
async fn css() -> Response {
    html("style",include_str!("../ui/style.css"),"text/css; charset=utf-8")
}
async fn health() -> impl IntoResponse { Json(json!({"status":"ok","engine":"subboost-rs","database":"sqlite"})) }

async fn list(AppState(state): AppState<State>, headers: HeaderMap) -> ApiResult<Vec<store::Subscription>> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    Ok(Json(sql(store::list(&db))?))
}
async fn detail(AppState(state): AppState<State>, headers: HeaderMap,
                Path(id): Path<String>) -> ApiResult<store::Subscription> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    sql(store::by_id(&db,&id))?.map(Json).ok_or_else(||error(StatusCode::NOT_FOUND,"Not found"))
}
async fn create(AppState(state): AppState<State>, headers: HeaderMap,
                Json(input): Json<store::SubscriptionInput>) -> ApiResult<store::Subscription> {
    authorized(&state,&headers)?;
    validate(&input)?;
    let db=lock(&state)?;
    Ok(Json(sql(store::create(&db,input))?))
}
async fn update(AppState(state): AppState<State>, headers: HeaderMap,
                Path(id): Path<String>, Json(input): Json<store::SubscriptionInput>) -> ApiResult<store::Subscription> {
    authorized(&state,&headers)?;
    validate(&input)?;
    let db=lock(&state)?;
    if !sql(store::update(&db,&id,input))? {return Err(error(StatusCode::NOT_FOUND,"Not found"));}
    Ok(Json(sql(store::by_id(&db,&id))?.ok_or_else(||error(StatusCode::NOT_FOUND,"Not found"))?))
}
async fn delete(AppState(state): AppState<State>, headers: HeaderMap,
                Path(id): Path<String>) -> ApiResult<JsonValue> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    if !sql(store::delete(&db,&id))? {return Err(error(StatusCode::NOT_FOUND,"Not found"));}
    Ok(Json(json!({"deleted":true})))
}
async fn rotate(AppState(state): AppState<State>, headers: HeaderMap,
                Path(id): Path<String>) -> ApiResult<store::Subscription> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    if !sql(store::rotate(&db,&id))? {return Err(error(StatusCode::NOT_FOUND,"Not found"));}
    Ok(Json(sql(store::by_id(&db,&id))?.ok_or_else(||error(StatusCode::NOT_FOUND,"Not found"))?))
}

/// Treat all non-globally routable destinations as off-limits by default.
fn public_ipv4(ip:Ipv4Addr)->bool {
    let o=ip.octets();
    !(ip.is_private() || ip.is_loopback() || ip.is_link_local() ||
      ip.is_unspecified() || ip.is_multicast() || ip.is_documentation() ||
      ip.is_broadcast() || o[0]==0 || o[0]>=240 ||
      (o[0]==100 && (64..128).contains(&o[1])) ||
      (o[0]==198 && (18..=19).contains(&o[1])) ||
      (o[0]==192 && o[1]==0 && o[2]==0))
}
fn public_ip(addr:IpAddr)->bool {
    match addr {
        IpAddr::V4(v)=>public_ipv4(v),
        IpAddr::V6(v)=>{
            if let Some(mapped)=v.to_ipv4_mapped(){return public_ipv4(mapped);}
            let seg=v.segments();
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast() ||
              v.is_unique_local() || v.is_unicast_link_local() ||
              (seg[0]==0x2001 && seg[1]==0x0db8) ||
              (seg[0]&0xffc0)==0xfec0)
        }
    }
}

/// Pin all DNS answers into the client, so name rebinding cannot bypass the
/// private-address restriction between validation and HTTP connection.
/// Redirects and environment-configured HTTP proxies are always disabled.
async fn source_client(source:&Url)->Result<reqwest::Client,String>{
    let host=source.host_str().ok_or("Source has no host")?;
    let port=source.port_or_known_default().ok_or("Missing source port")?;
    let addresses:Vec<SocketAddr>=tokio::net::lookup_host((host,port))
        .await.map_err(|e|format!("DNS lookup: {e}"))?.collect();
    if addresses.is_empty(){return Err("Source DNS returned no addresses".into());}
    let allow_private=std::env::var("SUBBOOST_ALLOW_PRIVATE_SOURCES")
        .map(|v|v=="1").unwrap_or(false);
    if !allow_private && addresses.iter().any(|addr|!public_ip(addr.ip())){
        return Err("Private, loopback or reserved source address is blocked".into());
    }
    reqwest::Client::builder()
        .resolve_to_addrs(host,&addresses)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("SubBoost-RS/0.2")
        .build().map_err(|e|e.to_string())
}

async fn fetch_source(_client: &reqwest::Client, source: &str)
    -> Result<(Vec<serde_yaml::Value>,metadata::SubscriptionInfo), String> {
    let parsed = Url::parse(source).map_err(|e|e.to_string())?;
    if !matches!(parsed.scheme(),"http"|"https") || parsed.host_str().is_none() {
        return Err("Source must be HTTP(S)".into());
    }
    // Explicitly refuse redirects; redirects can bypass admin-selected URL.
    let client=source_client(&parsed).await?;
    let mut response=client.get(source).send().await.map_err(|e|e.to_string())?;
    if !response.status().is_success() {return Err(format!("Source HTTP status {}",response.status()));}
    let source_info=response.headers().get("subscription-userinfo")
        .and_then(|v|v.to_str().ok()).map(metadata::SubscriptionInfo::parse)
        .unwrap_or_default();
    if response.content_length().map(|n|n>3*1024*1024).unwrap_or(false) {
        return Err("Source is too large".into());
    }
    let mut bytes=Vec::<u8>::new();
    while let Some(chunk)=response.chunk().await.map_err(|e|e.to_string())? {
        if bytes.len()+chunk.len()>3*1024*1024 {return Err("Source exceeds 3 MiB".into());}
        bytes.extend_from_slice(&chunk);
    }
    let data=String::from_utf8(bytes).map_err(|_| "Source is not UTF-8")?;
    Ok((parser::parse_document(&data)?,source_info))
}

pub(crate) async fn refresh_profile(state:&State,id:&str) -> Result<store::Subscription,ApiError> {
    let original={
        let db=lock(state)?;
        sql(store::by_id(&db,id))?.ok_or_else(||error(StatusCode::NOT_FOUND,"Not found"))?
    };
    let mut nodes=Vec::new();
    let mut successful=Vec::<(String,String,metadata::SubscriptionInfo)>::new();
    let mut combined_info=metadata::SubscriptionInfo::default();
    let mut failures=Vec::<String>::new();
    // Each successful source is persisted independently; one bad source
    // must not erase nodes obtained from another source.
    for source in &original.source_urls {
        match fetch_source(&state.client,source).await {
            Ok((found,source_info))=>{
                let yaml=serde_yaml::to_string(&found).map_err(bad)?;
                nodes.extend(found);
                combined_info.merge(&source_info);
                successful.push((source.clone(),yaml,source_info));
            }
            Err(e)=>{
                let host=Url::parse(source)
                    .ok().and_then(|u|u.host_str().map(str::to_owned))
                    .unwrap_or_else(||"source".into());
                failures.push(format!("{host}: {e}"));
                let (cached,source_info)={
                    let db=lock(state)?;
                    (sql(store::source_nodes(&db,id,source))?,
                     sql(store::source_info(&db,id,source))?)
                };
                if let Some(cached)=cached {
                    match serde_yaml::from_str::<Vec<serde_yaml::Value>>(&cached) {
                        Ok(previous)=>{
                            nodes.extend(previous);
                            combined_info.merge(&source_info);
                        },
                        Err(e)=>failures.push(format!("{host}: cached nodes invalid: {e}"))
                    }
                }
            }
        }
    }
    let error_message=failures.join("; ");
    if !original.source_urls.is_empty() && successful.is_empty() {
        // Keep the known-good full snapshot and report a retryable failure.
        let db=lock(state)?;
        if !sql(store::save_refresh_if_revision(&db,id,original.revision,
                &original.nodes_yaml,&error_message))?{
            return Err(error(StatusCode::CONFLICT,"Profile changed during refresh"));
        }
        sql(schedule::complete(&db,id,false))?;
        return Err(error(StatusCode::BAD_GATEWAY,error_message));
    }
    let nodes=match parser::validate_nodes(nodes) {
        Ok(nodes)=>nodes,
        Err(message)=>{
            let db=lock(state)?;
            if !sql(store::save_refresh_if_revision(&db,id,original.revision,
                    &original.nodes_yaml,&message))?{
                return Err(error(StatusCode::CONFLICT,"Profile changed during refresh"));
            }
            sql(schedule::complete(&db,id,false))?;
            return Err(bad(message));
        }
    };
    if original.source_urls.len()>0 && nodes.is_empty(){
        let message="All subscription sources returned zero nodes";
        let db=lock(state)?;
        if !sql(store::save_refresh_if_revision(&db,id,original.revision,
                &original.nodes_yaml,message))?{
            return Err(error(StatusCode::CONFLICT,"Profile changed during refresh"));
        }
        sql(schedule::complete(&db,id,false))?;
        return Err(bad(message));
    }
    let yaml=serde_yaml::to_string(&nodes).map_err(bad)?;
    let db=lock(state)?;
    if !sql(store::commit_refresh_if_revision(&db,id,original.revision,&yaml,
             &error_message,&successful,Some(&combined_info)))?{
        return Err(error(StatusCode::CONFLICT,"Profile changed during refresh"));
    }
    sql(schedule::complete(&db,id,failures.is_empty()))?;
    sql(store::by_id(&db,id))?.ok_or_else(||error(StatusCode::NOT_FOUND,"Not found"))
}

async fn refresh(AppState(state): AppState<State>, headers: HeaderMap,
                 Path(id): Path<String>) -> ApiResult<store::Subscription> {
    authorized(&state,&headers)?;
    Ok(Json(refresh_profile(&state,&id).await?))
}

#[derive(Deserialize)]
struct ScheduleInput { interval_seconds:i64 }

async fn schedule_get(AppState(state):AppState<State>, headers:HeaderMap,
    Path(id):Path<String>) -> ApiResult<Option<schedule::Schedule>> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    if sql(store::by_id(&db,&id))?.is_none() {
        return Err(error(StatusCode::NOT_FOUND,"Subscription not found"));
    }
    Ok(Json(sql(schedule::get(&db,&id))?))
}

async fn schedule_set(AppState(state):AppState<State>, headers:HeaderMap,
    Path(id):Path<String>,Json(input):Json<ScheduleInput>)
    -> ApiResult<schedule::Schedule> {
    authorized(&state,&headers)?;
    if !(schedule::MIN_INTERVAL..=schedule::MAX_INTERVAL).contains(&input.interval_seconds) {
        return Err(bad("Auto refresh interval must be 360-604800 seconds"));
    }
    let db=lock(&state)?;
    sql(schedule::set(&db,&id,input.interval_seconds))?.map(Json)
        .ok_or_else(||error(StatusCode::NOT_FOUND,"Subscription not found"))
}

async fn schedule_disable(AppState(state):AppState<State>, headers:HeaderMap,
    Path(id):Path<String>) -> ApiResult<JsonValue> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    Ok(Json(json!({"disabled":sql(schedule::disable(&db,&id))?})))
}

async fn export(AppState(state): AppState<State>,
                Path(token): Path<String>, Query(query): Query<HashMap<String,String>>) -> Response {
    let target=query.get("target").map(String::as_str).unwrap_or("mihomo");
    if !matches!(target,"mihomo"|"clash-rs"|"nikki-rs") {
        return error(StatusCode::BAD_REQUEST,"Unsupported target").into_response();
    }
    let (sub,options,subscription_info,refresh_interval,enabled_modules,aliases)={
        let db=match lock(&state) {Ok(v)=>v,Err(e)=>return e.into_response()};
        let sub=match sql(store::by_token(&db,&token)) {
            Ok(Some(s))=>s,
            Ok(None)=>return error(StatusCode::NOT_FOUND,"Subscription not found").into_response(),
            Err(e)=>return e.into_response(),
        };
        let options=match sql(filter::get(&db,&sub.id)){
            Ok(v)=>v,
            Err(e)=>return e.into_response(),
        };
        let info=match sql(store::info(&db,&sub.id)){
            Ok(v)=>v,
            Err(e)=>return e.into_response(),
        };
        let interval=match sql(schedule::get(&db,&sub.id)){
            Ok(v)=>v.map(|s|s.interval_seconds),
            Err(e)=>return e.into_response(),
        };
        let enabled=match sql(modules::get(&db,&sub.id)){
            Ok(v)=>v,
            Err(e)=>return e.into_response(),
        };
        let aliases=match sql(identity::aliases(&db,&sub.id)){
            Ok(v)=>v,
            Err(e)=>return e.into_response(),
        };
        (sub,options,info,interval,enabled,aliases)
    };
    match config::generate_with_aliases(&sub,target,&options,&enabled_modules,&aliases) {
        Ok(yaml)=>{
            // Only use percent-encoded RFC 5987 filenames to avoid header
            // injection from user-supplied configuration names.
            let encoded=percent_encoding::utf8_percent_encode(
                &sub.name,percent_encoding::NON_ALPHANUMERIC).to_string();
            let mut response=Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE,"text/yaml; charset=utf-8")
                .header(header::CONTENT_DISPOSITION,
                    format!("attachment; filename*=UTF-8''{encoded}"))
                .header(header::CACHE_CONTROL,"no-store")
                .header("x-content-type-options","nosniff");
            if let Some(quota)=subscription_info.header(){
                response=response.header("subscription-userinfo",quota);
            }
            if let Some(seconds)=refresh_interval {
                response=response.header("profile-update-interval",
                    ((seconds+3599)/3600).max(1).to_string());
            }
            response.body(Body::from(yaml)).unwrap()
        },
        Err(e)=>error(StatusCode::UNPROCESSABLE_ENTITY,e).into_response(),
    }
}

fn validate_template(input: &templates::TemplateInput) -> Result<(), ApiError> {
    if input.name.trim().is_empty() || input.name.len()>128 ||
        input.description.len()>512 || input.manual_yaml.len()>512*1024 ||
        input.rules_text.len()>128*1024 {
        return Err(bad("Template name must be 1-128 characters and body within limits"));
    }
    if !input.manual_yaml.trim().is_empty() {
        let doc: serde_yaml::Value=serde_yaml::from_str(&input.manual_yaml)
            .map_err(|e|bad(format!("Invalid template YAML: {e}")))?;
        if doc.as_mapping().is_none() { return Err(bad("Template YAML must be a mapping")); }
    }
    Ok(())
}

async fn templates_list(AppState(state): AppState<State>,headers: HeaderMap)
    -> ApiResult<Vec<templates::Template>> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    Ok(Json(sql(templates::list(&db))?))
}
async fn templates_get(AppState(state): AppState<State>,headers: HeaderMap,Path(id):Path<String>)
    -> ApiResult<templates::Template> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    sql(templates::get(&db,&id))?.map(Json)
        .ok_or_else(||error(StatusCode::NOT_FOUND,"Template not found"))
}
async fn templates_create(AppState(state): AppState<State>,headers: HeaderMap,
    Json(input):Json<templates::TemplateInput>) -> ApiResult<templates::Template> {
    authorized(&state,&headers)?;
    validate_template(&input)?;
    let db=lock(&state)?;
    Ok(Json(sql(templates::create(&db,input))?))
}
async fn templates_export(AppState(state): AppState<State>,headers:HeaderMap,
    Path(id):Path<String>) -> ApiResult<templates::PortableTemplate> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    let template=sql(templates::get(&db,&id))?
        .ok_or_else(||error(StatusCode::NOT_FOUND,"Template not found"))?;
    Ok(Json(templates::PortableTemplate::from_template(&template)))
}

async fn templates_import(AppState(state): AppState<State>,headers:HeaderMap,
    Json(payload):Json<templates::PortableTemplate>) -> ApiResult<templates::Template> {
    authorized(&state,&headers)?;
    let input=payload.into_input().map_err(bad)?;
    validate_template(&input)?;
    let db=lock(&state)?;
    Ok(Json(sql(templates::create(&db,input))?))
}

async fn templates_update(AppState(state): AppState<State>,headers: HeaderMap,
    Path(id):Path<String>,Json(input):Json<templates::TemplateInput>)
    -> ApiResult<templates::Template> {
    authorized(&state,&headers)?;
    validate_template(&input)?;
    let db=lock(&state)?;
    sql(templates::update(&db,&id,input))?.map(Json)
        .ok_or_else(||error(StatusCode::NOT_FOUND,"Template not found or built-in"))
}
async fn templates_delete(AppState(state): AppState<State>,headers: HeaderMap,
    Path(id):Path<String>) -> ApiResult<JsonValue> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    if !sql(templates::delete(&db,&id))? {
        return Err(error(StatusCode::NOT_FOUND,"Template not found or built-in"));
    }
    Ok(Json(json!({"deleted":true})))
}


#[derive(Deserialize)]
struct RuleCatalogQuery {
    q:Option<String>,
    limit:Option<usize>,
}

async fn module_rules_search(
    AppState(state):AppState<State>, headers:HeaderMap, Query(query):Query<RuleCatalogQuery>
) -> ApiResult<JsonValue> {
    authorized(&state,&headers)?;
    let keyword=query.q.unwrap_or_default().trim().to_lowercase();
    if keyword.chars().count()>128 {
        return Err(bad("Rule search keyword too long (max 128 characters)"));
    }
    let limit=query.limit.unwrap_or(20).clamp(1,50);
    let mut items=Vec::new();
    let mut matched=0usize;
    for module in modules::all() {
        for rule in &module.rules {
            if !keyword.is_empty() && ![
                module.id.as_str(),module.name.as_str(),rule.id.as_str(),
                rule.name.as_str(),rule.path.as_str(),rule.behavior.as_str()
            ].iter().any(|field|field.to_lowercase().contains(&keyword)){
                continue;
            }
            matched+=1;
            if items.len()<limit {
                items.push(json!({
                    "module_id":module.id,"module_name":module.name,
                    "rule_id":rule.id,"rule_name":rule.name,
                    "behavior":rule.behavior,"path":rule.path,
                    "no_resolve":rule.no_resolve
                }));
            }
        }
    }
    Ok(Json(json!({"items":items,"total_matched":matched,
        "total_rules":modules::all().iter().map(|m|m.rules.len()).sum::<usize>()})))
}

#[derive(Deserialize)]
struct NodeAliasInput { name:String }

fn profile_nodes(sub:&store::Subscription)->Result<Vec<serde_yaml::Value>,String>{
    let mut nodes=Vec::new();
    if !sub.manual_yaml.trim().is_empty() {
        let document:serde_yaml::Value=serde_yaml::from_str(&sub.manual_yaml)
            .map_err(|e|e.to_string())?;
        if let Some(manual)=document.get("proxies").and_then(serde_yaml::Value::as_sequence) {
            nodes.extend(manual.iter().cloned());
        }
    }
    if !sub.nodes_yaml.trim().is_empty(){
        let cached:Vec<serde_yaml::Value>=serde_yaml::from_str(&sub.nodes_yaml)
            .map_err(|e|e.to_string())?;
        nodes.extend(cached);
    }
    parser::validate_nodes(nodes)
}

async fn profile_nodes_get(AppState(state):AppState<State>,headers:HeaderMap,
    Path(id):Path<String>) -> ApiResult<JsonValue>{
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    let sub=sql(store::by_id(&db,&id))?
        .ok_or_else(||error(StatusCode::NOT_FOUND,"Subscription not found"))?;
    let aliases=sql(identity::aliases(&db,&id))?;
    let nodes=profile_nodes(&sub).map_err(bad)?;
    let mut result=Vec::with_capacity(nodes.len());
    for node in nodes{
        let key=identity::hash(&id,&node).map_err(bad)?;
        result.push(json!({
            "key":key,
            "name":node["name"],
            "type":node["type"],
            "server":node["server"],
            "port":node["port"],
            "alias":aliases.get(&key)
        }));
    }
    Ok(Json(json!(result)))
}

async fn profile_alias_set(AppState(state):AppState<State>,headers:HeaderMap,
    Path((id,key)):Path<(String,String)>,Json(input):Json<NodeAliasInput>)
    -> ApiResult<JsonValue>{
    authorized(&state,&headers)?;
    identity::validate_alias(&key,&input.name).map_err(bad)?;
    let db=lock(&state)?;
    let sub=sql(store::by_id(&db,&id))?
        .ok_or_else(||error(StatusCode::NOT_FOUND,"Subscription not found"))?;
    let nodes=profile_nodes(&sub).map_err(bad)?;
    let mut known=false;
    for node in &nodes {
        if identity::hash(&id,node).map_err(bad)?==key {
            known=true;
            break;
        }
    }
    if !known {return Err(error(StatusCode::NOT_FOUND,"Node identity not found"));}
    if !sql(identity::put_alias(&db,&id,&key,&input.name))? {
        return Err(error(StatusCode::NOT_FOUND,"Subscription not found"));
    }
    Ok(Json(json!({"key":key,"alias":input.name.trim()})))
}

async fn profile_alias_delete(AppState(state):AppState<State>,headers:HeaderMap,
    Path((id,key)):Path<(String,String)>) -> ApiResult<JsonValue>{
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    if sql(store::by_id(&db,&id))?.is_none(){
        return Err(error(StatusCode::NOT_FOUND,"Subscription not found"));
    }
    Ok(Json(json!({"deleted":sql(identity::delete_alias(&db,&id,&key))?})))
}

async fn modules_catalog(AppState(state):AppState<State>,headers:HeaderMap)
    -> ApiResult<Vec<modules::Module>>{
    authorized(&state,&headers)?;
    Ok(Json(modules::all().to_vec()))
}

async fn profile_modules_get(AppState(state):AppState<State>,headers:HeaderMap,
    Path(id):Path<String>) -> ApiResult<Vec<String>>{
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    if sql(store::by_id(&db,&id))?.is_none(){
        return Err(error(StatusCode::NOT_FOUND,"Subscription not found"));
    }
    Ok(Json(sql(modules::get(&db,&id))?))
}

#[derive(Deserialize)]
struct ModuleSelection { enabled:Vec<String> }

async fn profile_modules_set(AppState(state):AppState<State>,headers:HeaderMap,
    Path(id):Path<String>,Json(input):Json<ModuleSelection>) -> ApiResult<Vec<String>>{
    authorized(&state,&headers)?;
    modules::validate(&input.enabled).map_err(bad)?;
    let db=lock(&state)?;
    if !sql(modules::put(&db,&id,&input.enabled))?{
        return Err(error(StatusCode::NOT_FOUND,"Subscription not found"));
    }
    Ok(Json(input.enabled))
}

async fn subscription_info(AppState(state):AppState<State>, headers:HeaderMap,
    Path(id):Path<String>) -> ApiResult<metadata::SubscriptionInfo> {
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    if sql(store::by_id(&db,&id))?.is_none(){
        return Err(error(StatusCode::NOT_FOUND,"Subscription not found"));
    }
    Ok(Json(sql(store::info(&db,&id))?))
}

async fn filter_get(AppState(state):AppState<State>, headers:HeaderMap,
    Path(id):Path<String>) -> ApiResult<filter::NodeNameFilter>{
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    if sql(store::by_id(&db,&id))?.is_none(){
        return Err(error(StatusCode::NOT_FOUND,"Subscription not found"));
    }
    Ok(Json(sql(filter::get(&db,&id))?))
}

async fn filter_set(AppState(state):AppState<State>, headers:HeaderMap,
    Path(id):Path<String>,Json(input):Json<filter::NodeNameFilter>)
    -> ApiResult<filter::NodeNameFilter>{
    authorized(&state,&headers)?;
    filter::validate(&input).map_err(bad)?;
    let db=lock(&state)?;
    if !sql(filter::put(&db,&id,&input))?{
        return Err(error(StatusCode::NOT_FOUND,"Subscription not found"));
    }
    Ok(Json(input))
}

async fn filter_delete(AppState(state):AppState<State>, headers:HeaderMap,
    Path(id):Path<String>) -> ApiResult<JsonValue>{
    authorized(&state,&headers)?;
    let db=lock(&state)?;
    Ok(Json(json!({"deleted":sql(filter::delete(&db,&id))?})))
}

pub fn router(state: State) -> Router {
    Router::new()
        .route("/",get(index))
        .route("/app.js",get(js))
        .route("/style.css",get(css))
        .route("/api/health/live",get(health))
        .route("/api/modules",get(modules_catalog))
        .route("/api/module-rules/search",get(module_rules_search))
        .route("/api/subscriptions/{id}/modules",
            get(profile_modules_get).put(profile_modules_set))
        .route("/api/subscriptions/{id}/nodes",get(profile_nodes_get))
        .route("/api/subscriptions/{id}/node-aliases/{key}",
            axum::routing::put(profile_alias_set).delete(profile_alias_delete))
        .route("/api/templates",get(templates_list).post(templates_create))
        .route("/api/templates/import",axum::routing::post(templates_import))
        .route("/api/templates/{id}/export",get(templates_export))
        .route("/api/templates/{id}",get(templates_get).put(templates_update)
            .delete(templates_delete))
        .route("/api/subscriptions",get(list).post(create))
        .route("/api/subscriptions/{id}",get(detail).put(update).delete(delete))
        .route("/api/subscriptions/{id}/refresh",axum::routing::post(refresh))
        .route("/api/subscriptions/{id}/schedule",
            get(schedule_get).put(schedule_set).delete(schedule_disable))
        .route("/api/subscriptions/{id}/info",get(subscription_info))
        .route("/api/subscriptions/{id}/filter",
            get(filter_get).put(filter_set).delete(filter_delete))
        .route("/api/subscriptions/{id}/rotate",axum::routing::post(rotate))
        .route("/api/subscriptions/{token}/config.yaml",get(export))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;
    #[test]
    fn protects_private_addresses_and_mapped_ipv6() {
        for ip in ["127.0.0.1","10.0.0.1","192.168.1.1","100.64.0.1",
                   "198.18.0.1","169.254.1.1","224.0.0.1","0.0.0.0",
                   "::1","fd00::1","fe80::1","::ffff:127.0.0.1"] {
            assert!(!public_ip(ip.parse().unwrap()),"{ip}");
        }
        for ip in ["1.1.1.1","8.8.8.8","2606:4700:4700::1111"] {
            assert!(public_ip(ip.parse().unwrap()),"{ip}");
        }
    }
    #[tokio::test]
    async fn node_alias_api_persists_and_affects_public_config_export() {
        let db=store::open(std::path::Path::new(":memory:")).unwrap();
        let sub=store::create(&db,store::SubscriptionInput{
            name:"Renaming".into(),source_urls:vec![],
            manual_yaml:"proxies:\n  - {name: Original, type: ss, server: edge.example.org, port: 8388, cipher: aes-128-gcm, password: secret}\n".into(),
            rules_text:String::new()
        }).unwrap();
        let app=router(State{
            db:std::sync::Arc::new(std::sync::Mutex::new(db)),
            admin_token:std::sync::Arc::new("x".repeat(43)),
            client:reqwest::Client::new()
        });
        let token=format!("Bearer {}","x".repeat(43));
        let uri=format!("/api/subscriptions/{}/nodes",sub.id);
        let response=app.clone().oneshot(Request::builder().uri(&uri)
            .header("Authorization",&token).body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(response.status(),StatusCode::OK);
        let bytes=axum::body::to_bytes(response.into_body(),1024*1024).await.unwrap();
        let nodes:JsonValue=serde_json::from_slice(&bytes).unwrap();
        let hash=nodes[0]["key"].as_str().unwrap();
        assert_eq!(hash.len(),64);
        assert!(nodes[0].get("password").is_none());
        let uri=format!("/api/subscriptions/{}/node-aliases/{}",sub.id,hash);
        let result=app.clone().oneshot(Request::builder().uri(&uri).method("PUT")
            .header("Authorization",&token).header("Content-Type","application/json")
            .body(Body::from(r#"{"name":"Renamed"}"#)).unwrap())
            .await.unwrap();
        assert_eq!(result.status(),StatusCode::OK);
        let output=app.clone().oneshot(Request::builder()
            .uri(format!("/api/subscriptions/{}/config.yaml?target=mihomo",sub.token))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(output.status(),StatusCode::OK);
        let bytes=axum::body::to_bytes(output.into_body(),1024*1024).await.unwrap();
        let config:serde_yaml::Value=serde_yaml::from_slice(&bytes).unwrap();
        assert_eq!(config["proxies"][0]["name"].as_str(),Some("Renamed"));
        assert_eq!(config["proxy-groups"][0]["proxies"][1].as_str(),Some("Renamed"));
        let result=app.clone().oneshot(Request::builder().uri(&uri).method("DELETE")
            .header("Authorization",&token).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(result.status(),StatusCode::OK);
        let output=app.oneshot(Request::builder()
            .uri(format!("/api/subscriptions/{}/config.yaml?target=mihomo",sub.token))
            .body(Body::empty()).unwrap()).await.unwrap();
        let bytes=axum::body::to_bytes(output.into_body(),1024*1024).await.unwrap();
        let config:serde_yaml::Value=serde_yaml::from_slice(&bytes).unwrap();
        assert_eq!(config["proxies"][0]["name"].as_str(),Some("Original"));
    }
    #[tokio::test]
    async fn portable_template_export_and_import_require_admin() {
        let db=store::open(std::path::Path::new(":memory:")).unwrap();
        let template=templates::create(&db,templates::TemplateInput {
            name:"Portable".into(),description:"Test".into(),
            manual_yaml:"dns:\n  enable: true".into(),
            rules_text:"MATCH,DIRECT".into(),
        }).unwrap();
        let state=State {
            db:std::sync::Arc::new(std::sync::Mutex::new(db)),
            admin_token:std::sync::Arc::new("x".repeat(43)),
            client:reqwest::Client::new(),
        };
        let app=router(state);
        let uri=format!("/api/templates/{}/export",template.id);
        let denied=app.clone().oneshot(Request::builder().uri(&uri)
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(denied.status(),StatusCode::UNAUTHORIZED);
        let exported=app.clone().oneshot(Request::builder().uri(&uri)
            .header("Authorization",format!("Bearer {}","x".repeat(43)))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(exported.status(),StatusCode::OK);
        let bytes=axum::body::to_bytes(exported.into_body(),1024*1024).await.unwrap();
        let portable:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(portable["version"],1);
        assert_eq!(portable["format"],"subboost-rs-template");
        assert!(portable.get("id").is_none());
        let imported=app.clone().oneshot(Request::builder().uri("/api/templates/import")
            .method("POST")
            .header("Authorization",format!("Bearer {}","x".repeat(43)))
            .header("Content-Type","application/json")
            .body(Body::from(bytes.clone())).unwrap()).await.unwrap();
        assert_eq!(imported.status(),StatusCode::OK);
        let bytes=axum::body::to_bytes(imported.into_body(),1024*1024).await.unwrap();
        let imported:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(imported["name"],"Portable");
        assert_ne!(imported["id"],template.id);

        let mut invalid=portable.clone();
        invalid["version"]=json!(2);
        let rejected=app.oneshot(Request::builder().uri("/api/templates/import")
            .method("POST")
            .header("Authorization",format!("Bearer {}","x".repeat(43)))
            .header("Content-Type","application/json")
            .body(Body::from(invalid.to_string())).unwrap()).await.unwrap();
        assert_eq!(rejected.status(),StatusCode::BAD_REQUEST);
    }
    #[tokio::test]
    async fn rule_catalog_search_is_authenticated_and_bounded() {
        let db=store::open(std::path::Path::new(":memory:")).unwrap();
        let app=router(State {
            db:std::sync::Arc::new(std::sync::Mutex::new(db)),
            admin_token:std::sync::Arc::new("x".repeat(43)),
            client:reqwest::Client::new(),
        });
        let path="/api/module-rules/search?q=geosite&limit=3";
        let denied=app.clone().oneshot(Request::builder().uri(path)
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(denied.status(),StatusCode::UNAUTHORIZED);
        let response=app.clone().oneshot(Request::builder().uri(path)
            .header("Authorization",format!("Bearer {}","x".repeat(43)))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(),StatusCode::OK);
        let bytes=axum::body::to_bytes(response.into_body(),64*1024).await.unwrap();
        let body:JsonValue=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(),3);
        assert!(body["total_matched"].as_u64().unwrap()>=3);
        assert_eq!(body["total_rules"].as_u64(),Some(94));
        let invalid=app.oneshot(Request::builder().uri(
            format!("/api/module-rules/search?q={}", "a".repeat(129)))
            .header("Authorization",format!("Bearer {}","x".repeat(43)))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(invalid.status(),StatusCode::BAD_REQUEST);
    }
    #[tokio::test]
    async fn authenticated_crud_and_public_export() {
        let db=store::open(std::path::Path::new(":memory:")).unwrap();
        let sub=store::create(&db, store::SubscriptionInput {
            name:"Demo".into(),source_urls:vec![],
            manual_yaml:"proxies:\n  - {name: A, type: ss, server: example.org, port: 8388, cipher: aes-128-gcm, password: pwd}\n".into(),
            rules_text:String::new(),
        }).unwrap();
        let info=metadata::SubscriptionInfo::parse(
            "upload=1024; download=2048; total=8192; expire=1800000000");
        assert!(store::commit_refresh_if_revision(&db,&sub.id,sub.revision,
            "", "", &[],Some(&info)).unwrap());
        let state=State {db:std::sync::Arc::new(std::sync::Mutex::new(db)),
            admin_token:std::sync::Arc::new("s".repeat(43)),
            client:reqwest::Client::new()};
        let app=router(state);
        let denied=app.clone().oneshot(Request::builder().uri("/api/subscriptions")
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(denied.status(),StatusCode::UNAUTHORIZED);
        let allowed=app.clone().oneshot(Request::builder().uri("/api/subscriptions")
            .header("Authorization",format!("Bearer {}","s".repeat(43)))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(allowed.status(),StatusCode::OK);
        let yaml=app.clone().oneshot(Request::builder()
            .uri(format!("/api/subscriptions/{}/config.yaml?target=clash-rs",sub.token))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(yaml.status(),StatusCode::OK);
        assert_eq!(yaml.headers().get("subscription-userinfo").unwrap(),
            "upload=1024; download=2048; total=8192; expire=1800000000");
        assert!(yaml.headers().get("content-disposition").is_some());
    }
}
