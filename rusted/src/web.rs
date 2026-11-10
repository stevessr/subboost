use crate::{config, filter, parser, schedule, store, templates, State};
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

async fn fetch_source(_client: &reqwest::Client, source: &str) -> Result<Vec<serde_yaml::Value>, String> {
    let parsed = Url::parse(source).map_err(|e|e.to_string())?;
    if !matches!(parsed.scheme(),"http"|"https") || parsed.host_str().is_none() {
        return Err("Source must be HTTP(S)".into());
    }
    // Explicitly refuse redirects; redirects can bypass admin-selected URL.
    let client=source_client(&parsed).await?;
    let mut response=client.get(source).send().await.map_err(|e|e.to_string())?;
    if !response.status().is_success() {return Err(format!("Source HTTP status {}",response.status()));}
    if response.content_length().map(|n|n>3*1024*1024).unwrap_or(false) {
        return Err("Source is too large".into());
    }
    let mut bytes=Vec::<u8>::new();
    while let Some(chunk)=response.chunk().await.map_err(|e|e.to_string())? {
        if bytes.len()+chunk.len()>3*1024*1024 {return Err("Source exceeds 3 MiB".into());}
        bytes.extend_from_slice(&chunk);
    }
    let data=String::from_utf8(bytes).map_err(|_| "Source is not UTF-8")?;
    parser::parse_document(&data)
}

pub(crate) async fn refresh_profile(state:&State,id:&str) -> Result<store::Subscription,ApiError> {
    let original={
        let db=lock(state)?;
        sql(store::by_id(&db,id))?.ok_or_else(||error(StatusCode::NOT_FOUND,"Not found"))?
    };
    let mut nodes=Vec::new();
    for source in &original.source_urls {
        match fetch_source(&state.client,source).await {
            Ok(found)=>nodes.extend(found),
            Err(e)=>{
                // Preserve a previously working node snapshot on any fetch failure.
                let message=format!("Failed {}: {e}",
                    Url::parse(source).map(|u|
                        u.host_str().unwrap_or("source").to_owned())
                        .unwrap_or_else(|_|"source".into()));
                let db=lock(state)?;
                let persisted=sql(store::save_refresh_if_revision(&db,id,
                    original.revision,&original.nodes_yaml,&message))?;
                if !persisted {
                    return Err(error(StatusCode::CONFLICT,"Sources changed during refresh"));
                }
                sql(schedule::complete(&db,id,false))?;
                return Err(error(StatusCode::BAD_GATEWAY,message));
            }
        }
    }
    let nodes=parser::validate_nodes(nodes).map_err(bad)?;
    let yaml=serde_yaml::to_string(&nodes).map_err(bad)?;
    let db=lock(state)?;
    if !sql(store::save_refresh_if_revision(&db,id,original.revision,&yaml,""))? {
        return Err(error(StatusCode::CONFLICT,"Sources changed during refresh"));
    }
    sql(schedule::complete(&db,id,true))?;
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
    let (sub,options)={
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
        (sub,options)
    };
    match config::generate_filtered(&sub,target,&options) {
        Ok(yaml)=>Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE,"application/yaml; charset=utf-8")
            .header(header::CACHE_CONTROL,"no-store")
            .header("x-content-type-options","nosniff")
            .body(Body::from(yaml)).unwrap(),
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
        .route("/api/templates",get(templates_list).post(templates_create))
        .route("/api/templates/{id}",get(templates_get).put(templates_update)
            .delete(templates_delete))
        .route("/api/subscriptions",get(list).post(create))
        .route("/api/subscriptions/{id}",get(detail).put(update).delete(delete))
        .route("/api/subscriptions/{id}/refresh",axum::routing::post(refresh))
        .route("/api/subscriptions/{id}/schedule",
            get(schedule_get).put(schedule_set).delete(schedule_disable))
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
    async fn authenticated_crud_and_public_export() {
        let db=store::open(std::path::Path::new(":memory:")).unwrap();
        let sub=store::create(&db, store::SubscriptionInput {
            name:"Demo".into(),source_urls:vec![],
            manual_yaml:"proxies:\n  - {name: A, type: ss, server: example.org, port: 8388, cipher: aes-128-gcm, password: pwd}\n".into(),
            rules_text:String::new(),
        }).unwrap();
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
    }
}
