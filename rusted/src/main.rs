mod config;
mod parser;
mod store;
mod web;

use std::{env, net::SocketAddr, path::PathBuf, sync::{Arc, Mutex}};
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct State {
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub admin_token: Arc<String>,
    pub client: reqwest::Client,
}

fn admin_token_file(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        let token = store::random_token();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .write(true).create_new(true).mode(0o600).open(path);
            match file {
                Ok(mut file) => { writeln!(file, "{token}")?; }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e),
            };
        }
        #[cfg(not(unix))]
        std::fs::write(path, format!("{token}\n"))?;
    }
    let token = std::fs::read_to_string(path)?.trim().to_string();
    if token.len() < 32 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short admin token"));
    }
    Ok(token)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = PathBuf::from(env::var("SUBBOOST_DB").unwrap_or_else(|_| "./data/subboost.sqlite".into()));
    let token_file = PathBuf::from(env::var("SUBBOOST_TOKEN_FILE").unwrap_or_else(|_| "./data/admin.token".into()));
    let admin_token = admin_token_file(&token_file)?;
    if env::args().any(|arg| arg == "token") {
        println!("{admin_token}");
        return Ok(());
    }
    let db = store::open(&db_path)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("SubBoost-RS/0.1")
        .build()?;
    let state = State { db: Arc::new(Mutex::new(db)),
        admin_token: Arc::new(admin_token), client };
    let addr: SocketAddr = env::var("SUBBOOST_BIND")
        .unwrap_or_else(|_| "0.0.0.0:3000".into()).parse()?;
    let listener = TcpListener::bind(addr).await?;
    eprintln!("SubBoost-RS listening on {addr}; admin token at {}", token_file.display());
    axum::serve(listener, web::router(state)).await?;
    Ok(())
}
