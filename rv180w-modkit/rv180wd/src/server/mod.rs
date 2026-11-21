use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde::{Deserialize, Serialize};

use crate::auth::csrf::validate_csrf;
use crate::auth::ratelimit::LoginRateLimiter;
use crate::auth::session::{SessionStore, SESSION_COOKIE_NAME};
use crate::auth::store as auth_store;
use crate::config::diff::{diff_subsystems, Subsystem};
use crate::config::schema::Config;
use crate::config::store as cfg_store;
use crate::reconciler;
use crate::telemetry;
use crate::upgrade;

const IO_BUF_SIZE: usize = 8192;
const MAX_HEADER_BYTES: usize = 32_768;
const MAX_BODY_BYTES: usize = 512 * 1024;
const SAFE_ROLLBACK_SECS: u64 = 60;
const FALLBACK_CERT_DIR: &str = "/tmp/rv180wd-certs";
const SPA_HTML: &str = include_str!("../../web-ui/index.html");

#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub http_addr: String,
    pub https_addr: Option<String>,
    pub data_dir: PathBuf,
    pub san_ip: String,
    pub max_workers: usize,
}

impl ServerOptions {
    pub fn from_env() -> Self {
        let https_env = std::env::var("RV180WD_HTTPS_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:443".to_string());
        let https_addr = if https_env.is_empty() || https_env == "none" {
            None
        } else {
            Some(https_env)
        };
        Self {
            http_addr: std::env::var("RV180WD_HTTP_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:80".to_string()),
            https_addr,
            data_dir: cfg_store::data_dir(),
            san_ip: std::env::var("RV180WD_SAN_IP")
                .unwrap_or_else(|_| "192.168.1.1".to_string()),
            max_workers: std::env::var("RV180WD_MAX_WORKERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8)
                .clamp(1, 16),
        }
    }
}

struct PendingRollback {
    deadline: Instant,
    subsystems: Vec<Subsystem>,
}

struct AppState {
    config_path: PathBuf,
    auth_path: PathBuf,
    config: Mutex<Config>,
    auth_db: Mutex<auth_store::AuthDb>,
    sessions: Mutex<SessionStore>,
    rate_limiter: Mutex<LoginRateLimiter>,
    pending_rollback: Mutex<Option<PendingRollback>>,
}

impl AppState {
    fn new(data_dir: &Path) -> Self {
        let config_path = data_dir.join(cfg_store::DEFAULT_CONFIG_FILE);
        let auth_path = auth_store::default_auth_path(data_dir);
        let cfg = cfg_store::load_or_default(&config_path);
        let auth_db = auth_store::load_or_default(&auth_path);
        Self {
            config_path,
            auth_path,
            config: Mutex::new(cfg),
            auth_db: Mutex::new(auth_db),
            sessions: Mutex::new(SessionStore::new()),
            rate_limiter: Mutex::new(LoginRateLimiter::default_policy()),
            pending_rollback: Mutex::new(None),
        }
    }

    fn rollback_remaining_secs(&self) -> Option<u64> {
        let guard = self.pending_rollback.lock().unwrap();
        guard.as_ref().map(|p| {
            let now = Instant::now();
            if p.deadline > now {
                p.deadline.duration_since(now).as_secs()
            } else {
                0
            }
        })
    }

    fn execute_rollback(&self) -> Result<Vec<String>, String> {
        let subsystems = {
            let mut pending = self.pending_rollback.lock().unwrap();
            pending
                .take()
                .map(|p| p.subsystems)
                .unwrap_or_else(|| vec![Subsystem::Network, Subsystem::Firewall])
        };
        let rolled = cfg_store::rollback_to_backup(&self.config_path)
            .map_err(|e| format!("rollback failed: {e}"))?;
        let (applied, warnings) = reconciler::reconcile_subsystems(&rolled, &subsystems);
        for w in &warnings {
            eprintln!("[rv180wd] rollback warning: {w}");
        }
        *self.config.lock().unwrap() = rolled;
        Ok(applied)
    }
}

struct WorkerLimiter {
    max: usize,
    state: Mutex<usize>,
    cvar: Condvar,
}

impl WorkerLimiter {
    fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            state: Mutex::new(0),
            cvar: Condvar::new(),
        })
    }

    fn acquire(self: &Arc<Self>) -> WorkerGuard {
        let mut n = self.state.lock().unwrap();
        while *n >= self.max {
            n = self.cvar.wait(n).unwrap();
        }
        *n += 1;
        WorkerGuard(Arc::clone(self))
    }
}

struct WorkerGuard(Arc<WorkerLimiter>);
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        let mut n = self.0.state.lock().unwrap();
        *n = n.saturating_sub(1);
        self.0.cvar.notify_one();
    }
}

fn ensure_writable_cert_dir(primary: &Path) -> io::Result<PathBuf> {
    if fs::create_dir_all(primary).is_ok() {
        let probe = primary.join(".probe");
        if fs::write(&probe, b"ok").is_ok() {
            let _ = fs::remove_file(&probe);
            return Ok(primary.to_path_buf());
        }
    }
    let fallback = PathBuf::from(FALLBACK_CERT_DIR);
    fs::create_dir_all(&fallback)?;
    Ok(fallback)
}

fn load_or_create_tls_config(data_dir: &Path, san_ip: &str) -> io::Result<Arc<ServerConfig>> {
    let dir = ensure_writable_cert_dir(&data_dir.join("certs"))?;
    let cert_path = dir.join("rv180wd.crt");
    let key_path = dir.join("rv180wd.key");

    if !cert_path.exists() || !key_path.exists() {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Cisco RV180W Next Gateway");
        dn.push(DnType::OrganizationName, "rv180w-next");
        params.distinguished_name = dn;
        // Router boots at Jan 1 2011 before NTP sync; wide validity avoids browser clock errors.
        params.not_before = time::OffsetDateTime::from_unix_timestamp(1_262_304_000)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        params.not_after = time::OffsetDateTime::from_unix_timestamp(2_398_291_200)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);

        let mut sans = Vec::new();
        if let Ok(ip) = san_ip.parse::<IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        }
        if let Ok(lo) = "127.0.0.1".parse::<IpAddr>() {
            if san_ip != "127.0.0.1" {
                sans.push(SanType::IpAddress(lo));
            }
        }
        if let Ok(d1) = "rv180w.local".try_into() {
            sans.push(SanType::DnsName(d1));
        }
        if let Ok(d2) = "localhost".try_into() {
            sans.push(SanType::DnsName(d2));
        }
        params.subject_alt_names = sans;

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("keygen error: {e}")))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("cert sign error: {e}")))?;

        fs::write(&cert_path, cert.pem())?;
        fs::write(&key_path, key_pair.serialize_pem())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }
    }

    let cert_bytes = fs::read(&cert_path)?;
    let key_bytes = fs::read(&key_path)?;
    let mut cert_reader = BufReader::new(&cert_bytes[..]);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let mut key_reader = BufReader::new(&key_bytes[..]);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing TLS private key"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls version error: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls cert error: {e}")))?;

    Ok(Arc::new(cfg))
}

struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn session_cookie(&self) -> Option<String> {
        let raw = self.header("cookie")?;
        for part in raw.split(';') {
            let trimmed = part.trim();
            if let Some((k, v)) = trimmed.split_once('=') {
                if k.trim() == SESSION_COOKIE_NAME {
                    return Some(v.trim().to_string());
                }
            }
        }
        None
    }
}

struct HttpResponse {
    status: &'static str,
    content_type: &'static str,
    extra_headers: Vec<String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json<T: Serialize>(status: &'static str, val: &T) -> Self {
        let body = serde_json::to_vec(val).unwrap_or_else(|_| b"{}".to_vec());
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            extra_headers: Vec::new(),
            body,
        }
    }

    fn err(status: &'static str, msg: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": msg }))
    }

    fn html(body: &str) -> Self {
        Self {
            status: "200 OK",
            content_type: "text/html; charset=utf-8",
            extra_headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut head = format!(
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n",
            self.status,
            self.content_type,
            self.body.len()
        );
        for h in &self.extra_headers {
            head.push_str(h);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        w.write_all(head.as_bytes())?;
        w.write_all(&self.body)?;
        w.flush()
    }
}

fn read_request<R: Read>(stream: &mut R) -> io::Result<Option<HttpRequest>> {
    let mut reader = BufReader::with_capacity(IO_BUF_SIZE, stream);
    let mut first_line = String::new();
    let n = reader.read_line(&mut first_line)?;
    if n == 0 {
        return Ok(None);
    }
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let raw_target = parts.next().unwrap_or("/");
    let path = raw_target.split('?').next().unwrap_or("/").to_string();

    let mut total = n;
    let mut headers = Vec::new();
    let mut content_len: usize = 0;

    loop {
        let mut line = String::new();
        let r = reader.read_line(&mut line)?;
        if r == 0 {
            break;
        }
        total += r;
        if total > MAX_HEADER_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "headers too large"));
        }
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_len = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }

    if content_len > MAX_BODY_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
    }

    let mut body = vec![0u8; content_len];
    if content_len > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(Some(HttpRequest {
        method,
        path,
        headers,
        body,
    }))
}

#[derive(Deserialize)]
struct CredentialsReq {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct ChangePasswordReq {
    current_password: String,
    new_password: String,
}

fn build_session_cookie(token: &str, is_https: bool) -> String {
    let secure = if is_https { "; Secure" } else { "" };
    format!(
        "Set-Cookie: {SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax{secure}"
    )
}

fn clear_session_cookie() -> String {
    format!("Set-Cookie: {SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn require_session(state: &AppState, req: &HttpRequest, check_csrf: bool) -> Result<crate::auth::session::Session, HttpResponse> {
    let Some(token) = req.session_cookie() else {
        return Err(HttpResponse::err("401 Unauthorized", "authentication required"));
    };
    let session = state
        .sessions
        .lock()
        .unwrap()
        .get(&token)
        .ok_or_else(|| HttpResponse::err("401 Unauthorized", "session expired or invalid"))?;

    if check_csrf && !validate_csrf(&session.csrf_token, req.header("x-csrf-token")) {
        return Err(HttpResponse::err("403 Forbidden", "invalid CSRF token"));
    }
    Ok(session)
}

fn dispatch(state: &AppState, req: &HttpRequest, peer_ip: IpAddr, is_https: bool) -> HttpResponse {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => HttpResponse::html(SPA_HTML),

        ("GET", "/api/v1/health") => HttpResponse::json(
            "200 OK",
            &serde_json::json!({
                "status": "ok",
                "daemon": "rv180wd",
                "version": env!("CARGO_PKG_VERSION"),
                "tls": "1.2/1.3",
            }),
        ),

        ("GET", "/api/v1/auth/status") => {
            let initialized = state.auth_db.lock().unwrap().initialized;
            if let Ok(sess) = require_session(state, req, false) {
                HttpResponse::json(
                    "200 OK",
                    &serde_json::json!({
                        "initialized": initialized,
                        "authenticated": true,
                        "username": sess.username,
                        "csrf_token": sess.csrf_token,
                    }),
                )
            } else {
                HttpResponse::json(
                    "200 OK",
                    &serde_json::json!({
                        "initialized": initialized,
                        "authenticated": false,
                    }),
                )
            }
        }

        ("POST", "/api/v1/auth/setup") => {
            let Ok(creds) = serde_json::from_slice::<CredentialsReq>(&req.body) else {
                return HttpResponse::err("400 Bad Request", "invalid JSON payload");
            };
            let user = creds.username.trim();
            if user.is_empty() || user.len() > 32 || creds.password.len() < 6 {
                return HttpResponse::err(
                    "400 Bad Request",
                    "username (1-32 chars) and password (>= 6 chars) required",
                );
            }
            let mut db = state.auth_db.lock().unwrap();
            if db.initialized {
                return HttpResponse::err("409 Conflict", "router admin already initialized");
            }
            db.upsert_user(user, &creds.password, "admin");
            if let Err(e) = auth_store::save_atomic(&state.auth_path, &db) {
                return HttpResponse::err("500 Internal Server Error", &format!("failed to save auth.json: {e}"));
            }
            drop(db);

            let (token, csrf) = state.sessions.lock().unwrap().create(user);
            let mut resp = HttpResponse::json(
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "username": user,
                    "csrf_token": csrf,
                }),
            );
            resp.extra_headers.push(build_session_cookie(&token, is_https));
            resp
        }

        ("POST", "/api/v1/auth/login") => {
            {
                let mut rl = state.rate_limiter.lock().unwrap();
                if !rl.check_allowed(peer_ip) {
                    return HttpResponse::err("429 Too Many Requests", "too many failed attempts, try again later");
                }
            }
            let Ok(creds) = serde_json::from_slice::<CredentialsReq>(&req.body) else {
                return HttpResponse::err("400 Bad Request", "invalid JSON payload");
            };
            let ok = {
                let db = state.auth_db.lock().unwrap();
                if !db.initialized {
                    return HttpResponse::err("409 Conflict", "first-boot setup required");
                }
                db.verify(creds.username.trim(), &creds.password)
            };
            if !ok {
                state.rate_limiter.lock().unwrap().record_failure(peer_ip);
                return HttpResponse::err("401 Unauthorized", "invalid username or password");
            }
            state.rate_limiter.lock().unwrap().record_success(peer_ip);
            let (token, csrf) = state.sessions.lock().unwrap().create(creds.username.trim());
            let mut resp = HttpResponse::json(
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "username": creds.username.trim(),
                    "csrf_token": csrf,
                }),
            );
            resp.extra_headers.push(build_session_cookie(&token, is_https));
            resp
        }

        ("POST", "/api/v1/auth/logout") => {
            if let Err(e) = require_session(state, req, true) {
                return e;
            }
            if let Some(tok) = req.session_cookie() {
                state.sessions.lock().unwrap().invalidate(&tok);
            }
            let mut resp = HttpResponse::json("200 OK", &serde_json::json!({ "ok": true }));
            resp.extra_headers.push(clear_session_cookie());
            resp
        }

        ("POST", "/api/v1/auth/password") => {
            let sess = match require_session(state, req, true) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let Ok(body) = serde_json::from_slice::<ChangePasswordReq>(&req.body) else {
                return HttpResponse::err("400 Bad Request", "invalid JSON payload");
            };
            if body.new_password.len() < 6 {
                return HttpResponse::err("400 Bad Request", "new password must be at least 6 characters");
            }
            let mut db = state.auth_db.lock().unwrap();
            if !db.verify(&sess.username, &body.current_password) {
                return HttpResponse::err("401 Unauthorized", "current password is incorrect");
            }
            db.upsert_user(&sess.username, &body.new_password, "admin");
            if let Err(e) = auth_store::save_atomic(&state.auth_path, &db) {
                return HttpResponse::err("500 Internal Server Error", &format!("failed to persist password: {e}"));
            }
            HttpResponse::json("200 OK", &serde_json::json!({ "ok": true }))
        }

        ("GET", "/api/v1/dashboard") => {
            if let Err(e) = require_session(state, req, false) {
                return e;
            }
            let snap = telemetry::collect_snapshot();
            HttpResponse::json(
                "200 OK",
                &serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "mtd_layout": upgrade::mtd_layout_summary(),
                    "rollback_pending_secs": state.rollback_remaining_secs(),
                    "telemetry": snap,
                }),
            )
        }

        ("GET", "/api/v1/config") => {
            if let Err(e) = require_session(state, req, false) {
                return e;
            }
            let cfg = state.config.lock().unwrap().clone();
            HttpResponse::json("200 OK", &cfg)
        }

        ("PUT", "/api/v1/config") => {
            if let Err(e) = require_session(state, req, true) {
                return e;
            }
            let Ok(new_cfg) = serde_json::from_slice::<Config>(&req.body) else {
                return HttpResponse::err("400 Bad Request", "invalid configuration JSON");
            };

            let old_cfg = state.config.lock().unwrap().clone();
            let changed = diff_subsystems(&old_cfg, &new_cfg);
            if changed.is_empty() {
                return HttpResponse::json(
                    "200 OK",
                    &serde_json::json!({
                        "ok": true,
                        "reboot_required": false,
                        "applied_subsystems": [],
                        "rollback_pending_secs": state.rollback_remaining_secs(),
                    }),
                );
            }

            if let Err(e) = cfg_store::save_atomic(&state.config_path, &new_cfg) {
                return HttpResponse::err("500 Internal Server Error", &format!("failed to save config: {e}"));
            }
            let (applied, warnings) = reconciler::reconcile_subsystems(&new_cfg, &changed);
            *state.config.lock().unwrap() = new_cfg;

            let risky = changed
                .iter()
                .any(|s| matches!(s, Subsystem::Network | Subsystem::Firewall));
            let rollback_secs = if risky {
                *state.pending_rollback.lock().unwrap() = Some(PendingRollback {
                    deadline: Instant::now() + Duration::from_secs(SAFE_ROLLBACK_SECS),
                    subsystems: changed.clone(),
                });
                Some(SAFE_ROLLBACK_SECS)
            } else {
                None
            };

            HttpResponse::json(
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "reboot_required": false,
                    "applied_subsystems": applied,
                    "warnings": warnings,
                    "rollback_pending_secs": rollback_secs,
                }),
            )
        }

        ("POST", "/api/v1/config/confirm") => {
            if let Err(e) = require_session(state, req, true) {
                return e;
            }
            *state.pending_rollback.lock().unwrap() = None;
            HttpResponse::json("200 OK", &serde_json::json!({ "ok": true, "confirmed": true }))
        }

        ("POST", "/api/v1/config/rollback") => {
            if let Err(e) = require_session(state, req, true) {
                return e;
            }
            match state.execute_rollback() {
                Ok(applied) => HttpResponse::json(
                    "200 OK",
                    &serde_json::json!({ "ok": true, "rolled_back": applied }),
                ),
                Err(e) => HttpResponse::err("400 Bad Request", &e),
            }
        }

        _ => HttpResponse::err("404 Not Found", "not_found"),
    }
}

fn handle_plain(mut stream: TcpStream, peer: SocketAddr, state: Arc<AppState>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
    if let Ok(Some(req)) = read_request(&mut stream) {
        let resp = dispatch(&state, &req, peer.ip(), false);
        let _ = resp.write_to(&mut stream);
    }
}

fn handle_tls(stream: TcpStream, peer: SocketAddr, tls_cfg: Arc<ServerConfig>, state: Arc<AppState>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
    let Ok(conn) = ServerConnection::new(tls_cfg) else {
        return;
    };
    let mut tls_stream = StreamOwned::new(conn, stream);
    if let Ok(Some(req)) = read_request(&mut tls_stream) {
        let resp = dispatch(&state, &req, peer.ip(), true);
        let _ = resp.write_to(&mut tls_stream);
    }
}

fn spawn_safe_rollback_watcher(state: Arc<AppState>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(2));
        let expired = {
            let guard = state.pending_rollback.lock().unwrap();
            guard
                .as_ref()
                .map(|p| Instant::now() >= p.deadline)
                .unwrap_or(false)
        };
        if expired {
            eprintln!("[rv180wd] safe-rollback timer expired without confirmation; rolling back!");
            if let Err(e) = state.execute_rollback() {
                eprintln!("[rv180wd] auto-rollback error: {e}");
            }
        }
    });
}

pub fn run(opts: ServerOptions) -> Result<(), String> {
    let state = Arc::new(AppState::new(&opts.data_dir));
    let limiter = WorkerLimiter::new(opts.max_workers);
    spawn_safe_rollback_watcher(Arc::clone(&state));

    // Bind HTTP FIRST so http://192.168.1.1 is guaranteed reachable immediately even if TLS cert gen takes a moment
    let http_listener = TcpListener::bind(&opts.http_addr)
        .map_err(|e| format!("failed to bind HTTP {}: {e}", opts.http_addr))?;
    eprintln!(
        "[rv180wd] HTTP listening on http://{} (max_workers={})",
        opts.http_addr, opts.max_workers
    );

    // Start HTTPS (TLS 1.2 & TLS 1.3) listener in background thread; never kill HTTP if TLS init fails
    if let Some(https_addr) = opts.https_addr.clone() {
        let data_dir = opts.data_dir.clone();
        let san_ip = opts.san_ip.clone();
        let st = Arc::clone(&state);
        let lim = Arc::clone(&limiter);
        let max_workers = opts.max_workers;
        thread::spawn(move || {
            let tls_cfg = match load_or_create_tls_config(&data_dir, &san_ip) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[rv180wd] WARN: failed to init TLS 1.2/1.3 config (HTTP stays up): {e}");
                    return;
                }
            };
            let https_listener = match TcpListener::bind(&https_addr) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[rv180wd] WARN: failed to bind HTTPS {https_addr} (HTTP stays up): {e}");
                    return;
                }
            };
            eprintln!(
                "[rv180wd] HTTPS (TLS 1.2/1.3) listening on https://{https_addr} (max_workers={max_workers})"
            );
            for incoming in https_listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        let peer = stream
                            .peer_addr()
                            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
                        let guard = lim.acquire();
                        let tcfg = Arc::clone(&tls_cfg);
                        let s = Arc::clone(&st);
                        thread::spawn(move || {
                            let _g = guard;
                            handle_tls(stream, peer, tcfg, s);
                        });
                    }
                    Err(e) => {
                        eprintln!("[rv180wd] HTTPS accept error: {e}");
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });
    }

    for incoming in http_listener.incoming() {
        match incoming {
            Ok(stream) => {
                let peer = stream
                    .peer_addr()
                    .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
                let guard = limiter.acquire();
                let s = Arc::clone(&state);
                thread::spawn(move || {
                    let _g = guard;
                    handle_plain(stream, peer, s);
                });
            }
            Err(e) => {
                eprintln!("[rv180wd] HTTP accept error: {e}");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    Ok(())
}
