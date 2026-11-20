use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub http_addr: String,
    pub max_workers: usize,
}

impl ServerOptions {
    pub fn from_env() -> Self {
        Self {
            http_addr: std::env::var("RV180WD_HTTP_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:80".to_string()),
            max_workers: std::env::var("RV180WD_MAX_WORKERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
        }
    }
}

/// Minimal scaffold HTTP server (Phase 4 foundation).
/// Currently serves a basic health endpoint and placeholder responses.
/// TLS 1.2/1.3 listener, full REST API, and embedded SPA will be implemented in later phases.
pub fn run(opts: ServerOptions) -> Result<(), String> {
    let listener = TcpListener::bind(&opts.http_addr)
        .map_err(|e| format!("failed to bind {}: {e}", opts.http_addr))?;
    eprintln!(
        "[rv180wd] HTTP scaffold listening on http://{} (max_workers={})",
        opts.http_addr, opts.max_workers
    );

    let limiter = WorkerLimiter::new(opts.max_workers.max(1));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let _guard = limiter.acquire();
                thread::spawn(move || {
                    let _g = _guard;
                    let _ = handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("[rv180wd] accept error: {e}");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    Ok(())
}

struct WorkerLimiter {
    max: usize,
    state: std::sync::Mutex<usize>,
    cvar: std::sync::Condvar,
}

impl WorkerLimiter {
    fn new(max: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            max,
            state: std::sync::Mutex::new(0),
            cvar: std::sync::Condvar::new(),
        })
    }
}

struct WorkerGuard(std::sync::Arc<WorkerLimiter>);
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        let mut n = self.0.state.lock().unwrap();
        *n = n.saturating_sub(1);
        self.0.cvar.notify_one();
    }
}

trait Acquire {
    fn acquire(self: &std::sync::Arc<Self>) -> WorkerGuard;
}
impl Acquire for WorkerLimiter {
    fn acquire(self: &std::sync::Arc<Self>) -> WorkerGuard {
        let mut n = self.state.lock().unwrap();
        while *n >= self.max {
            n = self.cvar.wait(n).unwrap();
        }
        *n += 1;
        WorkerGuard(std::sync::Arc::clone(self))
    }
}

fn handle_client(mut stream: TcpStream) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, ctype, body) = match path {
        "/api/v1/health" => (
            "200 OK",
            "application/json",
            r#"{"status":"ok","daemon":"rv180wd","phase":"scaffold"}"#.to_string(),
        ),
        "/" => (
            "200 OK",
            "text/html; charset=utf-8",
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>rv180wd</title></head><body><h1>rv180wd (rv180w-next scaffold)</h1><p>Control plane scaffold is running. See <a href=\"/api/v1/health\">/api/v1/health</a>.</p></body></html>".to_string(),
        ),
        _ => (
            "404 Not Found",
            "application/json",
            r#"{"error":"not_found"}"#.to_string(),
        ),
    };

    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(())
}
