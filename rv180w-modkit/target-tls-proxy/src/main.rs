use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

const DEFAULT_LISTEN: &str = "0.0.0.0:443";
const DEFAULT_BACKEND: &str = "127.0.0.1:80";
const DEFAULT_CERT_DIR: &str = "/data/certs";
const FALLBACK_CERT_DIR: &str = "/tmp/modern-certs";
const DEFAULT_SAN_IP: &str = "192.168.1.1";
const DEFAULT_MAX_CONNS: usize = 16;
const IO_BUF_SIZE: usize = 8192;
const MAX_HEADER_BYTES: usize = 65536;

struct Config {
    listen: String,
    backend: String,
    cert_dir: PathBuf,
    san_ip: String,
    max_conns: usize,
    pid_file: Option<PathBuf>,
}

struct ConnLimiter {
    max: usize,
    state: Mutex<usize>,
    cvar: Condvar,
}

impl ConnLimiter {
    fn new(max: usize) -> Self {
        Self {
            max,
            state: Mutex::new(0),
            cvar: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> ConnGuard {
        let mut active = self.state.lock().unwrap();
        while *active >= self.max {
            active = self.cvar.wait(active).unwrap();
        }
        *active += 1;
        ConnGuard {
            limiter: Arc::clone(self),
        }
    }
}

struct ConnGuard {
    limiter: Arc<ConnLimiter>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut active = self.limiter.state.lock().unwrap();
        *active = active.saturating_sub(1);
        self.limiter.cvar.notify_one();
    }
}

fn parse_args() -> Config {
    let mut listen = env::var("MODERN_TLS_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    let mut backend = env::var("MODERN_TLS_BACKEND").unwrap_or_else(|_| DEFAULT_BACKEND.to_string());
    let mut cert_dir = PathBuf::from(
        env::var("MODERN_TLS_CERT_DIR").unwrap_or_else(|_| DEFAULT_CERT_DIR.to_string()),
    );
    let mut san_ip = env::var("MODERN_TLS_SAN_IP").unwrap_or_else(|_| DEFAULT_SAN_IP.to_string());
    let mut max_conns = env::var("MODERN_TLS_MAX_CONNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONNS);
    let mut pid_file = env::var("MODERN_TLS_PID_FILE").ok().map(PathBuf::from);

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" | "-l" if i + 1 < args.len() => {
                listen = args[i + 1].clone();
                i += 2;
            }
            "--backend" | "-b" if i + 1 < args.len() => {
                backend = args[i + 1].clone();
                i += 2;
            }
            "--cert-dir" | "-c" if i + 1 < args.len() => {
                cert_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--san-ip" if i + 1 < args.len() => {
                san_ip = args[i + 1].clone();
                i += 2;
            }
            "--max-conns" if i + 1 < args.len() => {
                if let Ok(n) = args[i + 1].parse::<usize>() {
                    if n > 0 {
                        max_conns = n;
                    }
                }
                i += 2;
            }
            "--pid-file" if i + 1 < args.len() => {
                pid_file = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--version" | "-V" => {
                println!("modern-tls-proxy 2.0.0-beta (RV180W TLS 1.2/1.3)");
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!(
                    "Usage: modern-tls-proxy [--listen 0.0.0.0:443] [--backend 127.0.0.1:80] [--cert-dir /data/certs] [--san-ip 192.168.1.1] [--max-conns 16] [--pid-file /var/run/modern-tls-proxy.pid]"
                );
                std::process::exit(0);
            }
            _ => {
                i += 1;
            }
        }
    }

    Config {
        listen,
        backend,
        cert_dir,
        san_ip,
        max_conns,
        pid_file,
    }
}

fn ensure_writable_dir(primary: &Path) -> io::Result<PathBuf> {
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

fn generate_self_signed_cert(
    cert_path: &Path,
    key_path: &Path,
    san_ip: &str,
) -> io::Result<()> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Cisco RV180W Gateway");
    dn.push(DnType::OrganizationName, "RV180W Modern TLS Mod");
    params.distinguished_name = dn;

    // Router boots at Jan 1 2011 before NTP sync; wide validity prevents browser clock rejection.
    params.not_before = time::OffsetDateTime::from_unix_timestamp(1_262_304_000)
        .unwrap_or_else(|_| time::OffsetDateTime::UNIX_EPOCH); // 2010-01-01
    params.not_after = time::OffsetDateTime::from_unix_timestamp(2_398_291_200)
        .unwrap_or_else(|_| time::OffsetDateTime::UNIX_EPOCH); // 2046-01-01

    let mut sans = Vec::new();
    if let Ok(ip) = san_ip.parse::<IpAddr>() {
        sans.push(SanType::IpAddress(ip));
    }
    if let Ok(loopback) = "127.0.0.1".parse::<IpAddr>() {
        if san_ip != "127.0.0.1" {
            sans.push(SanType::IpAddress(loopback));
        }
    }
    if let Ok(dns1) = "rv180w.local".try_into() {
        sans.push(SanType::DnsName(dns1));
    }
    if let Ok(dns2) = "localhost".try_into() {
        sans.push(SanType::DnsName(dns2));
    }
    params.subject_alt_names = sans;

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("keygen failed: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("cert sign failed: {e}")))?;

    fs::write(cert_path, cert.pem())?;
    fs::write(key_path, key_pair.serialize_pem())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(key_path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

fn load_or_create_tls_config(cert_dir: &Path, san_ip: &str) -> io::Result<Arc<ServerConfig>> {
    let dir = ensure_writable_dir(cert_dir)?;
    let cert_path = dir.join("modern_https.crt");
    let key_path = dir.join("modern_https.key");

    if !cert_path.exists() || !key_path.exists() {
        eprintln!(
            "[modern-tls-proxy] generating ECDSA P-256 certificate in {} (SAN IP {})",
            dir.display(),
            san_ip
        );
        generate_self_signed_cert(&cert_path, &key_path, san_ip)?;
    }

    let cert_bytes = fs::read(&cert_path)?;
    let key_bytes = fs::read(&key_path)?;

    let mut cert_reader = BufReader::new(&cert_bytes[..]);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificates found in PEM",
        ));
    }

    let mut key_reader = BufReader::new(&key_bytes[..]);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key in PEM"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls versions error: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls cert config error: {e}")))?;

    Ok(Arc::new(config))
}

fn read_http_head<R: Read>(reader: &mut BufReader<R>) -> io::Result<Option<(String, Vec<(String, String)>)>> {
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line)?;
    if n == 0 {
        return Ok(None);
    }
    let mut total = n;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        total += read;
        if total > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header section exceeds limit",
            ));
        }
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(Some((
        request_line.trim_end_matches(&['\r', '\n'][..]).to_string(),
        headers,
    )))
}

fn rewrite_scheme_to_http(val: &str) -> String {
    if let Some(rest) = val.strip_prefix("https://") {
        format!("http://{rest}")
    } else if let Some(rest) = val.strip_prefix("HTTPS://") {
        format!("http://{rest}")
    } else {
        val.to_string()
    }
}

fn rewrite_location_to_https(val: &str, client_host: &str) -> String {
    if let Some(rest) = val.strip_prefix("http://") {
        format!("https://{rest}")
    } else if let Some(rest) = val.strip_prefix("HTTP://") {
        format!("https://{rest}")
    } else if val.starts_with('/') && !client_host.is_empty() {
        val.to_string()
    } else {
        val.to_string()
    }
}

fn rewrite_set_cookie(val: &str) -> String {
    let lower = val.to_ascii_lowercase();
    let mut out = val.to_string();
    if !lower.contains("samesite=") {
        out.push_str("; SameSite=Lax");
    }
    if !lower.contains("; secure") && !lower.ends_with("secure") {
        out.push_str("; Secure");
    }
    out
}

fn copy_exact<R: Read, W: Write>(reader: &mut R, writer: &mut W, mut remaining: u64) -> io::Result<()> {
    let mut buf = [0u8; IO_BUF_SIZE];
    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

fn forward_chunked_body<R: Read, W: Write>(reader: &mut BufReader<R>, writer: &mut W) -> io::Result<()> {
    loop {
        let mut size_line = String::new();
        let n = reader.read_line(&mut size_line)?;
        if n == 0 {
            break;
        }
        writer.write_all(size_line.as_bytes())?;
        let hex_part = size_line
            .trim()
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let chunk_size = u64::from_str_radix(hex_part, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        if chunk_size == 0 {
            // Forward optional trailing headers until blank line.
            loop {
                let mut trailer = String::new();
                let tn = reader.read_line(&mut trailer)?;
                if tn == 0 {
                    break;
                }
                writer.write_all(trailer.as_bytes())?;
                if trailer == "\r\n" || trailer == "\n" {
                    break;
                }
            }
            break;
        }
        // Copy chunk payload + trailing CRLF.
        copy_exact(reader, writer, chunk_size + 2)?;
    }
    Ok(())
}

fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    tls_config: Arc<ServerConfig>,
    backend_addr: String,
) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    let conn = ServerConnection::new(tls_config)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls init error: {e}")))?;
    let tls_stream = StreamOwned::new(conn, stream);
    let mut client_reader = BufReader::with_capacity(IO_BUF_SIZE, tls_stream);

    let Some((req_line, req_headers)) = read_http_head(&mut client_reader)? else {
        return Ok(());
    };

    // Extend timeouts for firmware upload / long CGI actions.
    if req_line.contains("upgrade") || req_line.contains("backup") || req_line.starts_with("POST ") {
        let _ = client_reader
            .get_ref()
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(180)));
        let _ = client_reader
            .get_ref()
            .get_ref()
            .set_write_timeout(Some(Duration::from_secs(180)));
    }

    let mut backend = TcpStream::connect(&backend_addr)?;
    let _ = backend.set_nodelay(true);
    let _ = backend.set_read_timeout(Some(Duration::from_secs(180)));
    let _ = backend.set_write_timeout(Some(Duration::from_secs(180)));

    let mut content_length: Option<u64> = None;
    let mut is_chunked = false;
    let mut client_host = String::new();

    let mut req_buf = String::with_capacity(1024);
    req_buf.push_str(&req_line);
    req_buf.push_str("\r\n");

    for (name, val) in &req_headers {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "connection" | "proxy-connection" | "keep-alive" => continue,
            "host" => {
                client_host = val.clone();
                req_buf.push_str(&format!("Host: {val}\r\n"));
            }
            "origin" => {
                let rewritten = rewrite_scheme_to_http(val);
                req_buf.push_str(&format!("Origin: {rewritten}\r\n"));
            }
            "referer" => {
                let rewritten = rewrite_scheme_to_http(val);
                req_buf.push_str(&format!("Referer: {rewritten}\r\n"));
            }
            "content-length" => {
                content_length = val.parse::<u64>().ok();
                req_buf.push_str(&format!("{name}: {val}\r\n"));
            }
            "transfer-encoding" => {
                if val.to_ascii_lowercase().contains("chunked") {
                    is_chunked = true;
                }
                req_buf.push_str(&format!("{name}: {val}\r\n"));
            }
            _ => {
                req_buf.push_str(&format!("{name}: {val}\r\n"));
            }
        }
    }

    if client_host.is_empty() {
        req_buf.push_str("Host: 192.168.1.1\r\n");
    }
    req_buf.push_str("X-Forwarded-Proto: https\r\n");
    req_buf.push_str(&format!("X-Forwarded-For: {}\r\n", peer.ip()));
    req_buf.push_str("Connection: close\r\n\r\n");

    backend.write_all(req_buf.as_bytes())?;

    if is_chunked {
        forward_chunked_body(&mut client_reader, &mut backend)?;
    } else if let Some(len) = content_length {
        if len > 0 {
            copy_exact(&mut client_reader, &mut backend, len)?;
        }
    }
    backend.flush()?;

    // Read response head from internal thttpd backend and rewrite headers for modern browsers.
    let mut backend_reader = BufReader::with_capacity(IO_BUF_SIZE, backend);
    let Some((status_line, resp_headers)) = read_http_head(&mut backend_reader)? else {
        return Ok(());
    };

    let mut resp_buf = String::with_capacity(1024);
    resp_buf.push_str(&status_line);
    resp_buf.push_str("\r\n");

    for (name, val) in &resp_headers {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "connection" | "keep-alive" => continue,
            "location" => {
                let rewritten = rewrite_location_to_https(val, &client_host);
                resp_buf.push_str(&format!("Location: {rewritten}\r\n"));
            }
            "set-cookie" => {
                let rewritten = rewrite_set_cookie(val);
                resp_buf.push_str(&format!("Set-Cookie: {rewritten}\r\n"));
            }
            _ => {
                resp_buf.push_str(&format!("{name}: {val}\r\n"));
            }
        }
    }
    resp_buf.push_str("Connection: close\r\n\r\n");

    let mut tls_writer = client_reader.into_inner();
    tls_writer.write_all(resp_buf.as_bytes())?;

    let mut buf = [0u8; IO_BUF_SIZE];
    loop {
        let n = backend_reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        tls_writer.write_all(&buf[..n])?;
    }
    tls_writer.flush()?;
    Ok(())
}

fn main() {
    let cfg = parse_args();

    if let Some(ref pid_path) = cfg.pid_file {
        if let Some(parent) = pid_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(pid_path, format!("{}\n", std::process::id()));
    }

    let tls_config = match load_or_create_tls_config(&cfg.cert_dir, &cfg.san_ip) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[modern-tls-proxy] fatal TLS config error: {e}");
            std::process::exit(1);
        }
    };

    let listener = match TcpListener::bind(&cfg.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[modern-tls-proxy] failed to bind {}: {e}", cfg.listen);
            std::process::exit(1);
        }
    };

    eprintln!(
        "[modern-tls-proxy] listening on https://{} -> http://{} (max_conns={})",
        cfg.listen, cfg.backend, cfg.max_conns
    );

    let limiter = Arc::new(ConnLimiter::new(cfg.max_conns));
    let backend_addr = Arc::new(cfg.backend);

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let peer = stream
                    .peer_addr()
                    .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
                let guard = limiter.acquire();
                let tls_cfg = Arc::clone(&tls_config);
                let backend = Arc::clone(&backend_addr);

                thread::spawn(move || {
                    let _guard = guard;
                    if let Err(e) = handle_client(stream, peer, tls_cfg, backend.as_ref().clone()) {
                        let kind = e.kind();
                        if kind != io::ErrorKind::UnexpectedEof
                            && kind != io::ErrorKind::ConnectionReset
                            && kind != io::ErrorKind::BrokenPipe
                        {
                            eprintln!("[modern-tls-proxy] conn {peer} error: {e}");
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("[modern-tls-proxy] accept error: {e}");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}
