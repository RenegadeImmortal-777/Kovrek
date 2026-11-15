// HTTP servers: static directory serving, file-backed routes and the dynamic
// Kovrek app server.
//
// Extracted from `main.rs` without behavior change; see docs/ENGINE-SPLIT.md.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde_json::Value as JsonValue;
use tiny_http::{Header, Request, Response, Server, StatusCode};

use crate::pipeline::{load_source, prepare_vm};
use crate::registry::{safe_package_relative_path, unpack_bundle_to_dir};
use crate::value::{Val, constant_time_strings_equal};

pub(crate) const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
pub(crate) const REGISTRY_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub(crate) const DEFAULT_SECURITY_HEADERS: [(&str, &str); 5] = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    ),
    ("Cross-Origin-Resource-Policy", "same-origin"),
];

pub(crate) enum BodyReadError {
    TooLarge(usize),
    Io(String),
}

pub(crate) fn apply_security_headers<R: Read>(response: &mut Response<R>) {
    for (name, value) in DEFAULT_SECURITY_HEADERS {
        let present = response
            .headers()
            .iter()
            .any(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name));
        if !present && let Ok(h) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response.add_header(h);
        }
    }
}

pub(crate) fn read_request_body_limited(
    req: &mut Request,
    max_bytes: usize,
) -> Result<String, BodyReadError> {
    if let Some(content_len) = req.body_length()
        && content_len > max_bytes
    {
        return Err(BodyReadError::TooLarge(max_bytes));
    }
    let mut buf = Vec::new();
    let take_cap = max_bytes.saturating_add(1) as u64;
    req.as_reader()
        .take(take_cap)
        .read_to_end(&mut buf)
        .map_err(|e| BodyReadError::Io(e.to_string()))?;
    if buf.len() > max_bytes {
        return Err(BodyReadError::TooLarge(max_bytes));
    }
    String::from_utf8(buf).map_err(|e| BodyReadError::Io(format!("invalid UTF-8 body: {e}")))
}

pub(crate) fn json_error_response(status: u16, message: &str) -> Response<Box<dyn Read + Send>> {
    let payload = serde_json::json!({
        "ok": false,
        "error": message,
    })
    .to_string();
    let mut r = Response::from_string(payload)
        .with_status_code(StatusCode(status))
        .boxed();
    if let Ok(h) = Header::from_bytes(
        &b"Content-Type"[..],
        &b"application/json; charset=utf-8"[..],
    ) {
        r.add_header(h);
    }
    apply_security_headers(&mut r);
    r
}

pub(crate) fn resolve_static_path(dir: &Path, request_url: &str) -> Option<PathBuf> {
    const MAX_STATIC_FILE_BYTES: u64 = 64 * 1024 * 1024;
    let raw = request_url.split(['?', '#']).next().unwrap_or("/");
    if raw.bytes().any(|b| b.is_ascii_control()) || raw.contains(['\\', ':']) {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
    {
        return None;
    }
    let rel = raw.trim_start_matches('/');
    let rel_path = if rel.is_empty() {
        PathBuf::from("index.html")
    } else {
        safe_package_relative_path(rel).ok()?
    };
    for comp in rel_path.components() {
        if let std::path::Component::Normal(seg) = comp {
            let s = seg.to_str()?;
            if s.contains(':') || (s.starts_with('.') && s != ".well-known") {
                return None;
            }
        }
    }
    let mut candidate = dir.join(rel_path);
    if candidate.is_dir() {
        candidate = candidate.join("index.html");
    }
    let canon_dir = dir.canonicalize().ok()?;
    let canon_file = candidate.canonicalize().ok()?;
    if canon_file.starts_with(&canon_dir)
        && canon_file.is_file()
        && canon_file
            .metadata()
            .is_ok_and(|m| m.len() <= MAX_STATIC_FILE_BYTES)
    {
        Some(canon_file)
    } else {
        None
    }
}

pub(crate) fn write_secret_file(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        f.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        fs::write(path, content).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn default_bind_host() -> String {
    std::env::var("KOVREK_BIND_HOST")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

fn is_loopback_bind_host(host: &str) -> bool {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed.eq_ignore_ascii_case("localhost")
        || trimmed
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn actual_server_port(server: &Server, fallback_port: u16) -> u16 {
    server
        .server_addr()
        .to_ip()
        .map(|sa| sa.port())
        .unwrap_or(fallback_port)
}

fn req_header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().trim())
}

fn is_valid_host_header(host: &str, bind_host: &str, port: u16) -> bool {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return false;
    }
    if bind_host == "0.0.0.0" || bind_host == "::" || bind_host == "[::]" {
        return !trimmed.contains('/')
            && !trimmed.contains('@')
            && !trimmed.contains(char::is_whitespace);
    }
    let bh = bind_host.trim_start_matches('[').trim_end_matches(']');
    let expected_bh_host = if bh.contains(':') {
        format!("[{bh}]")
    } else {
        bh.to_string()
    };
    let candidates = [
        "127.0.0.1".to_string(),
        format!("127.0.0.1:{port}"),
        "localhost".to_string(),
        format!("localhost:{port}"),
        "[::1]".to_string(),
        format!("[::1]:{port}"),
        expected_bh_host.clone(),
        format!("{expected_bh_host}:{port}"),
    ];
    candidates.iter().any(|c| trimmed.eq_ignore_ascii_case(c))
}

fn is_valid_local_origin(origin: &str, bind_host: &str, port: u16) -> bool {
    let trimmed = origin.trim().trim_end_matches('/');
    let bh = bind_host.trim_start_matches('[').trim_end_matches(']');
    let bh_host = if bh.contains(':') {
        format!("[{bh}]")
    } else {
        bh.to_string()
    };
    let mut allowed = vec![
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
        format!("http://{bh_host}:{port}"),
    ];
    if port == 80 {
        allowed.push("http://127.0.0.1".into());
        allowed.push("http://localhost".into());
        allowed.push("http://[::1]".into());
        allowed.push(format!("http://{bh_host}"));
    }
    allowed.iter().any(|a| trimmed.eq_ignore_ascii_case(a))
}

pub(crate) fn authorize_control_plane_request(
    req: &Request,
    expected_token: &str,
    bind_host: &str,
    port: u16,
    require_json_post: bool,
) -> Result<(), (u16, &'static str)> {
    if let Some(host) = req_header(req, "Host")
        && !is_valid_host_header(host, bind_host, port)
    {
        return Err((403, "forbidden Host header"));
    }
    if let Some(origin) = req_header(req, "Origin")
        && !is_valid_local_origin(origin, bind_host, port)
    {
        return Err((403, "forbidden cross-origin request"));
    }
    let bearer = req_header(req, "Authorization").and_then(|v| {
        if v.len() >= 7 && v[..7].eq_ignore_ascii_case("bearer ") {
            Some(v[7..].trim())
        } else {
            None
        }
    });
    let alt = req_header(req, "X-Kovrek-Token");
    let supplied = bearer.or(alt).unwrap_or("");
    if expected_token.is_empty() || !constant_time_strings_equal(supplied, expected_token) {
        return Err((401, "unauthorized: valid bearer token required"));
    }
    if require_json_post && req.method().as_str().eq_ignore_ascii_case("POST") {
        let ct = req_header(req, "Content-Type").unwrap_or("");
        let media = ct.split(';').next().unwrap_or("").trim();
        if !media.eq_ignore_ascii_case("application/json") {
            return Err((415, "Content-Type must be application/json"));
        }
    }
    Ok(())
}

fn allowed_registry_static_path(root: &Path, raw_url: &str) -> Option<PathBuf> {
    let url_path = raw_url.split('?').next().unwrap_or("/");
    let trimmed = url_path.trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let rel = safe_package_relative_path(trimmed).ok()?;
    let mut comps = rel.components();
    let first = match comps.next() {
        Some(Component::Normal(s)) => s.to_string_lossy().to_string(),
        _ => return None,
    };
    if !matches!(first.as_str(), "bundles" | "packages" | "registry") {
        return None;
    }
    if rel
        .components()
        .any(|c| matches!(c, Component::Normal(s) if s.to_string_lossy().starts_with('.')))
    {
        return None;
    }
    let candidate = root.join(&rel);
    let canon_root = fs::canonicalize(root).ok()?;
    let canon_cand = fs::canonicalize(&candidate).ok()?;
    if canon_cand.starts_with(&canon_root) && canon_cand.is_file() {
        Some(canon_cand)
    } else {
        None
    }
}

pub(crate) fn serve_directory(dir: &Path, port: u16) -> Result<(), String> {
    let bind_host = default_bind_host();
    let server = Server::http(format!("{bind_host}:{port}")).map_err(|e| e.to_string())?;
    let actual_port = actual_server_port(&server, port);
    println!("Kovrek web server: http://{bind_host}:{actual_port}");
    println!("Serving {}", dir.display());
    for req in server.incoming_requests() {
        let mut response = if let Some(path) = resolve_static_path(dir, req.url()) {
            let data = fs::read(&path).map_err(|e| e.to_string())?;
            let mut r = Response::from_data(data);
            let content_type = match path.extension().and_then(|x| x.to_str()).unwrap_or("") {
                "html" => "text/html; charset=utf-8",
                "css" => "text/css; charset=utf-8",
                "js" => "application/javascript; charset=utf-8",
                "json" => "application/json; charset=utf-8",
                "png" => "image/png",
                "jpg" | "jpeg" => "image/jpeg",
                "svg" => "image/svg+xml",
                _ => "application/octet-stream",
            };
            if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()) {
                r.add_header(h);
            }
            r
        } else {
            Response::from_string("404 Not Found").with_status_code(StatusCode(404))
        };
        apply_security_headers(&mut response);
        req.respond(response).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(crate) fn serve_routes(routes_file: &Path, port: u16) -> Result<(), String> {
    let config: JsonValue =
        serde_json::from_str(&fs::read_to_string(routes_file).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let max_body_bytes = config
        .get("max_body_bytes")
        .and_then(JsonValue::as_u64)
        .map(|n| (n as usize).clamp(1024, 64 * 1024 * 1024))
        .unwrap_or(DEFAULT_MAX_BODY_BYTES);
    let routes = config
        .get("routes")
        .and_then(JsonValue::as_object)
        .ok_or("web route file requires a 'routes' object")?;
    let bind_host = default_bind_host();
    let server = Server::http(format!("{bind_host}:{port}")).map_err(|e| e.to_string())?;
    let actual_port = actual_server_port(&server, port);
    println!("Kovrek API server: http://{bind_host}:{actual_port}");
    println!("Routes: {}", routes.len());
    for mut req in server.incoming_requests() {
        let path = req.url().split('?').next().unwrap_or("/").to_string();
        let method = req.method().as_str().to_string();
        let method_key = format!("{method} {path}");
        let route = routes.get(&method_key).or_else(|| routes.get(&path));
        let response = if let Some(route) = route {
            let status = route
                .get("status")
                .and_then(JsonValue::as_u64)
                .unwrap_or(200) as u16;
            let content_type = route
                .get("content_type")
                .and_then(JsonValue::as_str)
                .unwrap_or_else(|| {
                    if route.get("json").is_some() {
                        "application/json; charset=utf-8"
                    } else {
                        "text/plain; charset=utf-8"
                    }
                });
            if route
                .get("echo")
                .and_then(JsonValue::as_bool)
                .unwrap_or(false)
            {
                match read_request_body_limited(&mut req, max_body_bytes) {
                    Ok(text) => {
                        let mut r = Response::from_string(text)
                            .with_status_code(StatusCode(status))
                            .boxed();
                        if let Ok(h) =
                            Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes())
                        {
                            r.add_header(h);
                        }
                        apply_security_headers(&mut r);
                        r
                    }
                    Err(BodyReadError::TooLarge(limit)) => {
                        json_error_response(413, &format!("request body exceeded {limit} bytes"))
                    }
                    Err(BodyReadError::Io(e)) => json_error_response(400, &e),
                }
            } else {
                let body = if let Some(j) = route.get("json") {
                    serde_json::to_string(j).map_err(|e| e.to_string())?
                } else {
                    route
                        .get("body")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("")
                        .to_string()
                };
                let mut r = Response::from_string(body)
                    .with_status_code(StatusCode(status))
                    .boxed();
                if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()) {
                    r.add_header(h);
                }
                apply_security_headers(&mut r);
                r
            }
        } else {
            let mut r = Response::from_string("404 Not Found")
                .with_status_code(StatusCode(404))
                .boxed();
            apply_security_headers(&mut r);
            r
        };
        req.respond(response).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(crate) fn match_route_pattern(pattern: &str, path: &str) -> Option<Vec<(String, String)>> {
    let p: Vec<&str> = pattern
        .trim_matches('/')
        .split('/')
        .filter(|x| !x.is_empty())
        .collect();
    let a: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|x| !x.is_empty())
        .collect();
    if p.len() != a.len() {
        return None;
    }
    let mut params = vec![];
    for (expected, actual) in p.iter().zip(a.iter()) {
        if expected.starts_with('{') && expected.ends_with('}') && expected.len() > 2 {
            params.push((
                expected[1..expected.len() - 1].to_string(),
                (*actual).to_string(),
            ));
        } else if expected != actual {
            return None;
        }
    }
    Some(params)
}

pub(crate) fn query_params(url: &str) -> Val {
    let mut pairs = vec![];
    if let Some(query) = url.split_once('?').map(|(_, q)| q) {
        for item in query.split('&').filter(|x| !x.is_empty()) {
            let (key, value) = item.split_once('=').unwrap_or((item, ""));
            pairs.push((Val::Str(key.to_string()), Val::Str(value.to_string())));
        }
    }
    Val::Map(pairs)
}

pub(crate) fn serve_kovrek_app(
    app_file: &Path,
    routes_file: &Path,
    port: u16,
) -> Result<(), String> {
    let src = load_source(app_file.to_string_lossy().as_ref())?;
    let vm = prepare_vm(&src)?;
    let config: JsonValue =
        serde_json::from_str(&fs::read_to_string(routes_file).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let routes = config
        .get("routes")
        .and_then(JsonValue::as_object)
        .ok_or("app routes file requires a 'routes' object")?
        .clone();
    let static_dir = config
        .get("static_dir")
        .and_then(JsonValue::as_str)
        .map(|s| {
            let p = Path::new(s);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                routes_file
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(p)
            }
        });
    let workers = config
        .get("workers")
        .and_then(JsonValue::as_u64)
        .map(|n| (n as usize).clamp(1, 16))
        .unwrap_or(4);
    let max_body_bytes = config
        .get("max_body_bytes")
        .and_then(JsonValue::as_u64)
        .map(|n| (n as usize).clamp(1024, 64 * 1024 * 1024))
        .unwrap_or(DEFAULT_MAX_BODY_BYTES);
    let bind_host = default_bind_host();
    let server = std::sync::Arc::new(
        Server::http(format!("{bind_host}:{port}")).map_err(|e| e.to_string())?,
    );
    let actual_port = actual_server_port(&server, port);
    println!("Kovrek dynamic app: http://{bind_host}:{actual_port}");
    println!("Handlers: {} (workers: {workers})", routes.len());
    let routes = std::sync::Arc::new(routes);
    let static_dir = std::sync::Arc::new(static_dir);
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let srv = server.clone();
        let wvm = vm.clone_worker();
        let rts = routes.clone();
        let sdir = static_dir.clone();
        handles.push(std::thread::spawn(move || {
            for mut req in srv.incoming_requests() {
                let full_url = req.url().to_string();
                let path = full_url.split('?').next().unwrap_or("/").to_string();
                let method = req.method().as_str().to_string();
                let key = format!("{method} {path}");
                let mut route_params: Vec<(String, String)> = vec![];
                let mut handler = rts
                    .get(&key)
                    .or_else(|| rts.get(&path))
                    .and_then(JsonValue::as_str)
                    .map(str::to_string);
                if handler.is_none() {
                    for (route_key, value) in rts.iter() {
                        let (route_method, pattern) = route_key
                            .split_once(' ')
                            .map(|(m, p)| (Some(m), p))
                            .unwrap_or((None, route_key.as_str()));
                        if route_method.is_some() && route_method != Some(method.as_str()) {
                            continue;
                        }
                        if let Some(params) = match_route_pattern(pattern, &path)
                            && let Some(name) = value.as_str()
                        {
                            handler = Some(name.to_string());
                            route_params = params;
                            break;
                        }
                    }
                }
                if let Some(handler) = handler {
                    let body = match read_request_body_limited(&mut req, max_body_bytes) {
                        Ok(b) => b,
                        Err(BodyReadError::TooLarge(limit)) => {
                            let _ = req.respond(json_error_response(
                                413,
                                &format!("request body exceeded {limit} bytes"),
                            ));
                            continue;
                        }
                        Err(BodyReadError::Io(e)) => {
                            let _ = req.respond(json_error_response(400, &e));
                            continue;
                        }
                    };
                    let params = Val::Map(
                        route_params
                            .iter()
                            .map(|(k, v)| (Val::Str(k.clone()), Val::Str(v.clone())))
                            .collect(),
                    );
                    let query = query_params(&full_url);
                    let headers = Val::Map(
                        req.headers()
                            .iter()
                            .map(|h| {
                                (
                                    Val::Str(h.field.as_str().to_string()),
                                    Val::Str(h.value.as_str().to_string()),
                                )
                            })
                            .collect(),
                    );
                    let request = Val::Map(vec![
                        (Val::Str("method".into()), Val::Str(method)),
                        (Val::Str("path".into()), Val::Str(path)),
                        (Val::Str("url".into()), Val::Str(full_url)),
                        (Val::Str("body".into()), Val::Str(body)),
                        (Val::Str("params".into()), params),
                        (Val::Str("query".into()), query),
                        (Val::Str("headers".into()), headers),
                    ]);
                    let resp = match wvm.invoke(&handler, vec![request]) {
                        Ok(value) => crate::universal_arch::val_to_http_response(value),
                        Err(e) => {
                            let mut r = Response::from_string(format!("Kovrek handler error: {e}"))
                                .with_status_code(StatusCode(500))
                                .boxed();
                            apply_security_headers(&mut r);
                            r
                        }
                    };
                    let _ = req.respond(resp);
                } else if let Some(dir) = sdir.as_deref()
                    && let Some(file_path) = resolve_static_path(dir, &full_url)
                    && let Ok(data) = fs::read(&file_path)
                {
                    let mut r = Response::from_data(data).boxed();
                    let ct = match file_path.extension().and_then(|x| x.to_str()).unwrap_or("") {
                        "html" | "htm" => "text/html; charset=utf-8",
                        "css" => "text/css; charset=utf-8",
                        "js" | "mjs" => "application/javascript; charset=utf-8",
                        "json" => "application/json; charset=utf-8",
                        "png" => "image/png",
                        "jpg" | "jpeg" => "image/jpeg",
                        "svg" => "image/svg+xml",
                        _ => "application/octet-stream",
                    };
                    if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], ct.as_bytes()) {
                        r.add_header(h);
                    }
                    apply_security_headers(&mut r);
                    let _ = req.respond(r);
                } else {
                    let mut r = Response::from_string("404 Not Found")
                        .with_status_code(StatusCode(404))
                        .boxed();
                    apply_security_headers(&mut r);
                    let _ = req.respond(r);
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

pub(crate) fn serve_registry(dir: &Path, port: u16) -> Result<(), String> {
    let bind_host = default_bind_host();
    let publish_token = if let Some(tok) = std::env::var("KOVREK_REGISTRY_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        tok
    } else {
        let tok = crate::security::random_token_urlsafe(32)?;
        write_secret_file(&dir.join(".registry-token"), &tok)?;
        tok
    };
    let server = Server::http(format!("{bind_host}:{port}")).map_err(|e| e.to_string())?;
    let actual_port = actual_server_port(&server, port);
    println!("Kovrek Package Registry Server: http://{bind_host}:{actual_port}");
    println!("Root {} (publish auth required)", dir.display());
    for mut req in server.incoming_requests() {
        let method = req.method().as_str().to_string();
        let path = req.url().split('?').next().unwrap_or("/").to_string();
        let mut response = if method == "POST"
            && (path == "/publish" || path == "/registry/publish")
        {
            if let Err((status, msg)) =
                authorize_control_plane_request(&req, &publish_token, &bind_host, actual_port, true)
            {
                let mut r = Response::from_string(serde_json::json!({ "error": msg }).to_string())
                    .with_status_code(StatusCode(status));
                if let Ok(h) = Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"application/json; charset=utf-8"[..],
                ) {
                    r.add_header(h);
                }
                apply_security_headers(&mut r);
                req.respond(r).map_err(|e| e.to_string())?;
                continue;
            }
            let resp = match read_request_body_limited(&mut req, REGISTRY_MAX_BODY_BYTES) {
                Ok(body) => match serde_json::from_str::<JsonValue>(&body) {
                    Ok(bundle) => {
                        let name = bundle.get("name").and_then(JsonValue::as_str).unwrap_or("");
                        let version = bundle
                            .get("version")
                            .and_then(JsonValue::as_str)
                            .unwrap_or("0.1.0");
                        let entry = bundle
                            .get("entry")
                            .and_then(JsonValue::as_str)
                            .unwrap_or("src/main.kvr");
                        if let Err(e) = crate::registry::validate_package_name(name) {
                            Response::from_string(format!("invalid package name: {e}"))
                                .with_status_code(StatusCode(400))
                        } else if let Err(e) = safe_package_relative_path(entry) {
                            Response::from_string(format!("invalid package entry: {e}"))
                                .with_status_code(StatusCode(400))
                        } else {
                            let pkg_dir = dir.join("packages").join(name);
                            match unpack_bundle_to_dir(&bundle, &pkg_dir).and_then(|()| {
                                let verified_sha =
                                    crate::registry::hash_directory_excluding_sig(&pkg_dir)?;
                                Ok(verified_sha)
                            }) {
                                Ok(verified_sha) => {
                                    let bundles_dir = dir.join("bundles");
                                    let bundle_dest = bundles_dir.join(format!("{name}.kvpkg"));
                                    if let Some(parent) = bundle_dest.parent() {
                                        let _ = fs::create_dir_all(parent);
                                    }
                                    let _ = fs::write(&bundle_dest, &body);
                                    let index_path = dir.join("registry").join("index.json");
                                    if let Some(parent) = index_path.parent() {
                                        let _ = fs::create_dir_all(parent);
                                    }
                                    let mut index: JsonValue = fs::read_to_string(&index_path)
                                        .ok()
                                        .and_then(|t| serde_json::from_str(&t).ok())
                                        .unwrap_or_else(|| {
                                            serde_json::json!({"registry_version":1,"packages":{}})
                                        });
                                    if !index.get("packages").is_some_and(JsonValue::is_object) {
                                        index["packages"] =
                                            JsonValue::Object(serde_json::Map::new());
                                    }
                                    let mut meta = serde_json::json!({
                                        "version": version,
                                        "entry": entry,
                                        "source": format!("../packages/{name}"),
                                        "bundle_path": format!("/bundles/{name}.kvpkg"),
                                        "sha256": verified_sha
                                    });
                                    if let Some(deps) = bundle.get("dependencies") {
                                        meta["dependencies"] = deps.clone();
                                    }
                                    if let Some(nat) = bundle.get("native").filter(|v| !v.is_null())
                                    {
                                        meta["native"] = nat.clone();
                                    }
                                    index["packages"][name] = meta;
                                    match serde_json::to_string_pretty(&index) {
                                        Ok(idx_text) => {
                                            if let Err(e) = fs::write(&index_path, idx_text) {
                                                Response::from_string(format!("write failed: {e}"))
                                                    .with_status_code(StatusCode(500))
                                            } else {
                                                let ok_json = serde_json::json!({
                                                    "published": name,
                                                    "version": version,
                                                    "sha256": verified_sha
                                                });
                                                Response::from_string(ok_json.to_string())
                                            }
                                        }
                                        Err(e) => Response::from_string(e.to_string())
                                            .with_status_code(StatusCode(500)),
                                    }
                                }
                                Err(e) => Response::from_string(format!("bundle error: {e}"))
                                    .with_status_code(StatusCode(400)),
                            }
                        }
                    }
                    Err(e) => Response::from_string(format!("invalid JSON: {e}"))
                        .with_status_code(StatusCode(400)),
                },
                Err(BodyReadError::TooLarge(limit)) => {
                    Response::from_string(format!("request body exceeded {limit} bytes"))
                        .with_status_code(StatusCode(413))
                }
                Err(BodyReadError::Io(e)) => {
                    Response::from_string(e).with_status_code(StatusCode(400))
                }
            };
            resp
        } else if method == "GET"
            && (path == "/" || path == "/index.json" || path == "/registry/index.json")
        {
            let p1 = dir.join("registry").join("index.json");
            let p2 = dir.join("index.json");
            let chosen = if p1.is_file() { p1 } else { p2 };
            match fs::read(&chosen) {
                Ok(data) => {
                    let mut r = Response::from_data(data);
                    if let Ok(h) = Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"application/json; charset=utf-8"[..],
                    ) {
                        r.add_header(h);
                    }
                    r
                }
                Err(_) => Response::from_string("404 Registry index not found")
                    .with_status_code(StatusCode(404)),
            }
        } else if let Some(sp) = allowed_registry_static_path(dir, req.url()) {
            match fs::read(&sp) {
                Ok(data) => Response::from_data(data),
                Err(_) => Response::from_string("500 Read error").with_status_code(StatusCode(500)),
            }
        } else {
            Response::from_string("404 Not Found").with_status_code(StatusCode(404))
        };
        apply_security_headers(&mut response);
        req.respond(response).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// =========================================================================
// Persistent Reactive Notebook Runtime & Server (`kovrek notebook`)
// =========================================================================

#[derive(Clone, Debug)]
pub(crate) struct NotebookCellResult {
    pub(crate) cell_id: String,
    pub(crate) source: String,
    pub(crate) stdout: String,
    pub(crate) value: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) exec_count: usize,
    pub(crate) defs: Vec<String>,
    pub(crate) refs: Vec<String>,
    pub(crate) cascade_updated: Vec<String>,
}

pub(crate) struct NotebookSession {
    vars: std::collections::HashMap<String, Val>,
    funcs: std::sync::Arc<std::collections::HashMap<String, crate::bytecode::FunctionDef>>,
    classes: std::sync::Arc<std::collections::HashMap<String, crate::bytecode::ClassDef>>,
    objects: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u64, crate::bytecode::ObjectData>>,
    >,
    class_objects: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
    pub(crate) cells: std::collections::BTreeMap<String, NotebookCellResult>,
    cell_order: Vec<String>,
    cell_deps: std::collections::BTreeMap<
        String,
        (
            std::collections::BTreeSet<String>,
            std::collections::BTreeSet<String>,
            std::collections::BTreeSet<String>,
        ),
    >,
    exec_counter: usize,
    storage_file: Option<PathBuf>,
}

impl NotebookSession {
    pub(crate) fn new(storage_file: Option<PathBuf>) -> Self {
        Self {
            vars: std::collections::HashMap::new(),
            funcs: std::sync::Arc::new(std::collections::HashMap::new()),
            classes: std::sync::Arc::new(std::collections::HashMap::new()),
            objects: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            class_objects: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            cells: std::collections::BTreeMap::new(),
            cell_order: Vec::new(),
            cell_deps: std::collections::BTreeMap::new(),
            exec_counter: 0,
            storage_file,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.vars.clear();
        self.funcs = std::sync::Arc::new(std::collections::HashMap::new());
        self.classes = std::sync::Arc::new(std::collections::HashMap::new());
        self.objects = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        self.class_objects =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        self.cells.clear();
        self.cell_order.clear();
        self.cell_deps.clear();
        self.exec_counter = 0;
        self.persist();
    }

    fn persist(&self) {
        let Some(ref path) = self.storage_file else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let items: Vec<JsonValue> = self
            .cells
            .values()
            .map(|c| {
                serde_json::json!({
                    "id": c.cell_id,
                    "source": c.source,
                    "stdout": c.stdout,
                    "value": c.value,
                    "error": c.error,
                    "exec_count": c.exec_count,
                    "defs": c.defs,
                    "refs": c.refs,
                })
            })
            .collect();
        if let Ok(raw) = serde_json::to_string_pretty(&serde_json::json!({ "cells": items })) {
            let _ = fs::write(path, raw);
        }
    }

    fn compute_dag_over(
        order_ids: &[String],
        deps_map: &std::collections::BTreeMap<
            String,
            (
                std::collections::BTreeSet<String>,
                std::collections::BTreeSet<String>,
                std::collections::BTreeSet<String>,
            ),
        >,
    ) -> (
        std::collections::BTreeMap<String, Vec<String>>,
        Vec<String>,
        Vec<String>,
    ) {
        let mut adj: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
            std::collections::BTreeMap::new();
        let mut indeg: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for id in order_ids {
            adj.entry(id.clone()).or_default();
            indeg.entry(id.clone()).or_insert(0);
        }
        for i in 0..order_ids.len() {
            for j in 0..order_ids.len() {
                if i == j {
                    continue;
                }
                let u = &order_ids[i];
                let v = &order_ids[j];
                let Some((u_defs, u_assigns, _)) = deps_map.get(u) else {
                    continue;
                };
                let Some((v_defs, v_assigns, v_refs)) = deps_map.get(v) else {
                    continue;
                };
                let def_edge = u_defs
                    .iter()
                    .any(|s| v_refs.contains(s) || v_assigns.contains(s));
                let assign_to_reader = u_assigns
                    .iter()
                    .any(|s| v_refs.contains(s) && !v_defs.contains(s) && !v_assigns.contains(s));
                if def_edge || assign_to_reader {
                    if adj.get_mut(u).is_some_and(|set| set.insert(v.clone())) {
                        *indeg.entry(v.clone()).or_insert(0) += 1;
                    }
                }
            }
        }

        let order_rank: std::collections::HashMap<&str, usize> = order_ids
            .iter()
            .enumerate()
            .map(|(idx, s)| (s.as_str(), idx))
            .collect();
        let mut ready: Vec<String> = order_ids
            .iter()
            .filter(|id| indeg.get(*id).copied().unwrap_or(0) == 0)
            .cloned()
            .collect();
        let mut topo = Vec::with_capacity(order_ids.len());
        while !ready.is_empty() {
            let cur = ready.remove(0);
            topo.push(cur.clone());
            if let Some(nbrs) = adj.get(&cur) {
                for nxt in nbrs {
                    if let Some(d) = indeg.get_mut(nxt) {
                        *d = d.saturating_sub(1);
                        if *d == 0 {
                            ready.push(nxt.clone());
                        }
                    }
                }
                ready.sort_by_key(|id| order_rank.get(id.as_str()).copied().unwrap_or(usize::MAX));
            }
        }
        let cycle_cells: Vec<String> = order_ids
            .iter()
            .filter(|id| !topo.contains(id))
            .cloned()
            .collect();
        let adj_vec = adj
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();
        (adj_vec, topo, cycle_cells)
    }

    fn execute_single_cell(
        &mut self,
        _cell_id: &str,
        source: &str,
    ) -> (String, Option<String>, Option<String>) {
        self.eval_snippet(source, true)
    }

    /// Evaluates a stateful Kovrek snippet against persistent session globals,
    /// functions, classes, and live object instances.
    fn eval_snippet(
        &mut self,
        source: &str,
        capture_stdout: bool,
    ) -> (String, Option<String>, Option<String>) {
        let trimmed = source.trim();
        let mut is_expr_fallback = false;
        let predeclared: Vec<String> = self
            .vars
            .keys()
            .chain(self.funcs.keys())
            .chain(self.classes.keys())
            .cloned()
            .collect();
        let compiled = if trimmed.is_empty() {
            Ok((Vec::new(), Vec::new()))
        } else {
            match crate::pipeline::compile_notebook_cell_with_globals(source, &predeclared) {
                Ok((code, dbg)) => Ok((code, dbg.local_names)),
                Err(stmt_err) => match crate::pipeline::compile_eval_expr(trimmed) {
                    Ok(code) => {
                        is_expr_fallback = true;
                        Ok((code, Vec::new()))
                    }
                    Err(_) => Err(stmt_err),
                },
            }
        };

        match compiled {
            Err(e) => (String::new(), None, Some(e)),
            Ok((code, local_names)) => {
                if code.is_empty() {
                    (String::new(), None, None)
                } else {
                    let mut vm = crate::vm::Vm::new(code);
                    vm.vars = self.vars.clone();
                    vm.funcs = self.funcs.clone();
                    vm.classes = self.classes.clone();
                    vm.objects = self.objects.clone();
                    vm.class_objects = self.class_objects.clone();
                    for (slot, name) in local_names.iter().enumerate() {
                        if let Some(val) = vm.vars.get(name).cloned()
                            && slot < vm.locals.len()
                        {
                            vm.locals[slot] = val;
                            vm.local_defined[slot] = true;
                        }
                    }

                    let (res, captured) = if capture_stdout {
                        crate::runtime::with_print_capture(|| vm.execute())
                    } else {
                        (vm.execute(), String::new())
                    };
                    for (slot, name) in local_names.iter().enumerate() {
                        if !name.starts_with("__")
                            && vm.local_defined.get(slot).copied().unwrap_or(false)
                            && let Some(val) = vm.locals.get(slot)
                        {
                            vm.vars.insert(name.clone(), val.clone());
                        }
                    }
                    self.vars = vm.vars;
                    self.funcs = vm.funcs;
                    self.classes = vm.classes;
                    self.objects = vm.objects;
                    self.class_objects = vm.class_objects;
                    match res {
                        Ok(v) => {
                            let val_str = if is_expr_fallback || !matches!(v, Val::Null) {
                                Some(v.show())
                            } else {
                                None
                            };
                            (captured, val_str, None)
                        }
                        Err(err) => (captured, None, Some(err)),
                    }
                }
            }
        }
    }

    /// Evaluates one interactive REPL/terminal input against persistent session state.
    pub(crate) fn eval_repl(&mut self, source: &str) -> Result<Option<String>, String> {
        let (_out, val, err) = self.eval_snippet(source, false);
        match err {
            Some(e) => Err(e),
            None => Ok(val),
        }
    }

    /// Lists user-visible session globals sorted by identifier name.
    pub(crate) fn session_vars(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .vars
            .iter()
            .filter(|(k, _)| !k.starts_with("__"))
            .map(|(k, v)| (k.clone(), v.show()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub(crate) fn set_var(&mut self, name: String, val: Val) {
        self.vars.insert(name, val);
    }

    pub(crate) fn has_symbol(&self, name: &str) -> bool {
        self.vars.contains_key(name)
            || self.funcs.contains_key(name)
            || self.classes.contains_key(name)
    }

    pub(crate) fn eval_cell(&mut self, cell_id: &str, source: &str) -> NotebookCellResult {
        self.exec_counter += 1;
        let exec_count = self.exec_counter;
        let (defs_set, assigns_set, refs_set) = crate::pipeline::analyze_cell_deps(source);
        let defs_vec: Vec<String> = defs_set.iter().cloned().collect();
        let refs_vec: Vec<String> = refs_set.iter().cloned().collect();

        let is_new = !self.cell_order.iter().any(|c| c == cell_id);
        let mut next_order = self.cell_order.clone();
        if is_new {
            next_order.push(cell_id.to_string());
        }
        let mut next_deps = self.cell_deps.clone();
        next_deps.insert(cell_id.to_string(), (defs_set, assigns_set, refs_set));

        let (adj, topo, cycle_cells) = Self::compute_dag_over(&next_order, &next_deps);
        if !cycle_cells.is_empty() {
            let err_msg = format!(
                "NotebookCycleError: cyclic dependency among cells {:?}",
                cycle_cells
            );
            self.cell_order = next_order;
            self.cell_deps = next_deps;
            let result = NotebookCellResult {
                cell_id: cell_id.to_string(),
                source: source.to_string(),
                stdout: String::new(),
                value: None,
                error: Some(err_msg),
                exec_count,
                defs: defs_vec,
                refs: refs_vec,
                cascade_updated: Vec::new(),
            };
            self.cells.insert(cell_id.to_string(), result.clone());
            self.persist();
            return result;
        }

        self.cell_order = next_order;
        self.cell_deps = next_deps;
        let (stdout, value, error) = self.execute_single_cell(cell_id, source);

        // Find all strict downstream cells in topological order and re-execute when cell succeeded.
        let mut downstream_set = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        if error.is_none() {
            queue.push_back(cell_id.to_string());
            while let Some(cur) = queue.pop_front() {
                if let Some(nbrs) = adj.get(&cur) {
                    for nxt in nbrs {
                        if nxt != cell_id && downstream_set.insert(nxt.clone()) {
                            queue.push_back(nxt.clone());
                        }
                    }
                }
            }
        }

        let mut cascade_updated = Vec::new();
        for dep_id in topo {
            if !downstream_set.contains(&dep_id) {
                continue;
            }
            let Some(prev) = self.cells.get(&dep_id).cloned() else {
                continue;
            };
            self.exec_counter += 1;
            let c_exec = self.exec_counter;
            let (c_out, c_val, c_err) = self.execute_single_cell(&dep_id, &prev.source);
            let updated = NotebookCellResult {
                cell_id: dep_id.clone(),
                source: prev.source,
                stdout: c_out,
                value: c_val,
                error: c_err,
                exec_count: c_exec,
                defs: prev.defs,
                refs: prev.refs,
                cascade_updated: Vec::new(),
            };
            self.cells.insert(dep_id.clone(), updated);
            cascade_updated.push(dep_id);
        }

        let result = NotebookCellResult {
            cell_id: cell_id.to_string(),
            source: source.to_string(),
            stdout,
            value,
            error,
            exec_count,
            defs: defs_vec,
            refs: refs_vec,
            cascade_updated,
        };
        self.cells.insert(cell_id.to_string(), result.clone());
        self.persist();
        result
    }

    pub(crate) fn dag_info(&self) -> JsonValue {
        let (adj, topo, cycle_cells) = Self::compute_dag_over(&self.cell_order, &self.cell_deps);
        let nodes: Vec<JsonValue> = self
            .cell_order
            .iter()
            .map(|id| {
                let (defs, assigns, refs) = self.cell_deps.get(id).cloned().unwrap_or_default();
                serde_json::json!({
                    "id": id,
                    "defs": defs.into_iter().collect::<Vec<_>>(),
                    "assigns": assigns.into_iter().collect::<Vec<_>>(),
                    "refs": refs.into_iter().collect::<Vec<_>>(),
                })
            })
            .collect();
        let mut edges = Vec::new();
        for (from, tos) in adj {
            for to in tos {
                edges.push(serde_json::json!({ "from": from, "to": to }));
            }
        }
        serde_json::json!({
            "nodes": nodes,
            "edges": edges,
            "order": topo,
            "has_cycle": !cycle_cells.is_empty(),
            "cycle_cells": cycle_cells,
        })
    }

    pub(crate) fn export_script(&self) -> String {
        let (_, topo, _) = Self::compute_dag_over(&self.cell_order, &self.cell_deps);
        let ordered = if topo.is_empty() {
            self.cell_order.clone()
        } else {
            topo
        };
        let mut out = String::new();
        for id in ordered {
            if let Some(cell) = self.cells.get(&id) {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&format!("// --- cell: {} ---\n", cell.cell_id));
                out.push_str(cell.source.trim_end());
                out.push('\n');
            }
        }
        out
    }
}

pub(crate) fn handle_notebook_api_request(
    session: &std::sync::Arc<std::sync::Mutex<NotebookSession>>,
    method: &str,
    url: &str,
    body: &str,
) -> (u16, &'static str, String) {
    match (method, url) {
        ("GET", "/api/notebook/state") => {
            let Ok(guard) = session.lock() else {
                return (500, "text/plain", "500 Session error".into());
            };
            let items: Vec<JsonValue> = guard
                .cells
                .values()
                .map(|c| {
                    serde_json::json!({
                        "id": c.cell_id,
                        "source": c.source,
                        "stdout": c.stdout,
                        "value": c.value,
                        "error": c.error,
                        "exec_count": c.exec_count,
                        "defs": c.defs,
                        "refs": c.refs,
                    })
                })
                .collect();
            (
                200,
                "application/json",
                serde_json::to_string(&serde_json::json!({ "cells": items })).unwrap_or_default(),
            )
        }
        ("GET", "/api/notebook/dag") => {
            let Ok(guard) = session.lock() else {
                return (500, "text/plain", "500 Session error".into());
            };
            (
                200,
                "application/json",
                serde_json::to_string(&guard.dag_info()).unwrap_or_default(),
            )
        }
        ("GET", "/api/notebook/export") => {
            let Ok(guard) = session.lock() else {
                return (500, "text/plain", "500 Session error".into());
            };
            (200, "text/plain; charset=utf-8", guard.export_script())
        }
        ("POST", "/api/notebook/run") => {
            let parsed: JsonValue = if body.trim().is_empty() {
                JsonValue::Null
            } else {
                match serde_json::from_str(body) {
                    Ok(v) => v,
                    Err(e) => {
                        return (
                            400,
                            "application/json",
                            serde_json::json!({ "error": format!("invalid JSON body: {e}") })
                                .to_string(),
                        );
                    }
                }
            };
            let cid = parsed
                .get("id")
                .and_then(JsonValue::as_str)
                .unwrap_or("cell1");
            let src = parsed
                .get("source")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let Ok(mut guard) = session.lock() else {
                return (500, "text/plain", "500 Session error".into());
            };
            let res = guard.eval_cell(cid, src);
            (
                200,
                "application/json",
                serde_json::to_string(&serde_json::json!({
                    "id": res.cell_id,
                    "stdout": res.stdout,
                    "value": res.value,
                    "error": res.error,
                    "exec_count": res.exec_count,
                    "defs": res.defs,
                    "refs": res.refs,
                    "cascade_updated": res.cascade_updated,
                }))
                .unwrap_or_default(),
            )
        }
        ("POST", "/api/notebook/reset") => {
            if let Ok(mut guard) = session.lock() {
                guard.reset();
            }
            (200, "application/json", r#"{"ok":true}"#.into())
        }
        _ => (404, "text/plain", "404 Not Found".into()),
    }
}

pub(crate) fn serve_notebook(dir: &Path, port: u16) -> Result<(), String> {
    let bind_host = default_bind_host();
    let auth_token = std::env::var("KOVREK_NOTEBOOK_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(Ok)
        .unwrap_or_else(|| crate::security::random_token_urlsafe(32))?;
    let notebook_caps: Option<Vec<String>> = std::env::var("KOVREK_NOTEBOOK_CAPS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .or_else(|| {
            if !is_loopback_bind_host(&bind_host) {
                Some(vec!["math".into(), "io".into(), "fs.read".into()])
            } else {
                None
            }
        });

    let storage = dir.join(".kovrek-notebook.json");
    let session = std::sync::Arc::new(std::sync::Mutex::new(NotebookSession::new(Some(
        storage.clone(),
    ))));
    let server = Server::http(format!("{bind_host}:{port}")).map_err(|e| e.to_string())?;
    let actual_port = actual_server_port(&server, port);
    println!("Kovrek Notebook server: http://{bind_host}:{actual_port}/#token={auth_token}");
    println!("Workspace: {}", dir.display());
    if let Some(ref caps) = notebook_caps {
        println!("Notebook sandbox caps: {}", caps.join(", "));
    }

    const UI_HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Kovrek Notebook</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;background:#0f172a;color:#e2e8f0}
textarea{width:100%;height:90px;background:#1e293b;color:#f8fafc;border:1px solid #334155;padding:.6rem;font-family:monospace}
input{padding:.4rem;background:#1e293b;color:#f8fafc;border:1px solid #334155}
button{background:#38bdf8;color:#0f172a;border:0;padding:.45rem 1rem;border-radius:6px;font-weight:600;cursor:pointer;margin:.4rem .3rem 0 0}
pre{background:#020617;padding:.75rem;border-radius:6px;white-space:pre-wrap}</style></head>
<body><h1>Kovrek Reactive Notebook</h1>
<div style="margin-bottom:.5rem"><input id="tok" type="password" placeholder="Notebook Bearer Token" style="width:24rem"/>
<input id="cid" value="cell1"/>
<button onclick="runCell()">Run Cell</button><button onclick="resetNb()">Reset Session</button></div>
<textarea id="src" placeholder="let x = 21 * 2;&#10;print(x);"></textarea>
<pre id="out">Ready.</pre>
<script>
(()=>{const h=location.hash||'';const m=h.match(/token=([^&]+)/);if(m){try{sessionStorage.setItem('kovrek_nb_tok',decodeURIComponent(m[1]));}catch(_){}history.replaceState(null,'',location.pathname+location.search);}try{tok.value=sessionStorage.getItem('kovrek_nb_tok')||'';}catch(_){}tok.addEventListener('change',()=>{try{sessionStorage.setItem('kovrek_nb_tok',tok.value);}catch(_){}});})();
function authHdrs(){const t=(tok.value||'').trim();return t?{'Content-Type':'application/json','Authorization':'Bearer '+t}:{'Content-Type':'application/json'};}
async function runCell(){const r=await fetch('/api/notebook/run',{method:'POST',headers:authHdrs(),body:JSON.stringify({id:cid.value,source:src.value})});const d=await r.json();out.textContent=JSON.stringify(d,null,2);}
async function resetNb(){const r=await fetch('/api/notebook/reset',{method:'POST',headers:authHdrs(),body:'{}'});const d=await r.json();out.textContent=JSON.stringify(d,null,2);}
</script></body></html>"#;

    for mut req in server.incoming_requests() {
        let method = req.method().as_str().to_string();
        let url = req.url().split('?').next().unwrap_or("/").to_string();
        let mut response = if method == "GET" && url == "/" {
            if let Some(host) = req_header(&req, "Host")
                && !is_valid_host_header(host, &bind_host, actual_port)
            {
                let mut r =
                    Response::from_string("403 Forbidden Host").with_status_code(StatusCode(403));
                apply_security_headers(&mut r);
                req.respond(r).map_err(|e| e.to_string())?;
                continue;
            }
            let mut r = Response::from_string(UI_HTML);
            if let Ok(h) =
                Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
            {
                r.add_header(h);
            }
            if let Ok(csp) = Header::from_bytes(
                &b"Content-Security-Policy"[..],
                &b"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; base-uri 'self'; frame-ancestors 'none'; form-action 'none'; object-src 'none'"[..],
            ) {
                r.add_header(csp);
            }
            r
        } else {
            if let Err((status, msg)) =
                authorize_control_plane_request(&req, &auth_token, &bind_host, actual_port, true)
            {
                let mut r = Response::from_string(serde_json::json!({ "error": msg }).to_string())
                    .with_status_code(StatusCode(status));
                if let Ok(h) = Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"application/json; charset=utf-8"[..],
                ) {
                    r.add_header(h);
                }
                apply_security_headers(&mut r);
                req.respond(r).map_err(|e| e.to_string())?;
                continue;
            }
            let body_res = if method == "POST" {
                read_request_body_limited(&mut req, DEFAULT_MAX_BODY_BYTES)
            } else {
                Ok(String::new())
            };
            let (status, ctype, text) = match body_res {
                Ok(body) => {
                    if let Some(ref caps) = notebook_caps {
                        crate::runtime::run_with_caps(caps.clone(), || {
                            Ok(handle_notebook_api_request(&session, &method, &url, &body))
                        })?
                    } else {
                        handle_notebook_api_request(&session, &method, &url, &body)
                    }
                }
                Err(BodyReadError::TooLarge(limit)) => (
                    413,
                    "application/json",
                    serde_json::json!({ "error": format!("request body exceeded {limit} bytes") })
                        .to_string(),
                ),
                Err(BodyReadError::Io(e)) => (
                    400,
                    "application/json",
                    serde_json::json!({ "error": e }).to_string(),
                ),
            };
            let mut r = Response::from_string(text).with_status_code(StatusCode(status));
            if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], ctype.as_bytes()) {
                r.add_header(h);
            }
            r
        };
        apply_security_headers(&mut response);
        req.respond(response).map_err(|e| e.to_string())?;
    }
    Ok(())
}
