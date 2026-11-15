#![allow(
    clippy::collapsible_if,
    clippy::needless_range_loop,
    clippy::type_complexity,
    clippy::let_and_return,
    clippy::only_used_in_recursion,
    unused_imports
)]

use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::Ordering,
        mpsc::{self, TryRecvError},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use libloading::Library;
use rand::Rng;
use regex::Regex;
#[cfg(feature = "native-services")]
use rusqlite::{Connection, OpenFlags};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::bytecode::{ClassDef, FunctionDef, ObjectData, Op};
use crate::pipeline::{compile_source, load_source};
use crate::pq_crypto;
use crate::project::project_root;
use crate::runtime::{
    CHANNEL_IDS, FUNCTION_IDS, GENERATOR_IDS, OBJECT_IDS, TASK_IDS, channels,
    export_function_object, namespace_module_ops, register_named_function_object,
    resolve_function_object, tasks,
};
use crate::security;
use crate::tensor::{
    AdamState, TensorOp, adam_states, tensor_backward, tensor_from_value, tensor_id,
    tensor_snapshot, tensor_store, tensors,
};
use crate::value::{
    Val, as_matrix, as_num_list, constant_time_strings_equal, distance_sq, hmac_sha256_hex,
    json_to_val, map_lookup, matrix_determinant, matrix_inverse, matrix_to_val, nums_to_val,
    pbkdf2_sha256_hex, solve_linear_system, svg_escape, val_to_json,
};
#[cfg(feature = "native-services")]
use crate::value::{json_stringify_value, val_to_sql_value};
use crate::vault_stream;
use crate::vm::{Vm, collect_generator, generators, resume_generator};

fn parse_aead_args<'a>(
    fn_name: &str,
    payload_label: &str,
    a: &'a [Val],
) -> Result<(&'a str, &'a str, &'a [u8]), String> {
    if a.len() != 2 && a.len() != 3 {
        return Err(format!("{fn_name} expects (key, {payload_label}[, aad])"));
    }
    let key = match &a[0] {
        Val::Str(s) => s.as_str(),
        _ => return Err(format!("{fn_name} key must be String")),
    };
    let payload = match &a[1] {
        Val::Str(s) => s.as_str(),
        _ => return Err(format!("{fn_name} {payload_label} must be String")),
    };
    let aad = match a.get(2) {
        Some(Val::Str(s)) => s.as_bytes(),
        Some(Val::Null) | None => b"",
        _ => return Err(format!("{fn_name} aad must be String")),
    };
    Ok((key, payload, aad))
}

fn val_to_raw_bytes(v: &Val, fn_name: &str, label: &str) -> Result<Vec<u8>, String> {
    match v {
        Val::Str(s) => Ok(s.as_bytes().to_vec()),
        Val::List(xs) => xs
            .iter()
            .map(|b| match b {
                Val::Num(n) if n.is_finite() && *n >= 0.0 && *n <= 255.0 => Ok(*n as u8),
                _ => Err(format!(
                    "{fn_name} {label} byte List entries must be integers in 0..=255"
                )),
            })
            .collect(),
        _ => Err(format!("{fn_name} {label} must be String or byte List")),
    }
}

fn map_opt_str(pairs: &[(Val, Val)], keys: &[&str]) -> Result<Option<String>, String> {
    for &k in keys {
        if let Some(v) = map_lookup(pairs, &Val::Str(k.into())) {
            return match v {
                Val::Null => Ok(None),
                Val::Str(s) => Ok(Some(s.clone())),
                _ => Err(format!("option '{k}' must be String")),
            };
        }
    }
    Ok(None)
}

fn map_opt_bool(pairs: &[(Val, Val)], keys: &[&str], default: bool) -> Result<bool, String> {
    for &k in keys {
        if let Some(v) = map_lookup(pairs, &Val::Str(k.into())) {
            return match v {
                Val::Null => Ok(default),
                Val::Bool(b) => Ok(*b),
                _ => Err(format!("option '{k}' must be Bool")),
            };
        }
    }
    Ok(default)
}

fn map_opt_u32(
    pairs: &[(Val, Val)],
    keys: &[&str],
    default: u32,
    min: u32,
    max: u32,
) -> Result<u32, String> {
    for &k in keys {
        if let Some(v) = map_lookup(pairs, &Val::Str(k.into())) {
            return match v {
                Val::Null => Ok(default),
                Val::Num(n) if n.is_finite() && *n >= f64::from(min) && *n <= f64::from(max) => {
                    Ok(*n as u32)
                }
                Val::Num(_) => Err(format!("option '{k}' must be in {min}..={max}")),
                _ => Err(format!("option '{k}' must be Number")),
            };
        }
    }
    Ok(default)
}

fn checked_usize_arg(v: &Val, name: &str, min: usize, max: usize) -> Result<usize, String> {
    match v {
        Val::Num(n) if n.is_finite() && *n >= (min as f64) && *n <= (max as f64) => Ok(*n as usize),
        Val::Num(_) => Err(format!("{name} must be in {min}..={max}")),
        _ => Err(format!("{name} must be Number")),
    }
}

fn wasm_bytes_from_val(v: &Val) -> Result<Vec<u8>, String> {
    match v {
        Val::Str(path) => {
            crate::runtime::require_cap("fs.read")?;
            fs::read(path).map_err(|e| format!("failed to read wasm '{path}': {e}"))
        }
        Val::List(xs) => xs
            .iter()
            .map(|b| match b {
                Val::Num(n) if *n >= 0.0 && *n <= 255.0 => Ok(*n as u8),
                _ => Err("wasm bytes List entries must be integers in 0..=255".to_string()),
            })
            .collect(),
        _ => Err("expected wasm byte List or .wasm file path String".into()),
    }
}

#[cfg(feature = "native-services")]
const SQLITE_BUSY_TIMEOUT_MS: u64 = 5000;
#[cfg(feature = "native-services")]
const DEFAULT_SAFE_HTTP_MAX_BYTES: usize = 8 * 1024 * 1024;

#[cfg(feature = "native-services")]
fn open_sqlite_conn(path: &str) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
        .map_err(|e| e.to_string())?;
    let _ = conn.execute_batch("PRAGMA foreign_keys = ON;");
    Ok(conn)
}

#[cfg(feature = "native-services")]
fn sql_ref_to_val(cell: rusqlite::types::ValueRef<'_>) -> Val {
    match cell {
        rusqlite::types::ValueRef::Null => Val::Null,
        rusqlite::types::ValueRef::Integer(x) => Val::Num(x as f64),
        rusqlite::types::ValueRef::Real(x) => Val::Num(x),
        rusqlite::types::ValueRef::Text(x) => Val::Str(String::from_utf8_lossy(x).to_string()),
        rusqlite::types::ValueRef::Blob(x) => Val::Str(format!("<{} bytes>", x.len())),
    }
}

#[cfg(feature = "native-services")]
fn collect_sqlite_rows(
    conn: &Connection,
    sql: &str,
    params: &[rusqlite::types::Value],
) -> Result<Vec<Val>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |row| {
            let mut pairs = Vec::with_capacity(names.len());
            for (i, name) in names.iter().enumerate() {
                pairs.push((Val::Str(name.clone()), sql_ref_to_val(row.get_ref(i)?)));
            }
            Ok(Val::Map(pairs))
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

#[cfg(feature = "native-services")]
fn parse_sqlite_tx_item(item: &Val) -> Result<(String, Vec<rusqlite::types::Value>), String> {
    match item {
        Val::Str(sql) => Ok((sql.clone(), Vec::new())),
        Val::List(parts) if parts.len() == 1 || parts.len() == 2 => {
            let Val::Str(sql) = &parts[0] else {
                return Err("sqlite_tx statement SQL must be String".into());
            };
            let params = match parts.get(1) {
                Some(Val::List(xs)) => xs.iter().map(val_to_sql_value).collect(),
                Some(Val::Null) | None => Vec::new(),
                _ => return Err("sqlite_tx statement params must be List".into()),
            };
            Ok((sql.clone(), params))
        }
        Val::Map(pairs) => {
            let sql = match map_lookup(pairs, &Val::Str("sql".into())) {
                Some(Val::Str(s)) => s.clone(),
                _ => return Err("sqlite_tx map entry requires String 'sql'".into()),
            };
            let params = match map_lookup(pairs, &Val::Str("params".into())) {
                Some(Val::List(xs)) => xs.iter().map(val_to_sql_value).collect(),
                Some(Val::Null) | None => Vec::new(),
                _ => return Err("sqlite_tx map 'params' must be List".into()),
            };
            Ok((sql, params))
        }
        _ => Err("sqlite_tx items must be SQL String, [sql, params], or {sql, params}".into()),
    }
}

#[cfg(feature = "native-services")]
const DEFAULT_HTTP_MAX_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "native-services")]
const DEFAULT_HTTP_TIMEOUT_MS: u64 = 30_000;

fn checked_finite_range(v: &Val, name: &str, min: f64, max: f64) -> Result<f64, String> {
    match v {
        Val::Num(n) if n.is_finite() => Ok(n.clamp(min, max)),
        Val::Num(_) => Err(format!("{name} must be a finite Number")),
        _ => Err(format!("{name} must be Number")),
    }
}

#[cfg(feature = "native-services")]
fn validated_http_headers(headers: &[(Val, Val)]) -> Result<Vec<(String, String)>, String> {
    if headers.len() > 128 {
        return Err("too many HTTP headers (max 128)".into());
    }
    let mut out = Vec::with_capacity(headers.len());
    for (k, v) in headers {
        let key_str = k.show();
        let val_str = v.show();
        security::validate_http_header_pair(&key_str, &val_str, false)?;
        out.push((key_str, val_str));
    }
    Ok(out)
}

#[cfg(feature = "native-services")]
fn serialize_http_body(body_val: &Val) -> Result<Option<String>, String> {
    if matches!(body_val, Val::Null) {
        Ok(None)
    } else {
        Ok(Some(match body_val {
            Val::Str(s) => s.clone(),
            other => json_stringify_value(other)?,
        }))
    }
}

#[cfg(feature = "native-services")]
fn response_to_http_val(
    response: reqwest::blocking::Response,
    max_bytes: usize,
) -> Result<Val, String> {
    let status = response.status();
    let header_pairs = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                Val::Str(k.as_str().to_string()),
                Val::Str(v.to_str().unwrap_or("").to_string()),
            )
        })
        .collect::<Vec<_>>();
    let buf = security::read_to_end_limited(response, max_bytes, "HTTP response")?;
    let body = String::from_utf8_lossy(&buf).into_owned();
    Ok(Val::Map(vec![
        (Val::Str("status".into()), Val::Num(status.as_u16() as f64)),
        (Val::Str("ok".into()), Val::Bool(status.is_success())),
        (Val::Str("headers".into()), Val::Map(header_pairs)),
        (Val::Str("body".into()), Val::Str(body)),
    ]))
}

#[cfg(feature = "native-services")]
fn execute_general_http_response(
    method_text: &str,
    url_raw: &str,
    headers: &[(Val, Val)],
    body_val: &Val,
    timeout_ms: u64,
) -> Result<reqwest::blocking::Response, String> {
    let checked_headers = validated_http_headers(headers)?;
    let initial_parsed = security::validate_general_http_url(url_raw)?;
    let initial_is_public = security::validate_public_url(&initial_parsed.url, true).is_ok();
    let initial_origin = initial_parsed.origin.clone();
    let max_redirects = 5usize;
    let clamped_timeout = timeout_ms.clamp(1, 300_000);

    let mut current_url = initial_parsed.url;
    let mut current_method =
        reqwest::Method::from_bytes(method_text.as_bytes()).map_err(|e| e.to_string())?;
    let mut current_body = serialize_http_body(body_val)?;

    for hop in 0..=max_redirects {
        let mut builder = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(clamped_timeout))
            .redirect(reqwest::redirect::Policy::none());
        let (target_url, target_origin) = if initial_is_public {
            let validated = security::validate_public_url(&current_url, true)?;
            let addrs = security::resolve_public_url_addrs(&validated)?;
            builder = builder.resolve_to_addrs(&validated.host, &addrs);
            (validated.url, validated.origin)
        } else {
            let validated = security::validate_general_http_url(&current_url)?;
            (validated.url, validated.origin)
        };
        let client = builder.build().map_err(|e| e.to_string())?;
        let mut request = client.request(current_method.clone(), &target_url);
        for (key_str, val_str) in &checked_headers {
            if target_origin != initial_origin
                && (key_str.eq_ignore_ascii_case("authorization")
                    || key_str.eq_ignore_ascii_case("proxy-authorization")
                    || key_str.eq_ignore_ascii_case("cookie")
                    || key_str.eq_ignore_ascii_case("x-kovrek-token"))
            {
                continue;
            }
            request = request.header(key_str.as_str(), val_str.as_str());
        }
        if let Some(ref body_str) = current_body {
            request = request.body(body_str.clone());
        }
        let response = request.send().map_err(|e| e.to_string())?;
        if response.status().is_redirection() && hop < max_redirects {
            let Some(loc) = response.headers().get(reqwest::header::LOCATION) else {
                return Ok(response);
            };
            let loc_str = loc.to_str().map_err(|e| e.to_string())?;
            let next_raw =
                security::resolve_redirect_location(&target_url, &target_origin, loc_str)?;
            if initial_is_public {
                let next_val = security::validate_public_url(&next_raw, true)?;
                let _ = security::resolve_public_url_addrs(&next_val)?;
                current_url = next_val.url;
            } else {
                let next_val = security::validate_general_http_url(&next_raw)?;
                current_url = next_val.url;
            }
            if (301..=303).contains(&response.status().as_u16())
                && current_method != reqwest::Method::GET
                && current_method != reqwest::Method::HEAD
            {
                current_method = reqwest::Method::GET;
                current_body = None;
            }
            continue;
        }
        return Ok(response);
    }
    Err("too many redirects".into())
}

#[cfg(feature = "native-services")]
fn execute_safe_http(
    method_text: &str,
    url_raw: &str,
    headers: &[(Val, Val)],
    body_val: &Val,
    timeout_ms: u64,
    opts: Option<&Vec<(Val, Val)>>,
) -> Result<Val, String> {
    let checked_headers = validated_http_headers(headers)?;
    let allow_http = opts
        .and_then(|m| map_lookup(m, &Val::Str("allow_http".into())))
        .is_none_or(Val::truthy);
    let max_redirects = opts
        .and_then(|m| map_lookup(m, &Val::Str("max_redirects".into())))
        .and_then(|v| match v {
            Val::Num(n) if n.is_finite() => Some((*n as i64).clamp(0, 5) as usize),
            _ => None,
        })
        .unwrap_or(3);
    let allow_cross_origin = opts
        .and_then(|m| map_lookup(m, &Val::Str("allow_cross_origin_redirect".into())))
        .is_some_and(Val::truthy);
    let max_resp_bytes = opts
        .and_then(|m| map_lookup(m, &Val::Str("max_response_bytes".into())))
        .and_then(|v| match v {
            Val::Num(n) if n.is_finite() && *n >= 1024.0 => {
                Some((*n as usize).min(64 * 1024 * 1024))
            }
            _ => None,
        })
        .unwrap_or(DEFAULT_SAFE_HTTP_MAX_BYTES);

    let clamped_timeout = timeout_ms.clamp(1, 300_000);
    let mut current_url = url_raw.to_string();
    let mut current_method =
        reqwest::Method::from_bytes(method_text.as_bytes()).map_err(|e| e.to_string())?;
    let mut current_body = serialize_http_body(body_val)?;

    let initial_origin = security::validate_public_url(&current_url, allow_http)?.origin;

    for hop in 0..=max_redirects {
        let validated = security::validate_public_url(&current_url, allow_http)?;
        let addrs = security::resolve_public_url_addrs(&validated)?;
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(clamped_timeout))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&validated.host, &addrs)
            .build()
            .map_err(|e| e.to_string())?;
        let mut request = client.request(current_method.clone(), &validated.url);
        for (key_str, val_str) in &checked_headers {
            if validated.origin != initial_origin
                && (key_str.eq_ignore_ascii_case("authorization")
                    || key_str.eq_ignore_ascii_case("proxy-authorization")
                    || key_str.eq_ignore_ascii_case("cookie")
                    || key_str.eq_ignore_ascii_case("x-kovrek-token"))
            {
                continue;
            }
            request = request.header(key_str.as_str(), val_str.as_str());
        }
        if let Some(ref body_str) = current_body {
            request = request.body(body_str.clone());
        }
        let response = request.send().map_err(|e| e.to_string())?;
        if response.status().is_redirection() && hop < max_redirects {
            let Some(loc) = response.headers().get(reqwest::header::LOCATION) else {
                return response_to_http_val(response, max_resp_bytes);
            };
            let loc_str = loc.to_str().map_err(|e| e.to_string())?;
            let next_raw =
                security::resolve_redirect_location(&validated.url, &validated.origin, loc_str)?;
            let next_val = security::validate_public_url(&next_raw, allow_http)?;
            if validated.scheme == "https" && next_val.scheme == "http" {
                return Err("HTTPS to HTTP downgrade redirect blocked in safe HTTP mode".into());
            }
            if !allow_cross_origin && next_val.origin != initial_origin {
                return Err("cross-origin redirect blocked in safe HTTP mode".into());
            }
            if (301..=303).contains(&response.status().as_u16())
                && current_method != reqwest::Method::GET
                && current_method != reqwest::Method::HEAD
            {
                current_method = reqwest::Method::GET;
                current_body = None;
            }
            current_url = next_val.url;
            continue;
        }
        return response_to_http_val(response, max_resp_bytes);
    }
    Err("too many redirects".into())
}

impl Vm {
    pub(crate) fn call_builtin_sys_net_conc_ffi(
        &mut self,
        n: &str,
        a: Vec<Val>,
    ) -> Result<Option<Val>, String> {
        let v = match n {
            "sha256" => {
                if a.len() != 1 {
                    return Err("sha256 expects value".into());
                }
                let mut h = Sha256::new();
                h.update(a[0].show().as_bytes());
                Val::Str(format!("{:x}", h.finalize()))
            }
            "hmac_sha256" => {
                if a.len() != 2 {
                    return Err("hmac_sha256 expects key,message".into());
                }
                let key = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("key must be String".into()),
                };
                let message = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("message must be String".into()),
                };
                Val::Str(hmac_sha256_hex(key, message))
            }
            "pbkdf2_sha256" => {
                if a.len() != 4 {
                    return Err("pbkdf2_sha256 expects password,salt,iterations,bytes".into());
                }
                let password = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("password must be String".into()),
                };
                let salt = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("salt must be String".into()),
                };
                let iterations =
                    checked_finite_range(&a[2], "iterations", 1.0, 5_000_000.0)? as u32;
                let bytes = checked_finite_range(&a[3], "bytes", 1.0, 4096.0)? as usize;
                Val::Str(pbkdf2_sha256_hex(password, salt, iterations, bytes))
            }
            "constant_time_equal" => {
                if a.len() != 2 {
                    return Err("constant_time_equal expects two strings".into());
                }
                let left = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("left must be String".into()),
                };
                let right = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("right must be String".into()),
                };
                Val::Bool(constant_time_strings_equal(left, right))
            }
            "random_bytes_hex" => {
                let n_bytes = match a.as_slice() {
                    [] => 32usize,
                    [v] => checked_finite_range(v, "random_bytes_hex count", 1.0, 4096.0)? as usize,
                    _ => return Err("random_bytes_hex expects optional byte count Number".into()),
                };
                Val::Str(security::random_bytes_hex(n_bytes)?)
            }
            "random_token" => {
                let n_bytes = match a.as_slice() {
                    [] => 32usize,
                    [v] => checked_finite_range(v, "random_token count", 1.0, 4096.0)? as usize,
                    _ => return Err("random_token expects optional byte count Number".into()),
                };
                Val::Str(security::random_token_urlsafe(n_bytes)?)
            }
            "html_escape" => {
                if a.len() != 1 {
                    return Err("html_escape expects value".into());
                }
                Val::Str(security::html_escape(&a[0].show()))
            }
            "base32_encode" => {
                if a.len() != 1 {
                    return Err("base32_encode expects String".into());
                }
                let s = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("base32_encode expects String".into()),
                };
                Val::Str(security::base32_encode(s.as_bytes()))
            }
            "base32_decode" => {
                if a.len() != 1 {
                    return Err("base32_decode expects Base32 String".into());
                }
                let s = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("base32_decode expects Base32 String".into()),
                };
                let raw = security::base32_decode(s)?;
                Val::Str(String::from_utf8(raw).map_err(|e| e.to_string())?)
            }
            "totp_secret" => {
                if !a.is_empty() {
                    return Err("totp_secret takes no arguments".into());
                }
                Val::Str(security::generate_totp_secret())
            }
            "totp_code" => {
                if a.is_empty() || a.len() > 2 {
                    return Err("totp_code expects (secret[, time_secs])".into());
                }
                let secret = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("totp_code secret must be String".into()),
                };
                let code = match a.get(1) {
                    Some(Val::Num(ts)) => {
                        security::totp_code_at(secret, (*ts).max(0.0) as u64, 6, 30)?
                    }
                    Some(Val::Null) | None => security::totp_code_now(secret)?,
                    _ => return Err("totp_code time_secs must be Number".into()),
                };
                Val::Str(code)
            }
            "totp_verify" => {
                if a.len() < 2 || a.len() > 4 {
                    return Err("totp_verify expects (secret, code[, window[, time_secs]])".into());
                }
                let secret = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("totp_verify secret must be String".into()),
                };
                let code = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("totp_verify code must be String".into()),
                };
                let window = match a.get(2) {
                    Some(Val::Num(w)) => (*w).max(0.0) as u32,
                    Some(Val::Null) | None => 1,
                    _ => return Err("totp_verify window must be Number".into()),
                };
                let ok = match a.get(3) {
                    Some(Val::Num(ts)) => {
                        security::verify_totp_at(secret, code, (*ts).max(0.0) as u64, window)
                    }
                    Some(Val::Null) | None => security::verify_totp_now(secret, code, window),
                    _ => return Err("totp_verify time_secs must be Number".into()),
                };
                Val::Bool(ok)
            }
            "aes_gcm_encrypt" => {
                let (key, plaintext, aad) = parse_aead_args("aes_gcm_encrypt", "plaintext", &a)?;
                Val::Str(security::aes_gcm_encrypt_token(key, plaintext, aad)?)
            }
            "aes_gcm_decrypt" => {
                let (key, token, aad) = parse_aead_args("aes_gcm_decrypt", "ciphertext", &a)?;
                Val::Str(security::aes_gcm_decrypt_token(key, token, aad)?)
            }
            "chacha20_poly1305_encrypt" => {
                let (key, plaintext, aad) =
                    parse_aead_args("chacha20_poly1305_encrypt", "plaintext", &a)?;
                Val::Str(security::chacha20_poly1305_encrypt_token(
                    key, plaintext, aad,
                )?)
            }
            "chacha20_poly1305_decrypt" => {
                let (key, token, aad) =
                    parse_aead_args("chacha20_poly1305_decrypt", "ciphertext", &a)?;
                Val::Str(security::chacha20_poly1305_decrypt_token(key, token, aad)?)
            }
            "hkdf_sha256" => {
                if !(2..=4).contains(&a.len()) {
                    return Err("hkdf_sha256 expects (ikm, salt[, info[, bytes]])".into());
                }
                let ikm = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("hkdf_sha256 ikm must be String".into()),
                };
                let salt = match &a[1] {
                    Val::Str(s) => s,
                    Val::Null => "",
                    _ => return Err("hkdf_sha256 salt must be String or Null".into()),
                };
                let info = match a.get(2) {
                    Some(Val::Str(s)) => s.as_str(),
                    Some(Val::Null) | None => "",
                    _ => return Err("hkdf_sha256 info must be String".into()),
                };
                let bytes = match a.get(3) {
                    Some(v) if !matches!(v, Val::Null) => {
                        checked_finite_range(v, "bytes", 1.0, 8160.0)? as usize
                    }
                    _ => 32usize,
                };
                Val::Str(security::hkdf_sha256_hex(ikm, salt, info, bytes)?)
            }
            "sha3_256" => {
                if a.len() != 1 {
                    return Err("sha3_256 expects 1 String or byte List argument".into());
                }
                let data = val_to_raw_bytes(&a[0], "sha3_256", "data")?;
                Val::Str(security::bytes_to_hex(&pq_crypto::sha3_256(&data)))
            }
            "sha3_512" => {
                if a.len() != 1 {
                    return Err("sha3_512 expects 1 String or byte List argument".into());
                }
                let data = val_to_raw_bytes(&a[0], "sha3_512", "data")?;
                Val::Str(security::bytes_to_hex(&pq_crypto::sha3_512(&data)))
            }
            "shake128" | "shake256" => {
                if !(1..=2).contains(&a.len()) {
                    return Err(format!("{n} expects (data[, bytes])"));
                }
                let data = val_to_raw_bytes(&a[0], n, "data")?;
                let default_bytes = if n == "shake128" { 32 } else { 64 };
                let out_len = match a.get(1) {
                    Some(v) if !matches!(v, Val::Null) => checked_usize_arg(v, "bytes", 1, 65_536)?,
                    _ => default_bytes,
                };
                let out = if n == "shake128" {
                    pq_crypto::shake128(&data, out_len)
                } else {
                    pq_crypto::shake256(&data, out_len)
                };
                Val::Str(security::bytes_to_hex(&out))
            }
            "blake2b" => {
                if !(1..=3).contains(&a.len()) {
                    return Err("blake2b expects (data[, bytes[, key]])".into());
                }
                let data = val_to_raw_bytes(&a[0], "blake2b", "data")?;
                let out_len = match a.get(1) {
                    Some(v) if !matches!(v, Val::Null) => checked_usize_arg(v, "bytes", 1, 64)?,
                    _ => 64usize,
                };
                let mut key = match a.get(2) {
                    Some(v) if !matches!(v, Val::Null) => val_to_raw_bytes(v, "blake2b", "key")?,
                    _ => Vec::new(),
                };
                let res = pq_crypto::blake2b(&data, &key, out_len);
                security::zeroize_bytes(&mut key);
                Val::Str(security::bytes_to_hex(&res?))
            }
            "kmac256" => {
                if !(2..=4).contains(&a.len()) {
                    return Err("kmac256 expects (key, data[, custom[, bytes]])".into());
                }
                let mut key = val_to_raw_bytes(&a[0], "kmac256", "key")?;
                let data = val_to_raw_bytes(&a[1], "kmac256", "data")?;
                let custom = match a.get(2) {
                    Some(v) if !matches!(v, Val::Null) => val_to_raw_bytes(v, "kmac256", "custom")?,
                    _ => Vec::new(),
                };
                let out_len = match a.get(3) {
                    Some(v) if !matches!(v, Val::Null) => checked_usize_arg(v, "bytes", 1, 65_536)?,
                    _ => 64usize,
                };
                let out = pq_crypto::kmac256(&key, &custom, &data, out_len);
                security::zeroize_bytes(&mut key);
                Val::Str(security::bytes_to_hex(&out))
            }
            "argon2id" => {
                if !(2..=6).contains(&a.len()) {
                    return Err(
                        "argon2id expects (password, salt[, mem_kib[, iterations[, parallelism[, bytes]]]])"
                            .into(),
                    );
                }
                let mut password = val_to_raw_bytes(&a[0], "argon2id", "password")?;
                let salt = val_to_raw_bytes(&a[1], "argon2id", "salt")?;
                let mem_kib = match a.get(2) {
                    Some(v) if !matches!(v, Val::Null) => {
                        checked_usize_arg(v, "mem_kib", 8, 4_194_304)? as u32
                    }
                    _ => 65_536,
                };
                let iterations = match a.get(3) {
                    Some(v) if !matches!(v, Val::Null) => {
                        checked_usize_arg(v, "iterations", 1, 10_000)? as u32
                    }
                    _ => 3,
                };
                let parallelism = match a.get(4) {
                    Some(v) if !matches!(v, Val::Null) => {
                        checked_usize_arg(v, "parallelism", 1, 64)? as u32
                    }
                    _ => 1,
                };
                let out_len = match a.get(5) {
                    Some(v) if !matches!(v, Val::Null) => checked_usize_arg(v, "bytes", 4, 1024)?,
                    _ => 32,
                };
                let res = pq_crypto::argon2id(
                    &password,
                    &salt,
                    mem_kib,
                    iterations,
                    parallelism,
                    out_len,
                );
                security::zeroize_bytes(&mut password);
                let mut derived = res?;
                let hex = security::bytes_to_hex(&derived);
                security::zeroize_bytes(&mut derived);
                Val::Str(hex)
            }
            "x25519_keygen" => {
                if !a.is_empty() {
                    return Err("x25519_keygen takes no arguments".into());
                }
                let mut sk = [0u8; 32];
                rand::rngs::OsRng.fill(&mut sk);
                sk[0] &= 248;
                sk[31] &= 127;
                sk[31] |= 64;
                let pk = pq_crypto::x25519_public(&sk);
                let sk_hex = security::bytes_to_hex(&sk);
                security::zeroize_bytes(&mut sk);
                Val::Map(vec![
                    (Val::Str("algorithm".into()), Val::Str("X25519".into())),
                    (Val::Str("secret_hex".into()), Val::Str(sk_hex)),
                    (
                        Val::Str("public_hex".into()),
                        Val::Str(security::bytes_to_hex(&pk)),
                    ),
                ])
            }
            "x25519_shared" => {
                if a.len() != 2 {
                    return Err("x25519_shared expects (secret_hex, public_hex)".into());
                }
                let sk_hex = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("x25519_shared secret_hex must be String".into()),
                };
                let pk_hex = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("x25519_shared public_hex must be String".into()),
                };
                let mut sk_vec = security::hex_to_bytes(sk_hex)?;
                let pk_vec = security::hex_to_bytes(pk_hex)?;
                if sk_vec.len() != 32 || pk_vec.len() != 32 {
                    security::zeroize_bytes(&mut sk_vec);
                    return Err("x25519_shared expects two 32-byte hex strings".into());
                }
                let mut sk_arr = [0u8; 32];
                let mut pk_arr = [0u8; 32];
                sk_arr.copy_from_slice(&sk_vec);
                pk_arr.copy_from_slice(&pk_vec);
                security::zeroize_bytes(&mut sk_vec);
                let res = pq_crypto::x25519_shared_checked(&sk_arr, &pk_arr);
                security::zeroize_bytes(&mut sk_arr);
                let mut ss = res?;
                let hex = security::bytes_to_hex(&ss);
                security::zeroize_bytes(&mut ss);
                Val::Str(hex)
            }
            "ml_kem_1024_keygen" => {
                if !a.is_empty() {
                    return Err("ml_kem_1024_keygen takes no arguments".into());
                }
                let (ek, mut dk) = pq_crypto::mlkem1024_keygen();
                let dk_hex = security::bytes_to_hex(&dk);
                security::zeroize_bytes(&mut dk);
                Val::Map(vec![
                    (Val::Str("algorithm".into()), Val::Str("ML-KEM-1024".into())),
                    (Val::Str("security_bits".into()), Val::Num(256.0)),
                    (
                        Val::Str("encaps_key_hex".into()),
                        Val::Str(security::bytes_to_hex(&ek)),
                    ),
                    (Val::Str("decaps_key_hex".into()), Val::Str(dk_hex)),
                ])
            }
            "ml_kem_1024_encaps" => {
                if a.len() != 1 {
                    return Err("ml_kem_1024_encaps expects (encaps_key_hex)".into());
                }
                let ek_hex = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("ml_kem_1024_encaps encaps_key_hex must be String".into()),
                };
                let ek = security::hex_to_bytes(ek_hex)?;
                let (ct, mut ss) = pq_crypto::mlkem1024_encaps(&ek)?;
                let ss_hex = security::bytes_to_hex(&ss);
                security::zeroize_bytes(&mut ss);
                Val::Map(vec![
                    (
                        Val::Str("ciphertext_hex".into()),
                        Val::Str(security::bytes_to_hex(&ct)),
                    ),
                    (Val::Str("shared_secret_hex".into()), Val::Str(ss_hex)),
                ])
            }
            "ml_kem_1024_decaps" => {
                if a.len() != 2 {
                    return Err(
                        "ml_kem_1024_decaps expects (decaps_key_hex, ciphertext_hex)".into(),
                    );
                }
                let dk_hex = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("ml_kem_1024_decaps decaps_key_hex must be String".into()),
                };
                let ct_hex = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("ml_kem_1024_decaps ciphertext_hex must be String".into()),
                };
                let mut dk = security::hex_to_bytes(dk_hex)?;
                let ct = security::hex_to_bytes(ct_hex)?;
                let res = pq_crypto::mlkem1024_decaps(&dk, &ct);
                security::zeroize_bytes(&mut dk);
                let mut ss = res?;
                let ss_hex = security::bytes_to_hex(&ss);
                security::zeroize_bytes(&mut ss);
                Val::Str(ss_hex)
            }
            "pq_hybrid_keygen" => {
                if !a.is_empty() {
                    return Err("pq_hybrid_keygen takes no arguments".into());
                }
                let (pk, sk) = pq_crypto::pq_hybrid_keygen();
                Val::Map(vec![
                    (
                        Val::Str("kem".into()),
                        Val::Str("ML-KEM-1024+X25519".into()),
                    ),
                    (Val::Str("public_key".into()), Val::Str(pk)),
                    (Val::Str("secret_key".into()), Val::Str(sk)),
                ])
            }
            "vault_seal_file" => {
                crate::runtime::require_cap("fs.read")?;
                crate::runtime::require_cap("fs.write")?;
                if a.len() != 3 {
                    return Err("vault_seal_file expects (src_path, dst_path, opts_map)".into());
                }
                let src = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("vault_seal_file src_path must be String".into()),
                };
                let dst = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("vault_seal_file dst_path must be String".into()),
                };
                let opts_pairs = match &a[2] {
                    Val::Map(p) => p,
                    _ => return Err("vault_seal_file opts must be Map".into()),
                };
                let cipher = match map_opt_str(opts_pairs, &["cipher"])? {
                    Some(c) => vault_stream::CipherSuite::from_str(&c)?,
                    None => vault_stream::CipherSuite::Mystique1024,
                };
                let opts = vault_stream::VaultSealOptions {
                    cipher,
                    opaque_obscure: map_opt_bool(
                        opts_pairs,
                        &["obscure", "opaque_obscure"],
                        false,
                    )?,
                    passphrase: map_opt_str(opts_pairs, &["passphrase"])?,
                    recipient_pub: map_opt_str(opts_pairs, &["recipient_pub", "pubkey"])?,
                    mem_kib: map_opt_u32(
                        opts_pairs,
                        &["mem_kib", "argon2id_mem_kib"],
                        65_536,
                        8,
                        4_194_304,
                    )?,
                    iterations: map_opt_u32(opts_pairs, &["iterations", "iters"], 3, 1, 10_000)?,
                    lanes: map_opt_u32(opts_pairs, &["lanes", "parallelism"], 1, 1, 64)?,
                    ratchet_every: map_opt_u32(
                        opts_pairs,
                        &["ratchet_every", "ratchet"],
                        16,
                        1,
                        65_536,
                    )?,
                    pad_bucket: map_opt_u32(
                        opts_pairs,
                        &["pad_bucket", "pad"],
                        4096,
                        0,
                        1_048_576,
                    )?,
                };
                let res = vault_stream::vault_seal_file(Path::new(src), Path::new(dst), &opts)?;
                Val::Map(vec![
                    (Val::Str("method".into()), Val::Str(res.method)),
                    (
                        Val::Str("plaintext_bytes".into()),
                        Val::Num(res.plaintext_bytes as f64),
                    ),
                    (
                        Val::Str("padded_bytes".into()),
                        Val::Num(res.padded_bytes as f64),
                    ),
                    (
                        Val::Str("chunks_written".into()),
                        Val::Num(res.chunks_written as f64),
                    ),
                    (
                        Val::Str("key_commitment_prefix".into()),
                        Val::Str(res.key_commitment_prefix),
                    ),
                    (Val::Str("opaque".into()), Val::Bool(res.opaque)),
                ])
            }
            "vault_unseal_file" => {
                crate::runtime::require_cap("fs.read")?;
                crate::runtime::require_cap("fs.write")?;
                if a.len() != 3 {
                    return Err(
                        "vault_unseal_file expects (vault_path, out_path, creds_map)".into(),
                    );
                }
                let vault = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("vault_unseal_file vault_path must be String".into()),
                };
                let out = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("vault_unseal_file out_path must be String".into()),
                };
                let cred_pairs = match &a[2] {
                    Val::Map(p) => p,
                    _ => return Err("vault_unseal_file creds must be Map".into()),
                };
                let creds = vault_stream::VaultOpenCreds {
                    passphrase: map_opt_str(cred_pairs, &["passphrase"])?,
                    secret_key: map_opt_str(cred_pairs, &["secret_key", "seckey"])?,
                };
                let res =
                    vault_stream::vault_unseal_file(Path::new(vault), Path::new(out), &creds)?;
                Val::Map(vec![
                    (Val::Str("method".into()), Val::Str(res.method)),
                    (
                        Val::Str("original_filename".into()),
                        Val::Str(res.original_filename),
                    ),
                    (
                        Val::Str("recovered_bytes".into()),
                        Val::Num(res.recovered_bytes as f64),
                    ),
                    (Val::Str("sha3_512".into()), Val::Str(res.sha3_512)),
                    (
                        Val::Str("chunks_verified".into()),
                        Val::Num(res.chunks_verified as f64),
                    ),
                ])
            }
            "vault_inspect" => {
                crate::runtime::require_cap("fs.read")?;
                if a.len() != 1 {
                    return Err("vault_inspect expects (vault_path)".into());
                }
                let vault = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("vault_inspect vault_path must be String".into()),
                };
                let info = vault_stream::vault_inspect(Path::new(vault))?;
                Val::Map(vec![
                    (Val::Str("format".into()), Val::Str(info.format)),
                    (Val::Str("opaque".into()), Val::Bool(info.opaque)),
                    (
                        Val::Str("cipher".into()),
                        info.cipher.map(Val::Str).unwrap_or(Val::Null),
                    ),
                    (
                        Val::Str("unlock_mode".into()),
                        info.unlock_mode.map(Val::Str).unwrap_or(Val::Null),
                    ),
                    (
                        Val::Str("argon2id_mem_kib".into()),
                        info.argon2id_mem_kib
                            .map(|n| Val::Num(f64::from(n)))
                            .unwrap_or(Val::Null),
                    ),
                    (
                        Val::Str("argon2id_iterations".into()),
                        info.argon2id_iterations
                            .map(|n| Val::Num(f64::from(n)))
                            .unwrap_or(Val::Null),
                    ),
                    (
                        Val::Str("ratchet_every".into()),
                        info.ratchet_every
                            .map(|n| Val::Num(f64::from(n)))
                            .unwrap_or(Val::Null),
                    ),
                    (
                        Val::Str("key_commitment_prefix".into()),
                        info.key_commitment_prefix
                            .map(Val::Str)
                            .unwrap_or(Val::Null),
                    ),
                    (
                        Val::Str("has_plaintext_leak".into()),
                        Val::Bool(info.has_plaintext_leak),
                    ),
                ])
            }
            "is_private_ip" => {
                if a.len() != 1 {
                    return Err("is_private_ip expects IP String".into());
                }
                let ip = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("is_private_ip expects String".into()),
                };
                Val::Bool(security::is_private_ip_str(ip))
            }
            "url_validate_public" => {
                if a.is_empty() || a.len() > 2 {
                    return Err("url_validate_public expects (url[, allow_http])".into());
                }
                let url = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("url must be String".into()),
                };
                let allow_http = a.get(1).is_none_or(Val::truthy);
                match security::validate_public_url(url, allow_http) {
                    Ok(v) => Val::Map(vec![
                        (Val::Str("ok".into()), Val::Bool(true)),
                        (Val::Str("scheme".into()), Val::Str(v.scheme)),
                        (Val::Str("host".into()), Val::Str(v.host)),
                        (Val::Str("port".into()), Val::Num(f64::from(v.port))),
                        (Val::Str("origin".into()), Val::Str(v.origin)),
                        (Val::Str("url".into()), Val::Str(v.url)),
                    ]),
                    Err(e) => Val::Map(vec![
                        (Val::Str("ok".into()), Val::Bool(false)),
                        (Val::Str("error".into()), Val::Str(e)),
                    ]),
                }
            }
            "url_resolve_public" => {
                crate::runtime::require_cap("net")?;
                if a.is_empty() || a.len() > 2 {
                    return Err("url_resolve_public expects (url[, allow_http])".into());
                }
                let url = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("url must be String".into()),
                };
                let allow_http = a.get(1).is_none_or(Val::truthy);
                match security::validate_public_url(url, allow_http)
                    .and_then(|v| Ok((v.clone(), security::resolve_public_url_addrs(&v)?)))
                {
                    Ok((v, addrs)) => Val::Map(vec![
                        (Val::Str("ok".into()), Val::Bool(true)),
                        (Val::Str("origin".into()), Val::Str(v.origin)),
                        (Val::Str("host".into()), Val::Str(v.host)),
                        (Val::Str("port".into()), Val::Num(f64::from(v.port))),
                        (
                            Val::Str("ips".into()),
                            Val::List(
                                addrs
                                    .into_iter()
                                    .map(|sa| Val::Str(sa.ip().to_string()))
                                    .collect(),
                            ),
                        ),
                    ]),
                    Err(e) => Val::Map(vec![
                        (Val::Str("ok".into()), Val::Bool(false)),
                        (Val::Str("error".into()), Val::Str(e)),
                    ]),
                }
            }
            "shell" => {
                crate::runtime::require_cap("process")?;
                if a.len() != 1 {
                    return Err("shell expects command".into());
                }
                let cmd = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("command must be String".into()),
                };
                let out = if cfg!(target_os = "windows") {
                    Command::new("cmd").args(["/C", cmd]).output()
                } else {
                    Command::new("sh").args(["-c", cmd]).output()
                }
                .map_err(|e| e.to_string())?;
                Val::Map(vec![
                    (
                        Val::Str("code".into()),
                        Val::Num(out.status.code().unwrap_or(-1) as f64),
                    ),
                    (
                        Val::Str("out".into()),
                        Val::Str(String::from_utf8_lossy(&out.stdout).to_string()),
                    ),
                    (
                        Val::Str("err".into()),
                        Val::Str(String::from_utf8_lossy(&out.stderr).to_string()),
                    ),
                ])
            }
            "powershell" | "ps_exec" => {
                crate::runtime::require_cap("process")?;
                if a.len() != 1 {
                    return Err(format!("{n} expects command"));
                }
                let Val::Str(cmd) = &a[0] else {
                    return Err("command must be String".into());
                };
                crate::term_ui::builtin_shell_val(crate::term_ui::ShellKind::PowerShell, cmd)?
            }
            "bash_exec" => {
                crate::runtime::require_cap("process")?;
                if a.len() != 1 {
                    return Err("bash_exec expects command".into());
                }
                let Val::Str(cmd) = &a[0] else {
                    return Err("command must be String".into());
                };
                crate::term_ui::builtin_shell_val(crate::term_ui::ShellKind::GitBash, cmd)?
            }
            #[cfg(feature = "native-services")]
            "http_request" => {
                crate::runtime::require_cap("net")?;
                if a.len() != 5 {
                    return Err("http_request expects method,url,headers,body,timeout_ms".into());
                }
                let method_text = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("method must be String".into()),
                };
                let url = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("url must be String".into()),
                };
                let headers = match &a[2] {
                    Val::Map(p) => p,
                    _ => return Err("headers must be Map".into()),
                };
                let timeout = checked_finite_range(&a[4], "timeout_ms", 1.0, 300_000.0)? as u64;
                let response =
                    execute_general_http_response(method_text, url, headers, &a[3], timeout)?;
                response_to_http_val(response, DEFAULT_HTTP_MAX_BYTES)?
            }
            #[cfg(feature = "native-services")]
            "http_request_safe" => {
                crate::runtime::require_cap("net")?;
                if a.len() != 5 && a.len() != 6 {
                    return Err(
                        "http_request_safe expects method,url,headers,body,timeout_ms[,opts]"
                            .into(),
                    );
                }
                let method_text = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("method must be String".into()),
                };
                let url = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("url must be String".into()),
                };
                let headers = match &a[2] {
                    Val::Map(p) => p,
                    _ => return Err("headers must be Map".into()),
                };
                let timeout = checked_finite_range(&a[4], "timeout_ms", 1.0, 300_000.0)? as u64;
                let opts = match a.get(5) {
                    Some(Val::Map(m)) => Some(m),
                    Some(Val::Null) | None => None,
                    _ => return Err("opts must be Map".into()),
                };
                execute_safe_http(method_text, url, headers, &a[3], timeout, opts)?
            }
            #[cfg(feature = "native-services")]
            "http_stream" => {
                crate::runtime::require_cap("net")?;
                if a.len() != 6 {
                    return Err(
                        "http_stream expects (method, url, headers_map, body_or_null, timeout_ms, on_line_fn)"
                            .into(),
                    );
                }
                let method_text = match &a[0] {
                    Val::Str(s) => s.to_uppercase(),
                    _ => return Err("http_stream method must be String".into()),
                };
                let url = match &a[1] {
                    Val::Str(s) => s.clone(),
                    _ => return Err("http_stream url must be String".into()),
                };
                let headers = match &a[2] {
                    Val::Map(items) => items.clone(),
                    _ => return Err("http_stream headers must be Map".into()),
                };
                let timeout =
                    checked_finite_range(&a[4], "http_stream timeout_ms", 1.0, 300_000.0)? as u64;
                let on_line = a[5].clone();
                if !self.is_callable_val(&on_line) {
                    return Err("http_stream on_line_fn must be callable".into());
                }
                let response =
                    execute_general_http_response(&method_text, &url, &headers, &a[3], timeout)?;
                let status = response.status();
                let mut line_count = 0usize;
                for line_res in std::io::BufRead::lines(std::io::BufReader::new(
                    std::io::Read::take(response, DEFAULT_HTTP_MAX_BYTES as u64),
                )) {
                    let line = line_res.map_err(|e| e.to_string())?;
                    line_count += 1;
                    let keep_going = self.invoke_callable_sync(&on_line, vec![Val::Str(line)])?;
                    if matches!(keep_going, Val::Bool(false)) {
                        break;
                    }
                }
                Val::Map(vec![
                    (Val::Str("status".into()), Val::Num(status.as_u16() as f64)),
                    (Val::Str("ok".into()), Val::Bool(status.is_success())),
                    (Val::Str("lines".into()), Val::Num(line_count as f64)),
                ])
            }
            #[cfg(feature = "native-services")]
            "http_get" => {
                crate::runtime::require_cap("net")?;
                if a.len() != 1 {
                    return Err("http_get expects url".into());
                }
                let url = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("url must be String".into()),
                };
                let response = execute_general_http_response(
                    "GET",
                    url,
                    &[],
                    &Val::Null,
                    DEFAULT_HTTP_TIMEOUT_MS,
                )?;
                let bytes =
                    security::read_to_end_limited(response, DEFAULT_HTTP_MAX_BYTES, "http_get")?;
                Val::Str(String::from_utf8_lossy(&bytes).into_owned())
            }
            #[cfg(feature = "native-services")]
            "http_post" => {
                crate::runtime::require_cap("net")?;
                if a.len() != 2 {
                    return Err("http_post expects url,body".into());
                }
                let url = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("url must be String".into()),
                };
                let response = execute_general_http_response(
                    "POST",
                    url,
                    &[],
                    &a[1],
                    DEFAULT_HTTP_TIMEOUT_MS,
                )?;
                let bytes =
                    security::read_to_end_limited(response, DEFAULT_HTTP_MAX_BYTES, "http_post")?;
                Val::Str(String::from_utf8_lossy(&bytes).into_owned())
            }
            "sleep_ms" => {
                if a.len() != 1 {
                    return Err("sleep_ms expects milliseconds".into());
                }
                let ms = checked_finite_range(&a[0], "milliseconds", 0.0, 300_000.0)? as u64;
                thread::sleep(std::time::Duration::from_millis(ms));
                Val::Null
            }
            "cpu_count" => Val::Num(
                thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1) as f64,
            ),
            "platform_os" => Val::Str(env::consts::OS.to_string()),
            "platform_arch" => Val::Str(env::consts::ARCH.to_string()),
            "platform_family" => Val::Str(env::consts::FAMILY.to_string()),
            "path_separator" => Val::Str(std::path::MAIN_SEPARATOR.to_string()),
            #[cfg(feature = "native-services")]
            "sqlite_exec" => {
                crate::runtime::require_cap("fs.write")?;
                if a.len() != 2 {
                    return Err("sqlite_exec expects path,sql".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("path must be String".into()),
                };
                let sql = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("sql must be String".into()),
                };
                let conn = open_sqlite_conn(path)?;
                let n = conn.execute(sql, []).map_err(|e| e.to_string())?;
                Val::Num(n as f64)
            }
            #[cfg(feature = "native-services")]
            "sqlite_query" => {
                crate::runtime::require_cap("fs.read")?;
                if a.len() != 2 {
                    return Err("sqlite_query expects path,sql".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("path must be String".into()),
                };
                let sql = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("sql must be String".into()),
                };
                let conn = open_sqlite_conn(path)?;
                Val::List(collect_sqlite_rows(&conn, sql, &[])?)
            }
            #[cfg(feature = "native-services")]
            "sqlite_exec_params" => {
                crate::runtime::require_cap("fs.write")?;
                if a.len() != 3 {
                    return Err("sqlite_exec_params expects path,sql,params".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("path must be String".into()),
                };
                let sql = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("sql must be String".into()),
                };
                let params = match &a[2] {
                    Val::List(v) => v,
                    _ => return Err("params must be List".into()),
                };
                let values: Vec<rusqlite::types::Value> =
                    params.iter().map(val_to_sql_value).collect();
                let conn = open_sqlite_conn(path)?;
                let n = conn
                    .execute(sql, rusqlite::params_from_iter(values.iter()))
                    .map_err(|e| e.to_string())?;
                Val::Num(n as f64)
            }
            #[cfg(feature = "native-services")]
            "sqlite_query_params" => {
                crate::runtime::require_cap("fs.read")?;
                if a.len() != 3 {
                    return Err("sqlite_query_params expects path,sql,params".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("path must be String".into()),
                };
                let sql = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("sql must be String".into()),
                };
                let params = match &a[2] {
                    Val::List(v) => v,
                    _ => return Err("params must be List".into()),
                };
                let values: Vec<rusqlite::types::Value> =
                    params.iter().map(val_to_sql_value).collect();
                let conn = open_sqlite_conn(path)?;
                Val::List(collect_sqlite_rows(&conn, sql, &values)?)
            }
            #[cfg(feature = "native-services")]
            "sqlite_init_wal" => {
                crate::runtime::require_cap("fs.write")?;
                if a.len() != 1 {
                    return Err("sqlite_init_wal expects path".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("path must be String".into()),
                };
                if let Some(parent) = Path::new(path).parent()
                    && !parent.as_os_str().is_empty()
                {
                    let _ = fs::create_dir_all(parent);
                }
                let conn = open_sqlite_conn(path)?;
                let journal_mode: String = conn
                    .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
                    .map_err(|e| e.to_string())?;
                conn.execute_batch("PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;")
                    .map_err(|e| e.to_string())?;
                Val::Map(vec![
                    (Val::Str("ok".into()), Val::Bool(true)),
                    (Val::Str("journal_mode".into()), Val::Str(journal_mode)),
                    (Val::Str("foreign_keys".into()), Val::Bool(true)),
                    (
                        Val::Str("busy_timeout_ms".into()),
                        Val::Num(SQLITE_BUSY_TIMEOUT_MS as f64),
                    ),
                ])
            }
            #[cfg(feature = "native-services")]
            "sqlite_tx" => {
                crate::runtime::require_cap("fs.write")?;
                if a.len() != 2 {
                    return Err("sqlite_tx expects (path, statements)".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("path must be String".into()),
                };
                let Val::List(items) = &a[1] else {
                    return Err("sqlite_tx statements must be List".into());
                };
                let parsed: Vec<(String, Vec<rusqlite::types::Value>)> = items
                    .iter()
                    .map(parse_sqlite_tx_item)
                    .collect::<Result<_, _>>()?;
                let conn = open_sqlite_conn(path)?;
                conn.execute_batch("BEGIN IMMEDIATE;")
                    .map_err(|e| e.to_string())?;
                let mut total_changes = 0usize;
                for (sql, values) in &parsed {
                    match conn.execute(sql, rusqlite::params_from_iter(values.iter())) {
                        Ok(n) => total_changes += n,
                        Err(e) => {
                            let _ = conn.execute_batch("ROLLBACK;");
                            return Err(format!("sqlite_tx rolled back: {e}"));
                        }
                    }
                }
                if let Err(e) = conn.execute_batch("COMMIT;") {
                    let _ = conn.execute_batch("ROLLBACK;");
                    return Err(format!("sqlite_tx commit failed: {e}"));
                }
                Val::Map(vec![
                    (Val::Str("ok".into()), Val::Bool(true)),
                    (Val::Str("changes".into()), Val::Num(total_changes as f64)),
                    (Val::Str("statements".into()), Val::Num(parsed.len() as f64)),
                ])
            }
            #[cfg(feature = "native-services")]
            "sqlite_backup" => {
                crate::runtime::require_cap("fs.read")?;
                crate::runtime::require_cap("fs.write")?;
                if a.len() != 2 {
                    return Err("sqlite_backup expects (src_path, dst_path)".into());
                }
                let src_path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("src_path must be String".into()),
                };
                let dst_path = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("dst_path must be String".into()),
                };
                if src_path == dst_path {
                    return Err("sqlite_backup src_path and dst_path must differ".into());
                }
                if !Path::new(src_path).is_file() {
                    return Err(format!("sqlite_backup source '{src_path}' not found"));
                }
                if let Some(parent) = Path::new(dst_path).parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                let dst = PathBuf::from(dst_path);
                let tmp_dst = PathBuf::from(format!("{dst_path}.tmp"));
                let _ = fs::remove_file(&tmp_dst);
                let src = open_sqlite_conn(src_path)?;
                let _ = src.execute_batch("PRAGMA wal_checkpoint(FULL);");
                let tmp_str = tmp_dst.to_string_lossy().to_string();
                src.execute("VACUUM INTO ?1", rusqlite::params![tmp_str])
                    .map_err(|e| {
                        let _ = fs::remove_file(&tmp_dst);
                        e.to_string()
                    })?;
                drop(src);
                let verify_conn = Connection::open_with_flags(
                    &tmp_dst,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .map_err(|e| {
                    let _ = fs::remove_file(&tmp_dst);
                    e.to_string()
                })?;
                let integrity: String = verify_conn
                    .pragma_query_value(None, "integrity_check", |row| row.get(0))
                    .map_err(|e| {
                        let _ = fs::remove_file(&tmp_dst);
                        e.to_string()
                    })?;
                drop(verify_conn);
                let ok = integrity.eq_ignore_ascii_case("ok");
                if !ok {
                    let _ = fs::remove_file(&tmp_dst);
                    return Err(format!("sqlite_backup integrity check failed: {integrity}"));
                }
                if dst.exists() {
                    let _ = fs::remove_file(&dst);
                }
                fs::rename(&tmp_dst, &dst).map_err(|e| {
                    let _ = fs::remove_file(&tmp_dst);
                    e.to_string()
                })?;
                Val::Map(vec![
                    (Val::Str("ok".into()), Val::Bool(true)),
                    (Val::Str("source".into()), Val::Str(src_path.clone())),
                    (Val::Str("backup".into()), Val::Str(dst_path.clone())),
                    (Val::Str("integrity".into()), Val::Str(integrity)),
                ])
            }
            #[cfg(feature = "native-services")]
            "sqlite_verify" => {
                crate::runtime::require_cap("fs.read")?;
                if a.len() != 1 {
                    return Err("sqlite_verify expects path".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("path must be String".into()),
                };
                if !Path::new(path).is_file() {
                    return Err(format!("sqlite_verify file '{path}' not found"));
                }
                let conn = Connection::open_with_flags(
                    path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .map_err(|e| e.to_string())?;
                conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
                    .map_err(|e| e.to_string())?;
                let mut ic_stmt = conn
                    .prepare("PRAGMA integrity_check;")
                    .map_err(|e| e.to_string())?;
                let ic_msgs: Vec<String> = ic_stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| e.to_string())?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?;
                let integrity = if ic_msgs.is_empty() {
                    "unknown".to_string()
                } else {
                    ic_msgs.join("; ")
                };
                let fk_rows = collect_sqlite_rows(&conn, "PRAGMA foreign_key_check;", &[])?;
                let fk_violations = fk_rows.len();
                let ok = integrity.eq_ignore_ascii_case("ok") && fk_violations == 0;
                Val::Map(vec![
                    (Val::Str("ok".into()), Val::Bool(ok)),
                    (Val::Str("integrity".into()), Val::Str(integrity)),
                    (
                        Val::Str("foreign_key_violations".into()),
                        Val::Num(fk_violations as f64),
                    ),
                ])
            }
            "spawn" => {
                if a.len() != 2 {
                    return Err("spawn expects callable,args".into());
                }
                let (_, def) = self.callable_def(&a[0])?;
                let args = match &a[1] {
                    Val::List(v) => v.clone(),
                    _ => return Err("spawn args must be List".into()),
                };
                self.spawn_task_with_kind(def, args, "task")?
            }
            "task_done" => {
                if a.len() != 1 {
                    return Err("task_done expects task id".into());
                }
                let id = match a[0] {
                    Val::Num(n) => n as u64,
                    _ => return Err("task id must be Number".into()),
                };
                let guard = tasks().lock().map_err(|_| "task registry poisoned")?;
                Val::Bool(guard.get(&id).map(|h| h.is_finished()).unwrap_or(true))
            }
            "task_status" => {
                if a.len() != 1 {
                    return Err("task_status expects task id".into());
                }
                let id = match a[0] {
                    Val::Num(n) => n as u64,
                    _ => return Err("task id must be Number".into()),
                };
                let guard = tasks().lock().map_err(|_| "task registry poisoned")?;
                Val::Str(
                    match guard.get(&id) {
                        Some(h) if h.is_finished() => "finished",
                        Some(_) => "running",
                        None => "consumed",
                    }
                    .into(),
                )
            }
            "await_timeout" => {
                if a.len() != 2 {
                    return Err("await_timeout expects task_id,milliseconds".into());
                }
                let id = match a[0] {
                    Val::Num(n) => n as u64,
                    _ => return Err("task id must be Number".into()),
                };
                let ms = match a[1] {
                    Val::Num(n) if n >= 0.0 => n as u64,
                    _ => return Err("timeout must be a non-negative Number".into()),
                };
                let deadline = Instant::now() + Duration::from_millis(ms);
                loop {
                    let finished = {
                        let guard = tasks().lock().map_err(|_| "task registry poisoned")?;
                        match guard.get(&id) {
                            Some(h) => h.is_finished(),
                            None => return Err(format!("unknown task {id}")),
                        }
                    };
                    if finished {
                        let handle = tasks()
                            .lock()
                            .map_err(|_| "task registry poisoned")?
                            .remove(&id)
                            .ok_or(format!("unknown task {id}"))?;
                        break handle.join().map_err(|_| "task panicked".to_string())??;
                    }
                    if Instant::now() >= deadline {
                        break Val::Null;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
            "await_task" => {
                if a.len() != 1 {
                    return Err("await_task expects task id".into());
                }
                let id = match a[0] {
                    Val::Num(n) => n as u64,
                    _ => return Err("task id must be Number".into()),
                };
                let handle = tasks()
                    .lock()
                    .map_err(|_| "task registry poisoned")?
                    .remove(&id)
                    .ok_or(format!("unknown task {id}"))?;
                handle.join().map_err(|_| "task panicked".to_string())??
            }
            "gather" => {
                if a.len() != 1 {
                    return Err("gather expects list of task ids".into());
                }
                let ids = match &a[0] {
                    Val::List(v) => v.clone(),
                    _ => return Err("gather expects List".into()),
                };
                let mut out = vec![];
                for task in ids {
                    let id = match task {
                        Val::Num(n) => n as u64,
                        _ => return Err("gather task ids must be Numbers".into()),
                    };
                    let handle = tasks()
                        .lock()
                        .map_err(|_| "task registry poisoned")?
                        .remove(&id)
                        .ok_or(format!("unknown task {id}"))?;
                    out.push(handle.join().map_err(|_| "task panicked".to_string())??);
                }
                Val::List(out)
            }
            "channel" => {
                if !a.is_empty() {
                    return Err("channel expects no arguments".into());
                }
                let (tx, rx) = mpsc::channel::<Val>();
                let id = CHANNEL_IDS.fetch_add(1, Ordering::Relaxed);
                channels()
                    .lock()
                    .map_err(|_| "channel registry poisoned")?
                    .insert(id, (tx, Arc::new(Mutex::new(rx))));
                Val::Num(id as f64)
            }
            "send" => {
                if a.len() != 2 {
                    return Err("send expects channel,value".into());
                }
                let id = match a[0] {
                    Val::Num(n) => n as u64,
                    _ => return Err("channel id must be Number".into()),
                };
                let tx = channels()
                    .lock()
                    .map_err(|_| "channel registry poisoned")?
                    .get(&id)
                    .map(|(tx, _)| tx.clone())
                    .ok_or(format!("unknown channel {id}"))?;
                tx.send(a[1].clone()).map_err(|e| e.to_string())?;
                Val::Null
            }
            "recv" => {
                if a.len() != 1 {
                    return Err("recv expects channel".into());
                }
                let id = match a[0] {
                    Val::Num(n) => n as u64,
                    _ => return Err("channel id must be Number".into()),
                };
                let rx = channels()
                    .lock()
                    .map_err(|_| "channel registry poisoned")?
                    .get(&id)
                    .map(|(_, rx)| rx.clone())
                    .ok_or(format!("unknown channel {id}"))?;
                let value = rx
                    .lock()
                    .map_err(|_| "channel receiver poisoned")?
                    .recv()
                    .map_err(|e| e.to_string())?;
                value
            }
            "try_recv" => {
                if a.len() != 1 {
                    return Err("try_recv expects channel".into());
                }
                let id = match a[0] {
                    Val::Num(n) => n as u64,
                    _ => return Err("channel id must be Number".into()),
                };
                let rx = channels()
                    .lock()
                    .map_err(|_| "channel registry poisoned")?
                    .get(&id)
                    .map(|(_, rx)| rx.clone())
                    .ok_or(format!("unknown channel {id}"))?;
                match rx
                    .lock()
                    .map_err(|_| "channel receiver poisoned")?
                    .try_recv()
                {
                    Ok(v) => v,
                    Err(TryRecvError::Empty) => Val::Null,
                    Err(TryRecvError::Disconnected) => {
                        return Err("channel disconnected".into());
                    }
                }
            }
            "ffi_available" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 1 {
                    return Err("ffi_available expects library path".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("library path must be String".into()),
                };
                Val::Bool(unsafe { Library::new(path) }.is_ok())
            }
            "ffi_i32" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 3 {
                    return Err("ffi_i32 expects library,symbol,args".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("library path must be String".into()),
                };
                let symbol = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("symbol must be String".into()),
                };
                let vals = match &a[2] {
                    Val::List(v) => v,
                    _ => return Err("ffi args must be List".into()),
                };
                let nums: Result<Vec<i32>, String> = vals
                    .iter()
                    .map(|v| match v {
                        Val::Num(n) => Ok(*n as i32),
                        _ => Err("ffi_i32 arguments must be Numbers".into()),
                    })
                    .collect();
                let nums = nums?;
                let mut sym = symbol.as_bytes().to_vec();
                sym.push(0);
                let lib = unsafe { Library::new(path) }.map_err(|e| e.to_string())?;
                let result: i32 = unsafe {
                    match nums.as_slice() {
                        [] => {
                            let f: libloading::Symbol<unsafe extern "C" fn() -> i32> =
                                lib.get(&sym).map_err(|e| e.to_string())?;
                            f()
                        }
                        [a] => {
                            let f: libloading::Symbol<unsafe extern "C" fn(i32) -> i32> =
                                lib.get(&sym).map_err(|e| e.to_string())?;
                            f(*a)
                        }
                        [a, b] => {
                            let f: libloading::Symbol<unsafe extern "C" fn(i32, i32) -> i32> =
                                lib.get(&sym).map_err(|e| e.to_string())?;
                            f(*a, *b)
                        }
                        [a, b, c] => {
                            let f: libloading::Symbol<unsafe extern "C" fn(i32, i32, i32) -> i32> =
                                lib.get(&sym).map_err(|e| e.to_string())?;
                            f(*a, *b, *c)
                        }
                        [a, b, c, e] => {
                            let f: libloading::Symbol<
                                unsafe extern "C" fn(i32, i32, i32, i32) -> i32,
                            > = lib.get(&sym).map_err(|e| e.to_string())?;
                            f(*a, *b, *c, *e)
                        }
                        _ => {
                            return Err("ffi_i32 supports 0..4 integer arguments".into());
                        }
                    }
                };
                Val::Num(result as f64)
            }
            "ffi_i64" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 3 {
                    return Err("ffi_i64 expects library,symbol,args".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("library path must be String".into()),
                };
                let symbol = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("symbol must be String".into()),
                };
                let vals = match &a[2] {
                    Val::List(v) => v,
                    _ => return Err("ffi args must be List".into()),
                };
                let nums: Result<Vec<i64>, String> = vals
                    .iter()
                    .map(|v| match v {
                        Val::Num(n) => Ok(*n as i64),
                        _ => Err("ffi_i64 arguments must be Numbers".into()),
                    })
                    .collect();
                let nums = nums?;
                let mut sym = symbol.as_bytes().to_vec();
                sym.push(0);
                let lib = unsafe { Library::new(path) }.map_err(|e| e.to_string())?;
                let result: i64 = unsafe {
                    match nums.as_slice() {
                        [] => {
                            let f: libloading::Symbol<unsafe extern "C" fn() -> i64> =
                                lib.get(&sym).map_err(|e| e.to_string())?;
                            f()
                        }
                        [a] => {
                            let f: libloading::Symbol<unsafe extern "C" fn(i64) -> i64> =
                                lib.get(&sym).map_err(|e| e.to_string())?;
                            f(*a)
                        }
                        [a, b] => {
                            let f: libloading::Symbol<unsafe extern "C" fn(i64, i64) -> i64> =
                                lib.get(&sym).map_err(|e| e.to_string())?;
                            f(*a, *b)
                        }
                        _ => {
                            return Err("ffi_i64 supports 0..2 integer arguments".into());
                        }
                    }
                };
                Val::Num(result as f64)
            }
            "ffi_f64" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 3 {
                    return Err("ffi_f64 expects library,symbol,args".into());
                }
                let path = match &a[0] {
                    Val::Str(s) => s,
                    _ => return Err("library path must be String".into()),
                };
                let symbol = match &a[1] {
                    Val::Str(s) => s,
                    _ => return Err("symbol must be String".into()),
                };
                let vals = match &a[2] {
                    Val::List(v) => v,
                    _ => return Err("ffi args must be List".into()),
                };
                let nums: Result<Vec<f64>, String> = vals
                    .iter()
                    .map(|v| match v {
                        Val::Num(n) => Ok(*n),
                        _ => Err("ffi_f64 arguments must be Numbers".into()),
                    })
                    .collect();
                let nums = nums?;
                let mut sym = symbol.as_bytes().to_vec();
                sym.push(0);
                let lib = unsafe { Library::new(path) }.map_err(|e| e.to_string())?;
                let result: f64 = unsafe {
                    match nums.as_slice() {
                        [] => {
                            let f: libloading::Symbol<unsafe extern "C" fn() -> f64> =
                                lib.get(&sym).map_err(|e| e.to_string())?;
                            f()
                        }
                        [a] => {
                            let f: libloading::Symbol<unsafe extern "C" fn(f64) -> f64> =
                                lib.get(&sym).map_err(|e| e.to_string())?;
                            f(*a)
                        }
                        [a, b] => {
                            let f: libloading::Symbol<unsafe extern "C" fn(f64, f64) -> f64> =
                                lib.get(&sym).map_err(|e| e.to_string())?;
                            f(*a, *b)
                        }
                        _ => {
                            return Err("ffi_f64 supports 0..2 floating arguments".into());
                        }
                    }
                };
                Val::Num(result)
            }
            "py_available" => {
                if !a.is_empty() {
                    return Err("py_available expects 0 arguments".into());
                }
                Val::Bool(crate::py_bridge::py_available())
            }
            "py_import" => {
                crate::runtime::require_cap("python")?;
                if a.len() != 1 {
                    return Err("py_import expects module name String".into());
                }
                let Val::Str(name) = &a[0] else {
                    return Err("py_import module name must be String".into());
                };
                crate::py_bridge::py_import(name)?
            }
            "py_call" => {
                crate::runtime::require_cap("python")?;
                if a.is_empty() || a.len() > 3 {
                    return Err("py_call expects (callable[, args[, kwargs]])".into());
                }
                let args = match a.get(1) {
                    None | Some(Val::Null) => Vec::new(),
                    Some(Val::List(xs)) => xs.clone(),
                    _ => return Err("py_call args must be List".into()),
                };
                crate::py_bridge::py_call(&a[0], &args, a.get(2))?
            }
            "py_get" => {
                crate::runtime::require_cap("python")?;
                if a.len() != 2 {
                    return Err("py_get expects (py_obj, attr)".into());
                }
                let Val::Str(attr) = &a[1] else {
                    return Err("py_get attr must be String".into());
                };
                crate::py_bridge::py_get(&a[0], attr)?
            }
            "py_set" => {
                crate::runtime::require_cap("python")?;
                if a.len() != 3 {
                    return Err("py_set expects (py_obj, attr, value)".into());
                }
                let Val::Str(attr) = &a[1] else {
                    return Err("py_set attr must be String".into());
                };
                crate::py_bridge::py_set(&a[0], attr, &a[2])?
            }
            "py_dir" => {
                crate::runtime::require_cap("python")?;
                if a.len() != 1 {
                    return Err("py_dir expects py_obj".into());
                }
                crate::py_bridge::py_dir(&a[0])?
            }
            "py_eval" => {
                crate::runtime::require_cap("python")?;
                if a.is_empty() || a.len() > 2 {
                    return Err("py_eval expects (expr[, locals])".into());
                }
                let Val::Str(expr) = &a[0] else {
                    return Err("py_eval expr must be String".into());
                };
                crate::py_bridge::py_eval(expr, a.get(1))?
            }
            "py_exec" => {
                crate::runtime::require_cap("python")?;
                if a.len() != 1 {
                    return Err("py_exec expects Python source String".into());
                }
                let Val::Str(code) = &a[0] else {
                    return Err("py_exec source must be String".into());
                };
                crate::py_bridge::py_exec(code)?
            }
            "py_info" => {
                if !a.is_empty() {
                    return Err("py_info expects no args".into());
                }
                crate::py_bridge::py_info_val()
            }
            "py_free" => {
                crate::runtime::require_cap("python")?;
                if a.len() != 1 {
                    return Err("py_free expects Python handle".into());
                }
                Val::Bool(crate::py_bridge::py_free(&a[0])?)
            }
            "py_to_tensor" => {
                crate::runtime::require_cap("python")?;
                if a.len() != 1 {
                    return Err("py_to_tensor expects Python buffer/ndarray handle".into());
                }
                crate::py_bridge::py_to_tensor(&a[0])?
            }
            "tensor_to_py" => {
                crate::runtime::require_cap("python")?;
                if a.len() != 1 {
                    return Err("tensor_to_py expects Tensor".into());
                }
                crate::py_bridge::tensor_to_py(&a[0])?
            }
            "tensor_to_dlpack" => {
                crate::runtime::require_cap("python")?;
                if a.len() != 1 {
                    return Err("tensor_to_dlpack expects Tensor".into());
                }
                crate::py_bridge::tensor_to_dlpack(&a[0])?
            }
            "py_from_dlpack" => {
                crate::runtime::require_cap("python")?;
                if a.len() != 1 {
                    return Err("py_from_dlpack expects DLPack Python object/PyCapsule".into());
                }
                crate::py_bridge::py_from_dlpack(&a[0])?
            }
            "jit_available" => {
                if !a.is_empty() {
                    return Err("jit_available expects 0 arguments".into());
                }
                Val::Bool(crate::jit::jit_available())
            }
            "jit_info" | "jit_stats" => {
                if !a.is_empty() {
                    return Err(format!("{n} expects 0 arguments"));
                }
                crate::jit::jit_info_val()
            }
            "jit_set_enabled" => {
                if a.len() != 1 {
                    return Err("jit_set_enabled expects Bool".into());
                }
                Val::Bool(crate::jit::jit_set_enabled(a[0].truthy()))
            }
            "jit_compile" => {
                if a.len() != 1 {
                    return Err("jit_compile expects function or function name".into());
                }
                let (name, def) = match &a[0] {
                    Val::Function(key) => {
                        let def = self
                            .funcs
                            .get(key)
                            .cloned()
                            .or_else(|| resolve_function_object(key).ok().flatten())
                            .ok_or_else(|| format!("unknown function reference '{key}'"))?;
                        (def.debug_name.clone(), def)
                    }
                    Val::Str(fn_name) => {
                        let def = match self.vars.get(fn_name) {
                            Some(Val::Function(key)) => self
                                .funcs
                                .get(key)
                                .cloned()
                                .or_else(|| resolve_function_object(key).ok().flatten()),
                            _ => self.funcs.get(fn_name).cloned(),
                        }
                        .ok_or_else(|| format!("unknown function '{fn_name}'"))?;
                        (fn_name.clone(), def)
                    }
                    _ => return Err("jit_compile expects Function or String".into()),
                };
                let ok = crate::jit::jit_try_compile(&name, &def, &|fname| {
                    self.resolve_jit_callee(fname)
                })
                .is_ok();
                Val::Bool(ok)
            }
            "plugin_load" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 1 {
                    return Err("plugin_load expects library path String".into());
                }
                let Val::Str(path) = &a[0] else {
                    return Err("plugin_load path must be String".into());
                };
                crate::plugin::load_plugin(Path::new(path))?.info_val()
            }
            "plugin_info" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 1 {
                    return Err("plugin_info expects plugin handle or name".into());
                }
                let key = match &a[0] {
                    Val::Str(s) => s.clone(),
                    Val::Map(pairs) => map_lookup(pairs, &Val::Str("id".into()))
                        .and_then(|v| {
                            if let Val::Str(s) = v {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .ok_or("invalid plugin handle Map")?,
                    _ => return Err("plugin_info expects String or plugin Map".into()),
                };
                crate::plugin::get_loaded_plugin(&key)?.info_val()
            }
            "plugin_list" => {
                crate::runtime::require_cap("ffi")?;
                if !a.is_empty() {
                    return Err("plugin_list expects 0 arguments".into());
                }
                Val::List(crate::plugin::list_loaded_plugins())
            }
            "plugin_call" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() < 2 || a.len() > 3 {
                    return Err("plugin_call expects (plugin, fn_name[, args])".into());
                }
                let key = match &a[0] {
                    Val::Str(s) => s.clone(),
                    Val::Map(pairs) => map_lookup(pairs, &Val::Str("id".into()))
                        .and_then(|v| {
                            if let Val::Str(s) = v {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .ok_or("invalid plugin handle Map")?,
                    _ => return Err("plugin_call expects String or plugin Map".into()),
                };
                let Val::Str(fn_name) = &a[1] else {
                    return Err("plugin_call function name must be String".into());
                };
                let call_args = match a.get(2) {
                    None => Vec::new(),
                    Some(Val::List(xs)) => xs.clone(),
                    Some(_) => return Err("plugin_call args must be List".into()),
                };
                let p = crate::plugin::get_loaded_plugin(&key)?;
                p.call(fn_name, &call_args)?
            }
            "plugin_build" => {
                crate::runtime::require_cap("ffi")?;
                crate::runtime::require_cap("process")?;
                crate::runtime::require_cap("fs.write")?;
                if a.is_empty() || a.len() > 2 {
                    return Err("plugin_build expects (source_rs_path[, out_lib_path])".into());
                }
                let Val::Str(src) = &a[0] else {
                    return Err("plugin_build source path must be String".into());
                };
                let src_path = PathBuf::from(src);
                let out_path = match a.get(1) {
                    Some(Val::Str(o)) => PathBuf::from(o),
                    Some(_) => return Err("plugin_build out path must be String".into()),
                    None => {
                        let stem = src_path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("kovrek_plugin");
                        src_path.with_file_name(format!(
                            "{stem}.{}",
                            crate::plugin::platform_shared_ext()
                        ))
                    }
                };
                let built = crate::plugin::build_rust_plugin(&src_path, &out_path)?;
                Val::Str(built.to_string_lossy().to_string())
            }
            "__plugin_trampoline" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() < 2 {
                    return Err("__plugin_trampoline expects plugin_id,fn_name,...".into());
                }
                let (Val::Str(pid), Val::Str(fname)) = (&a[0], &a[1]) else {
                    return Err("invalid plugin trampoline arguments".into());
                };
                crate::plugin::get_loaded_plugin(pid)?.call(fname, &a[2..])?
            }
            "cap_current" => {
                if !a.is_empty() {
                    return Err("cap_current expects 0 arguments".into());
                }
                match crate::runtime::current_caps() {
                    None => Val::Str("all".into()),
                    Some(list) => Val::List(list.into_iter().map(Val::Str).collect()),
                }
            }
            "cap_restrict" => {
                if a.len() != 2 {
                    return Err("cap_restrict expects (caps_list_or_csv, fn)".into());
                }
                let caps: Vec<String> = match &a[0] {
                    Val::Str(s) => s
                        .split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect(),
                    Val::List(xs) => xs
                        .iter()
                        .map(|v| match v {
                            Val::Str(s) => Ok(s.trim().to_string()),
                            _ => Err("cap_restrict capability names must be String".to_string()),
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => return Err("cap_restrict caps must be String or List".into()),
                };
                let callee = a[1].clone();
                crate::runtime::run_with_caps(caps, || self.invoke_callable_sync(&callee, vec![]))?
            }
            "wasm_compile" => {
                if a.is_empty() || a.len() > 2 {
                    return Err("wasm_compile expects (source_string[, wasi])".into());
                }
                let Val::Str(src) = &a[0] else {
                    return Err("wasm_compile source must be String".into());
                };
                let wasi = match a.get(1) {
                    None => false,
                    Some(Val::Bool(b)) => *b,
                    Some(_) => return Err("wasm_compile wasi flag must be Bool".into()),
                };
                let bytes = crate::native_codegen::compile_source_to_wasm_with_opts(src, wasi)?;
                Val::List(bytes.into_iter().map(|b| Val::Num(f64::from(b))).collect())
            }
            "wasm_disasm" => {
                if a.len() != 1 {
                    return Err("wasm_disasm expects (wasm_bytes_or_path)".into());
                }
                let bytes = wasm_bytes_from_val(&a[0])?;
                Val::Str(crate::native_codegen::wasm_disasm(&bytes)?)
            }
            "wasm_run" => {
                if a.is_empty() || a.len() > 3 {
                    return Err("wasm_run expects (wasm_bytes_or_path[, fn_name[, args]])".into());
                }
                let bytes = wasm_bytes_from_val(&a[0])?;
                let fn_name = match a.get(1) {
                    None | Some(Val::Null) => "main".to_string(),
                    Some(Val::Str(s)) => s.clone(),
                    Some(_) => return Err("wasm_run fn_name must be String".into()),
                };
                let args = match a.get(2) {
                    None | Some(Val::Null) => Vec::new(),
                    Some(Val::List(xs)) => xs
                        .iter()
                        .map(|v| match v {
                            Val::Num(n) => Ok(*n),
                            Val::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
                            _ => Err("wasm_run args must be numeric".to_string()),
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    Some(_) => return Err("wasm_run args must be List".into()),
                };
                let (res, prints) = crate::native_codegen::wasm_run(&bytes, &fn_name, &args)?;
                Val::Map(vec![
                    (Val::Str("result".into()), Val::Num(res)),
                    (
                        Val::Str("prints".into()),
                        Val::List(prints.into_iter().map(Val::Str).collect()),
                    ),
                ])
            }
            "__plugin_trampoline_list" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 3 {
                    return Err("__plugin_trampoline_list expects plugin_id,fn_name,args".into());
                }
                let (Val::Str(pid), Val::Str(fname), Val::List(xs)) = (&a[0], &a[1], &a[2]) else {
                    return Err("invalid plugin list trampoline arguments".into());
                };
                crate::plugin::get_loaded_plugin(pid)?.call(fname, xs)?
            }
            "gc_collect" => {
                if a.len() > 1 {
                    return Err("gc_collect expects ([mode])".into());
                }
                match a.first() {
                    None | Some(Val::Null) => self.gc_collect()?,
                    Some(Val::Str(mode)) => self.gc_collect_mode(Some(mode))?,
                    Some(_) => {
                        return Err("gc_collect mode must be String ('minor' or 'major')".into());
                    }
                }
            }
            "arena_scope" => {
                if a.len() != 1 {
                    return Err("arena_scope expects (callable)".into());
                }
                self.arena_scope(a[0].clone())?
            }
            "gc_stats" => {
                if !a.is_empty() {
                    return Err("gc_stats expects 0 arguments".into());
                }
                self.gc_stats()?
            }
            "gc_pause" => {
                if !a.is_empty() {
                    return Err("gc_pause expects 0 arguments".into());
                }
                self.gc_set_paused(true)
            }
            "gc_resume" => {
                if !a.is_empty() {
                    return Err("gc_resume expects 0 arguments".into());
                }
                self.gc_set_paused(false)
            }
            "profile_start" => {
                if !a.is_empty() {
                    return Err("profile_start expects 0 arguments".into());
                }
                self.profile_start()
            }
            "profile_stop" => {
                if !a.is_empty() {
                    return Err("profile_stop expects 0 arguments".into());
                }
                self.profile_stop()?
            }
            "profile_report" => {
                if !a.is_empty() {
                    return Err("profile_report expects 0 arguments".into());
                }
                self.profile_report()?
            }
            "sim_start" => {
                if a.len() != 1 {
                    return Err("sim_start expects integer seed".into());
                }
                let seed = match a[0] {
                    Val::Num(n) if n.is_finite() => n as i64 as u64,
                    _ => return Err("sim_start seed must be Number".into()),
                };
                crate::sim_actor::sim_start(seed)
            }
            "sim_stop" => {
                if !a.is_empty() {
                    return Err("sim_stop expects 0 arguments".into());
                }
                crate::sim_actor::sim_stop()
            }
            "sim_now" => {
                if !a.is_empty() {
                    return Err("sim_now expects 0 arguments".into());
                }
                crate::sim_actor::sim_now()?
            }
            "sim_advance" => {
                if a.len() != 1 {
                    return Err("sim_advance expects milliseconds".into());
                }
                let Val::Num(ms) = a[0] else {
                    return Err("sim_advance expects Number milliseconds".into());
                };
                crate::sim_actor::sim_advance(ms)?
            }
            "sim_rand" => {
                if !a.is_empty() {
                    return Err("sim_rand expects 0 arguments".into());
                }
                crate::sim_actor::sim_rand()?
            }
            "sim_fault" => {
                if a.is_empty() || a.len() > 2 {
                    return Err("sim_fault expects (target[, rate])".into());
                }
                let Val::Str(ref target) = a[0] else {
                    return Err("sim_fault target must be String".into());
                };
                if a.len() == 2 {
                    let Val::Num(rate) = a[1] else {
                        return Err("sim_fault rate must be Number".into());
                    };
                    crate::sim_actor::sim_fault_set(target, rate)?
                } else {
                    crate::sim_actor::sim_fault_check(target)?
                }
            }
            "sim_log" => {
                if a.len() > 1 {
                    return Err("sim_log expects 0 or 1 argument".into());
                }
                if a.is_empty() {
                    crate::sim_actor::sim_log_get()?
                } else {
                    crate::sim_actor::sim_log_append(a[0].clone())?
                }
            }
            "sim_actor_spawn" => match a.len() {
                1 => crate::sim_actor::sim_actor_spawn(self, None, a[0].clone(), None)?,
                2 => {
                    if let Val::Str(ref name) = a[0] {
                        crate::sim_actor::sim_actor_spawn(self, Some(name), a[1].clone(), None)?
                    } else {
                        crate::sim_actor::sim_actor_spawn(self, None, a[0].clone(), Some(&a[1]))?
                    }
                }
                3 => {
                    let Val::Str(ref name) = a[0] else {
                        return Err("sim_actor_spawn first argument must be String name".into());
                    };
                    crate::sim_actor::sim_actor_spawn(self, Some(name), a[1].clone(), Some(&a[2]))?
                }
                _ => {
                    return Err(
                        "sim_actor_spawn expects ([name,] handler[, options_or_init])".into(),
                    );
                }
            },
            "sim_actor_send" => match a.len() {
                2 => {
                    let Val::Str(ref to) = a[0] else {
                        return Err("sim_actor_send target must be String name".into());
                    };
                    crate::sim_actor::sim_actor_send("__host__", to, a[1].clone(), 1)?
                }
                3 => {
                    let (Val::Str(from), Val::Str(to)) = (&a[0], &a[1]) else {
                        return Err(
                            "sim_actor_send (from, to, payload) expects String actor names".into(),
                        );
                    };
                    crate::sim_actor::sim_actor_send(from, to, a[2].clone(), 1)?
                }
                4 => {
                    let (Val::Str(from), Val::Str(to), Val::Num(delay)) = (&a[0], &a[1], &a[3])
                    else {
                        return Err(
                            "sim_actor_send expects (from, to, payload[, delay_ticks])".into()
                        );
                    };
                    if !delay.is_finite() || *delay < 0.0 {
                        return Err("sim_actor_send delay_ticks must be non-negative Number".into());
                    }
                    crate::sim_actor::sim_actor_send(from, to, a[2].clone(), *delay as u64)?
                }
                _ => {
                    return Err(
                        "sim_actor_send expects ([from,] to, payload[, delay_ticks])".into(),
                    );
                }
            },
            "sim_step" => {
                if !a.is_empty() {
                    return Err("sim_step expects 0 arguments".into());
                }
                crate::sim_actor::sim_step()?
            }
            "sim_run_until" => {
                if a.len() > 1 {
                    return Err("sim_run_until expects ([until_tick])".into());
                }
                let until = match a.first() {
                    None | Some(Val::Null) => None,
                    Some(Val::Num(n)) if n.is_finite() && *n >= 0.0 => Some(*n as u64),
                    Some(_) => {
                        return Err("sim_run_until until_tick must be non-negative Number".into());
                    }
                };
                crate::sim_actor::sim_run_until(until)?
            }
            "sim_partition" => {
                if a.len() < 2 || a.len() > 3 {
                    return Err("sim_partition expects (actor_a, actor_b[, drop_prob])".into());
                }
                let (Val::Str(a_name), Val::Str(b_name)) = (&a[0], &a[1]) else {
                    return Err("sim_partition actor names must be String".into());
                };
                let prob = match a.get(2) {
                    None | Some(Val::Null) => 1.0,
                    Some(Val::Num(p)) => *p,
                    Some(_) => return Err("sim_partition drop_prob must be Number".into()),
                };
                crate::sim_actor::sim_partition(a_name, b_name, prob)?
            }
            "sim_actor_state" => {
                if a.len() != 1 {
                    return Err("sim_actor_state expects (actor_name)".into());
                }
                let Val::Str(ref name) = a[0] else {
                    return Err("sim_actor_state name must be String".into());
                };
                crate::sim_actor::sim_actor_state(name)?
            }
            "sim_trace" => {
                if !a.is_empty() {
                    return Err("sim_trace expects 0 arguments".into());
                }
                crate::sim_actor::sim_trace()?
            }
            "sim_fs_write" => {
                if a.len() != 2 {
                    return Err("sim_fs_write expects (path, content)".into());
                }
                let (Val::Str(path), Val::Str(content)) = (&a[0], &a[1]) else {
                    return Err("sim_fs_write expects String arguments".into());
                };
                crate::sim_actor::sim_fs_write(path, content)?
            }
            "sim_fs_read" => {
                if a.len() != 1 {
                    return Err("sim_fs_read expects (path)".into());
                }
                let Val::Str(ref path) = a[0] else {
                    return Err("sim_fs_read path must be String".into());
                };
                crate::sim_actor::sim_fs_read(path)?
            }
            "sim_fs_delete" => {
                if a.len() != 1 {
                    return Err("sim_fs_delete expects (path)".into());
                }
                let Val::Str(ref path) = a[0] else {
                    return Err("sim_fs_delete path must be String".into());
                };
                crate::sim_actor::sim_fs_delete(path)?
            }
            "sim_fs_list" => {
                if a.len() > 1 {
                    return Err("sim_fs_list expects ([prefix])".into());
                }
                let prefix = match a.first() {
                    None | Some(Val::Null) => None,
                    Some(Val::Str(s)) => Some(s.as_str()),
                    Some(_) => return Err("sim_fs_list prefix must be String".into()),
                };
                crate::sim_actor::sim_fs_list(prefix)?
            }
            "sim_fs_sync" => {
                if !a.is_empty() {
                    return Err("sim_fs_sync expects 0 arguments".into());
                }
                crate::sim_actor::sim_fs_sync()?
            }
            "sim_fs_crash" => {
                if !a.is_empty() {
                    return Err("sim_fs_crash expects 0 arguments".into());
                }
                crate::sim_actor::sim_fs_crash()?
            }
            "sim_fs_snapshot" => {
                if !a.is_empty() {
                    return Err("sim_fs_snapshot expects 0 arguments".into());
                }
                crate::sim_actor::sim_fs_snapshot()?
            }
            "actor_node_listen" => {
                crate::runtime::require_cap("net")?;
                if a.is_empty() || a.len() > 2 {
                    return Err("actor_node_listen expects (actor_id[, port_or_addr])".into());
                }
                let Val::Num(id) = a[0] else {
                    return Err("actor_node_listen actor_id must be Number".into());
                };
                if !id.is_finite() || id < 0.0 {
                    return Err("actor_node_listen actor_id must be non-negative Number".into());
                }
                crate::sim_actor::actor_node_listen(id as u64, a.get(1))?
            }
            "actor_node_stop" => {
                crate::runtime::require_cap("net")?;
                if a.len() != 1 {
                    return Err("actor_node_stop expects (node_id_or_map)".into());
                }
                crate::sim_actor::actor_node_stop(&a[0])?
            }
            "actor_remote_send" => {
                crate::runtime::require_cap("net")?;
                if a.len() != 2 {
                    return Err("actor_remote_send expects (target, message)".into());
                }
                crate::sim_actor::actor_remote_send(&a[0], a[1].clone())?
            }
            "actor_remote_ask" => {
                crate::runtime::require_cap("net")?;
                if a.len() < 2 || a.len() > 3 {
                    return Err("actor_remote_ask expects (target, message[, timeout_ms])".into());
                }
                let timeout = parse_nonneg_timeout_ms(a.get(2), "actor_remote_ask")?;
                crate::sim_actor::actor_remote_ask(&a[0], a[1].clone(), timeout)?
            }
            "actor_spawn" => {
                if a.is_empty() || a.len() > 2 {
                    return Err("actor_spawn expects (handler[, options_map])".into());
                }
                crate::sim_actor::actor_spawn(self, a[0].clone(), a.get(1))?
            }
            "actor_send" => {
                if a.len() != 2 {
                    return Err("actor_send expects (actor_id, message)".into());
                }
                let Val::Num(id) = a[0] else {
                    return Err("actor_send id must be Number".into());
                };
                if !id.is_finite() || id < 0.0 {
                    return Err("actor_send id must be non-negative Number".into());
                }
                crate::sim_actor::actor_send(id as u64, a[1].clone())?
            }
            "actor_ask" => {
                if a.len() < 2 || a.len() > 3 {
                    return Err("actor_ask expects (actor_id, message[, timeout_ms])".into());
                }
                let Val::Num(id) = a[0] else {
                    return Err("actor_ask id must be Number".into());
                };
                if !id.is_finite() || id < 0.0 {
                    return Err("actor_ask id must be non-negative Number".into());
                }
                let timeout = parse_nonneg_timeout_ms(a.get(2), "actor_ask")?;
                crate::sim_actor::actor_ask(id as u64, a[1].clone(), timeout)?
            }
            "actor_stop" => {
                if a.len() != 1 {
                    return Err("actor_stop expects (actor_id)".into());
                }
                let Val::Num(id) = a[0] else {
                    return Err("actor_stop id must be Number".into());
                };
                crate::sim_actor::actor_stop(id as u64)?
            }
            "actor_status" => {
                if a.len() != 1 {
                    return Err("actor_status expects (actor_id)".into());
                }
                let Val::Num(id) = a[0] else {
                    return Err("actor_status id must be Number".into());
                };
                crate::sim_actor::actor_status(id as u64)?
            }
            "actor_mailbox_len" => {
                if a.len() != 1 {
                    return Err("actor_mailbox_len expects (actor_id)".into());
                }
                let Val::Num(id) = a[0] else {
                    return Err("actor_mailbox_len id must be Number".into());
                };
                if !id.is_finite() || id < 0.0 {
                    return Err("actor_mailbox_len id must be non-negative Number".into());
                }
                crate::sim_actor::actor_mailbox_len(id as u64)?
            }
            "supervisor_spawn" => {
                if a.len() < 2 || a.len() > 3 {
                    return Err(
                        "supervisor_spawn expects (strategy, child_specs[, options])".into(),
                    );
                }
                let (Val::Str(strategy), Val::List(specs)) = (&a[0], &a[1]) else {
                    return Err(
                        "supervisor_spawn expects (strategy: String, child_specs: List[, options])"
                            .into(),
                    );
                };
                crate::sim_actor::supervisor_spawn(self, strategy, specs, a.get(2))?
            }
            "supervisor_status" => {
                if a.len() != 1 {
                    return Err("supervisor_status expects (supervisor_id)".into());
                }
                let Val::Num(id) = a[0] else {
                    return Err("supervisor_status id must be Number".into());
                };
                if !id.is_finite() || id < 0.0 {
                    return Err("supervisor_status id must be non-negative Number".into());
                }
                crate::sim_actor::supervisor_status(id as u64)?
            }
            "ffi_bindgen" => {
                if a.len() != 2 {
                    return Err("ffi_bindgen expects (header_source, lib_path)".into());
                }
                let (Val::Str(header_src), Val::Str(lib_path)) = (&a[0], &a[1]) else {
                    return Err("ffi_bindgen expects String arguments".into());
                };
                Val::Str(crate::plugin::ffi_bindgen(header_src, lib_path)?)
            }
            "mem_alloc" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 1 {
                    return Err("mem_alloc expects (size)".into());
                }
                let Val::Num(sz) = a[0] else {
                    return Err("mem_alloc size must be Number".into());
                };
                if !sz.is_finite() || sz <= 0.0 {
                    return Err("mem_alloc size must be positive".into());
                }
                Val::Num(crate::plugin::mem_alloc(sz as usize)? as f64)
            }
            "mem_free" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 1 {
                    return Err("mem_free expects (ptr)".into());
                }
                let Val::Num(ptr) = a[0] else {
                    return Err("mem_free ptr must be Number".into());
                };
                Val::Bool(crate::plugin::mem_free(ptr as usize)?)
            }
            "mem_read_u8" | "mem_read_i32" | "mem_read_i64" | "mem_read_f32" | "mem_read_f64"
            | "mem_read_cstr" => {
                crate::runtime::require_cap("ffi")?;
                if a.is_empty() || a.len() > 2 {
                    return Err(format!("{n} expects (ptr[, offset])"));
                }
                let Val::Num(ptr) = a[0] else {
                    return Err(format!("{n} ptr must be Number"));
                };
                let offset = match a.get(1) {
                    None => 0usize,
                    Some(Val::Num(o)) if o.is_finite() && *o >= 0.0 => *o as usize,
                    Some(_) => return Err(format!("{n} offset must be non-negative Number")),
                };
                let p = ptr as usize;
                match n {
                    "mem_read_u8" => Val::Num(f64::from(crate::plugin::mem_read_u8(p, offset)?)),
                    "mem_read_i32" => Val::Num(f64::from(crate::plugin::mem_read_i32(p, offset)?)),
                    "mem_read_i64" => Val::Num(crate::plugin::mem_read_i64(p, offset)? as f64),
                    "mem_read_f32" => Val::Num(f64::from(crate::plugin::mem_read_f32(p, offset)?)),
                    "mem_read_f64" => Val::Num(crate::plugin::mem_read_f64(p, offset)?),
                    "mem_read_cstr" => Val::Str(crate::plugin::mem_read_cstr(p, offset)?),
                    _ => unreachable!(),
                }
            }
            "mem_write_u8" | "mem_write_i32" | "mem_write_i64" | "mem_write_f32"
            | "mem_write_f64" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 2 && a.len() != 3 {
                    return Err(format!("{n} expects (ptr, [offset, ]val)"));
                }
                let Val::Num(ptr) = a[0] else {
                    return Err(format!("{n} ptr must be Number"));
                };
                let (offset, val) = if a.len() == 2 {
                    let Val::Num(v) = a[1] else {
                        return Err(format!("{n} val must be Number"));
                    };
                    (0usize, v)
                } else {
                    let Val::Num(o) = a[1] else {
                        return Err(format!("{n} offset must be Number"));
                    };
                    if !o.is_finite() || o < 0.0 {
                        return Err(format!("{n} offset must be non-negative Number"));
                    }
                    let Val::Num(v) = a[2] else {
                        return Err(format!("{n} val must be Number"));
                    };
                    (o as usize, v)
                };
                let p = ptr as usize;
                match n {
                    "mem_write_u8" => crate::plugin::mem_write_u8(p, offset, val as u8)?,
                    "mem_write_i32" => crate::plugin::mem_write_i32(p, offset, val as i32)?,
                    "mem_write_i64" => crate::plugin::mem_write_i64(p, offset, val as i64)?,
                    "mem_write_f32" => crate::plugin::mem_write_f32(p, offset, val as f32)?,
                    "mem_write_f64" => crate::plugin::mem_write_f64(p, offset, val)?,
                    _ => unreachable!(),
                }
                Val::Null
            }
            "ffi_call" => {
                crate::runtime::require_cap("ffi")?;
                if a.len() != 5 {
                    return Err(
                        "ffi_call expects (lib_path, symbol, ret_type, param_types, args)".into(),
                    );
                }
                let (
                    Val::Str(lib_path),
                    Val::Str(symbol),
                    Val::Str(ret_type),
                    Val::List(param_list),
                    Val::List(arg_list),
                ) = (&a[0], &a[1], &a[2], &a[3], &a[4])
                else {
                    return Err("ffi_call expects (String, String, String, List, List)".into());
                };
                let param_types: Vec<String> = param_list
                    .iter()
                    .map(|v| match v {
                        Val::Str(s) => Ok(s.clone()),
                        _ => Err("ffi_call param_types must be Strings".to_string()),
                    })
                    .collect::<Result<_, _>>()?;
                crate::plugin::ffi_call(lib_path, symbol, ret_type, &param_types, arg_list)?
            }
            _ => return Ok(None),
        };
        Ok(Some(v))
    }
}

fn parse_nonneg_timeout_ms(arg: Option<&Val>, fn_name: &str) -> Result<u64, String> {
    match arg {
        None | Some(Val::Null) => Ok(10_000),
        Some(Val::Num(ms)) if ms.is_finite() && *ms >= 0.0 => Ok(*ms as u64),
        Some(_) => Err(format!("{fn_name} timeout_ms must be non-negative Number")),
    }
}
