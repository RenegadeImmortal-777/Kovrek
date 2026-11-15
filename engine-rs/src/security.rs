//! Security primitives: CSPRNG tokens, HTML escaping, Base32/TOTP (RFC 6238),
//! HKDF-SHA256 (RFC 5869), pure-Rust AES-256-GCM, ChaCha20-Poly1305 (RFC 8439),
//! and SSRF URL/IP validation.
#![allow(clippy::needless_range_loop)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::value::{constant_time_strings_equal, hmac_sha256_bytes, pbkdf2_hmac_sha256_bytes};

fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    std::hint::black_box(buf);
}

pub(crate) fn random_bytes(len: usize) -> Result<Vec<u8>, String> {
    if len == 0 || len > 4096 {
        return Err("byte length must be between 1 and 4096".into());
    }
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    Ok(buf)
}

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    if trimmed.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let raw = trimmed.as_bytes();
    for &pair in raw.as_chunks::<2>().0 {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex character".to_string())?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex character".to_string())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

pub(crate) fn random_bytes_hex(len: usize) -> Result<String, String> {
    Ok(bytes_to_hex(&random_bytes(len)?))
}

pub(crate) fn random_token_urlsafe(len: usize) -> Result<String, String> {
    let bytes = random_bytes(len)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

pub(crate) fn constant_time_bytes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Base32 (RFC 4648) + SHA-1 / HMAC-SHA1 + TOTP (RFC 6238)
// ---------------------------------------------------------------------------

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub(crate) fn base32_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

pub(crate) fn base32_decode(encoded: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;
    for raw in encoded.bytes() {
        if raw == b'=' || raw.is_ascii_whitespace() || raw == b'-' {
            continue;
        }
        let ch = raw.to_ascii_uppercase();
        let val = match ch {
            b'A'..=b'Z' => u32::from(ch - b'A'),
            b'2'..=b'7' => u32::from(ch - b'2' + 26),
            _ => return Err(format!("invalid Base32 character '{}'", ch as char)),
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

pub(crate) fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in padded.as_chunks::<64>().0 {
        for i in 0..16 {
            let off = i * 4;
            w[i] = u32::from_be_bytes([chunk[off], chunk[off + 1], chunk[off + 2], chunk[off + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub(crate) fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let digest = sha1_digest(key);
        k_block[..20].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    let mut outer = Vec::with_capacity(64 + 20);
    for &b in &k_block {
        inner.push(b ^ 0x36);
        outer.push(b ^ 0x5c);
    }
    inner.extend_from_slice(msg);
    let inner_hash = sha1_digest(&inner);
    outer.extend_from_slice(&inner_hash);
    sha1_digest(&outer)
}

pub(crate) fn generate_totp_secret() -> String {
    let mut buf = [0u8; 20];
    OsRng.fill_bytes(&mut buf);
    base32_encode(&buf)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn totp_code_at(
    secret_b32: &str,
    timestamp_secs: u64,
    digits: u32,
    period: u64,
) -> Result<String, String> {
    if !(6..=8).contains(&digits) {
        return Err("TOTP digits must be between 6 and 8".into());
    }
    let step = timestamp_secs / period.max(1);
    let key = base32_decode(secret_b32)?;
    if key.is_empty() {
        return Err("TOTP secret must not be empty".into());
    }
    let mac = hmac_sha1(&key, &step.to_be_bytes());
    let offset = (mac[19] & 0x0f) as usize;
    let bin_code = (u32::from(mac[offset] & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);
    let modulo = 10u32.pow(digits);
    let otp = bin_code % modulo;
    Ok(format!("{otp:0width$}", width = digits as usize))
}

pub(crate) fn verify_totp_at(
    secret_b32: &str,
    code: &str,
    timestamp_secs: u64,
    window: u32,
) -> bool {
    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let max_win = window.min(2) as i64;
    let base_step = (timestamp_secs / 30) as i64;
    let mut matched = 0u8;
    for delta in -max_win..=max_win {
        let step_secs = ((base_step + delta).max(0) as u64) * 30;
        if let Ok(expected) = totp_code_at(secret_b32, step_secs, 6, 30) {
            matched |= u8::from(constant_time_strings_equal(&expected, trimmed));
        }
    }
    matched != 0
}

pub(crate) fn totp_code_now(secret_b32: &str) -> Result<String, String> {
    totp_code_at(secret_b32, unix_now_secs(), 6, 30)
}

pub(crate) fn verify_totp_now(secret_b32: &str, code: &str, window: u32) -> bool {
    verify_totp_at(secret_b32, code, unix_now_secs(), window)
}

// ---------------------------------------------------------------------------
// Constant-Time Pure-Rust AES-256-GCM (NIST FIPS 197 + SP 800-38D)
// ---------------------------------------------------------------------------

const PBKDF2_AES_ITERATIONS: u32 = 100_000;
const PBKDF2_AES_DOMAIN: &[u8] = b"kovrek-aes256-gcm-v2\0";
const RCON: [u8; 8] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

/// Branchless multiplication in GF(2^8) modulo Rijndael polynomial x^8 + x^4 + x^3 + x + 1.
#[inline(always)]
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        let b_mask = 0u8.wrapping_sub(b & 1);
        p ^= a & b_mask;
        let hi_mask = 0u8.wrapping_sub((a >> 7) & 1);
        a = (a << 1) ^ (0x1b & hi_mask);
        b >>= 1;
    }
    p
}

/// Branchless multiplicative inverse in GF(2^8) via a^254 (0 -> 0).
#[inline(always)]
fn gf256_inv(a: u8) -> u8 {
    let a2 = gf256_mul(a, a);
    let a3 = gf256_mul(a2, a);
    let a6 = gf256_mul(a3, a3);
    let a7 = gf256_mul(a6, a);
    let a14 = gf256_mul(a7, a7);
    let a15 = gf256_mul(a14, a);
    let mut a240 = a15;
    for _ in 0..4 {
        a240 = gf256_mul(a240, a240);
    }
    gf256_mul(a240, a14)
}

/// Cache-timing-safe AES S-box with zero table lookups or secret-dependent branches.
#[inline(always)]
fn aes_sbox_ct(x: u8) -> u8 {
    let inv = gf256_inv(x);
    inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
}

fn aes256_expand_key(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut w = [[0u8; 4]; 60];
    for i in 0..8 {
        w[i] = [key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]];
    }
    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = [
                aes_sbox_ct(temp[1]) ^ RCON[i / 8],
                aes_sbox_ct(temp[2]),
                aes_sbox_ct(temp[3]),
                aes_sbox_ct(temp[0]),
            ];
        } else if i % 8 == 4 {
            temp = [
                aes_sbox_ct(temp[0]),
                aes_sbox_ct(temp[1]),
                aes_sbox_ct(temp[2]),
                aes_sbox_ct(temp[3]),
            ];
        }
        for c in 0..4 {
            w[i][c] = w[i - 8][c] ^ temp[c];
        }
    }
    let mut rk = [[0u8; 16]; 15];
    for r in 0..15 {
        for col in 0..4 {
            rk[r][col * 4..col * 4 + 4].copy_from_slice(&w[r * 4 + col]);
        }
    }
    for word in &mut w {
        zeroize_bytes(word);
    }
    rk
}

#[inline(always)]
fn xtime(a: u8) -> u8 {
    let hi_mask = 0u8.wrapping_sub((a >> 7) & 1);
    (a << 1) ^ (0x1b & hi_mask)
}

fn aes256_encrypt_block(rk: &[[u8; 16]; 15], input: &[u8; 16]) -> [u8; 16] {
    let mut s = *input;
    for i in 0..16 {
        s[i] ^= rk[0][i];
    }
    for round in 1..=14 {
        for b in &mut s {
            *b = aes_sbox_ct(*b);
        }
        // ShiftRows (column-major: index = row + 4*col)
        let t1 = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t1;

        s.swap(2, 10);
        s.swap(6, 14);

        let t3 = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t3;

        if round < 14 {
            for col in 0..4 {
                let i = col * 4;
                let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
                let xor_all = a0 ^ a1 ^ a2 ^ a3;
                s[i] = a0 ^ xor_all ^ xtime(a0 ^ a1);
                s[i + 1] = a1 ^ xor_all ^ xtime(a1 ^ a2);
                s[i + 2] = a2 ^ xor_all ^ xtime(a2 ^ a3);
                s[i + 3] = a3 ^ xor_all ^ xtime(a3 ^ a0);
            }
        }
        for i in 0..16 {
            s[i] ^= rk[round][i];
        }
    }
    s
}

/// Branchless constant-time multiplication in GF(2^128) for GHASH.
fn ghash_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        let x_mask = 0u128.wrapping_sub((x >> (127 - i)) & 1);
        z ^= v & x_mask;
        let lsb_mask = 0u128.wrapping_sub(v & 1);
        v = (v >> 1) ^ (R & lsb_mask);
    }
    z
}

fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut acc = 0u128;
    for data in [aad, ct] {
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            acc = ghash_mul(acc ^ u128::from_be_bytes(block), h);
        }
    }
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lens[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    acc = ghash_mul(acc ^ u128::from_be_bytes(lens), h);
    acc.to_be_bytes()
}

fn inc32(counter: &mut [u8; 16]) {
    let n = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    counter[12..16].copy_from_slice(&n.wrapping_add(1).to_be_bytes());
}

fn gctr(rk: &[[u8; 16]; 15], icb: [u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut cb = icb;
    for chunk in data.chunks(16) {
        let mask = aes256_encrypt_block(rk, &cb);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ mask[i]);
        }
        inc32(&mut cb);
    }
    out
}

fn derive_salted_key_with_domain(domain: &[u8], secret: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut domain_salt = Vec::with_capacity(domain.len() + salt.len());
    domain_salt.extend_from_slice(domain);
    domain_salt.extend_from_slice(salt);
    let mut derived =
        pbkdf2_hmac_sha256_bytes(secret.as_bytes(), &domain_salt, PBKDF2_AES_ITERATIONS, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&derived);
    zeroize_bytes(&mut derived);
    key
}

fn seal_salted_aead_token<F>(
    version: &str,
    domain: &[u8],
    secret: &str,
    plaintext: &str,
    seal_fn: F,
) -> Result<String, String>
where
    F: FnOnce(&[u8; 32], &[u8; 12], &[u8]) -> (Vec<u8>, [u8; 16]),
{
    if secret.is_empty() {
        return Err("encryption key must not be empty".into());
    }
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);
    let mut key = derive_salted_key_with_domain(domain, secret, &salt);
    let (ct, tag) = seal_fn(&key, &iv, plaintext.as_bytes());
    zeroize_bytes(&mut key);
    Ok(format!(
        "{version}:{}:{}:{}:{}",
        bytes_to_hex(&salt),
        bytes_to_hex(&iv),
        bytes_to_hex(&tag),
        bytes_to_hex(&ct)
    ))
}

fn open_salted_aead_token<F>(
    expected_version: &str,
    cipher_label: &str,
    domain: &[u8],
    secret: &str,
    token: &str,
    open_fn: F,
) -> Result<String, String>
where
    F: FnOnce(&[u8; 32], &[u8; 12], &[u8], &[u8; 16]) -> Result<Vec<u8>, String>,
{
    if secret.is_empty() {
        return Err("decryption key must not be empty".into());
    }
    let parts: Vec<&str> = token.trim().split(':').collect();
    if parts.len() != 5 || parts[0] != expected_version {
        return Err(format!(
            "invalid encrypted payload format (expected {expected_version}:salt:iv:tag:ciphertext)"
        ));
    }
    let salt_vec = hex_to_bytes(parts[1])?;
    let iv_vec = hex_to_bytes(parts[2])?;
    let tag_vec = hex_to_bytes(parts[3])?;
    let ct = hex_to_bytes(parts[4])?;
    let salt: [u8; 16] = salt_vec
        .try_into()
        .map_err(|_| format!("invalid {cipher_label} salt length (expected 16 bytes)"))?;
    let iv: [u8; 12] = iv_vec
        .try_into()
        .map_err(|_| format!("invalid {cipher_label} IV length (expected 12 bytes)"))?;
    let tag: [u8; 16] = tag_vec
        .try_into()
        .map_err(|_| format!("invalid {cipher_label} tag length (expected 16 bytes)"))?;
    let mut key = derive_salted_key_with_domain(domain, secret, &salt);
    let pt_res = open_fn(&key, &iv, &ct, &tag);
    zeroize_bytes(&mut key);
    let pt = pt_res?;
    String::from_utf8(pt).map_err(|e| format!("decrypted payload is not valid UTF-8: {e}"))
}

pub(crate) fn aes_gcm_seal_raw(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let mut rk = aes256_expand_key(key);
    let h = u128::from_be_bytes(aes256_encrypt_block(&rk, &[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;

    let mut ctr0 = j0;
    inc32(&mut ctr0);
    let ct = gctr(&rk, ctr0, plaintext);
    let gh = ghash(h, aad, &ct);
    let e_j0 = aes256_encrypt_block(&rk, &j0);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = gh[i] ^ e_j0[i];
    }
    for round in &mut rk {
        zeroize_bytes(round);
    }
    (ct, tag)
}

pub(crate) fn aes_gcm_open_raw(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, String> {
    let mut rk = aes256_expand_key(key);
    let h = u128::from_be_bytes(aes256_encrypt_block(&rk, &[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;

    let gh = ghash(h, aad, ciphertext);
    let e_j0 = aes256_encrypt_block(&rk, &j0);
    let mut expected_tag = [0u8; 16];
    for i in 0..16 {
        expected_tag[i] = gh[i] ^ e_j0[i];
    }
    if !constant_time_bytes_equal(&expected_tag, tag) {
        for round in &mut rk {
            zeroize_bytes(round);
        }
        return Err("decryption failed: authentication tag mismatch".into());
    }
    let mut ctr0 = j0;
    inc32(&mut ctr0);
    let pt = gctr(&rk, ctr0, ciphertext);
    for round in &mut rk {
        zeroize_bytes(round);
    }
    Ok(pt)
}

pub(crate) fn aes_gcm_encrypt_token(
    secret: &str,
    plaintext: &str,
    aad: &[u8],
) -> Result<String, String> {
    seal_salted_aead_token("v2", PBKDF2_AES_DOMAIN, secret, plaintext, |key, iv, pt| {
        aes_gcm_seal_raw(key, iv, aad, pt)
    })
}

pub(crate) fn aes_gcm_decrypt_token(
    secret: &str,
    token: &str,
    aad: &[u8],
) -> Result<String, String> {
    open_salted_aead_token(
        "v2",
        "AES-GCM",
        PBKDF2_AES_DOMAIN,
        secret,
        token,
        |key, iv, ct, tag| aes_gcm_open_raw(key, iv, aad, ct, tag),
    )
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) & Pure-Rust ChaCha20-Poly1305 (RFC 8439)
// ---------------------------------------------------------------------------

const PBKDF2_CHACHA_DOMAIN: &[u8] = b"kovrek-chacha20-poly1305-v1\0";

pub(crate) fn hkdf_sha256_bytes(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, String> {
    if out_len == 0 || out_len > 255 * 32 {
        return Err("hkdf_sha256 length must be between 1 and 8160 bytes".into());
    }
    let effective_salt = if salt.is_empty() {
        vec![0u8; 32]
    } else {
        salt.to_vec()
    };
    let mut prk = hmac_sha256_bytes(&effective_salt, ikm);
    let blocks = out_len.div_ceil(32);
    let mut okm = Vec::with_capacity(blocks * 32);
    let mut prev: Vec<u8> = Vec::new();
    for counter in 1..=blocks {
        let mut msg = Vec::with_capacity(prev.len() + info.len() + 1);
        msg.extend_from_slice(&prev);
        msg.extend_from_slice(info);
        msg.push(counter as u8);
        let next = hmac_sha256_bytes(&prk, &msg);
        zeroize_bytes(&mut msg);
        okm.extend_from_slice(&next);
        zeroize_bytes(&mut prev);
        prev = next;
    }
    zeroize_bytes(&mut prev);
    zeroize_bytes(&mut prk);
    okm.truncate(out_len);
    Ok(okm)
}

pub(crate) fn hkdf_sha256_hex(
    ikm: &str,
    salt: &str,
    info: &str,
    out_len: usize,
) -> Result<String, String> {
    let mut okm = hkdf_sha256_bytes(ikm.as_bytes(), salt.as_bytes(), info.as_bytes(), out_len)?;
    let hex = bytes_to_hex(&okm);
    zeroize_bytes(&mut okm);
    Ok(hex)
}

#[inline(always)]
fn chacha_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut initial = [0u32; 16];
    initial[0] = 0x6170_7865;
    initial[1] = 0x3320_646e;
    initial[2] = 0x7962_2d32;
    initial[3] = 0x6b20_6574;
    for i in 0..8 {
        initial[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    initial[12] = counter;
    for i in 0..3 {
        initial[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    let mut working = initial;
    for _ in 0..10 {
        chacha_quarter_round(&mut working, 0, 4, 8, 12);
        chacha_quarter_round(&mut working, 1, 5, 9, 13);
        chacha_quarter_round(&mut working, 2, 6, 10, 14);
        chacha_quarter_round(&mut working, 3, 7, 11, 15);
        chacha_quarter_round(&mut working, 0, 5, 10, 15);
        chacha_quarter_round(&mut working, 1, 6, 11, 12);
        chacha_quarter_round(&mut working, 2, 7, 8, 13);
        chacha_quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(initial[i]).to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&word);
    }
    out
}

fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (idx, chunk) in input.chunks(64).enumerate() {
        let mut ks = chacha20_block(key, counter.wrapping_add(idx as u32), nonce);
        for (i, &byte) in chunk.iter().enumerate() {
            out.push(byte ^ ks[i]);
        }
        zeroize_bytes(&mut ks);
    }
    out
}

fn poly1305_key_gen(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut block = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block[..32]);
    zeroize_bytes(&mut block);
    otk
}

fn poly1305_extract_limbs(b: &[u8; 17]) -> [u64; 5] {
    [
        u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])) & 0x3ff_ffff,
        (u64::from(u32::from_le_bytes([b[3], b[4], b[5], b[6]])) >> 2) & 0x3ff_ffff,
        (u64::from(u32::from_le_bytes([b[6], b[7], b[8], b[9]])) >> 4) & 0x3ff_ffff,
        (u64::from(u32::from_le_bytes([b[9], b[10], b[11], b[12]])) >> 6) & 0x3ff_ffff,
        (u64::from(u32::from_le_bytes([b[12], b[13], b[14], b[15]])) >> 8)
            | (u64::from(b[16]) << 24),
    ]
}

fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut r_bytes = [0u8; 17];
    r_bytes[..16].copy_from_slice(&key[..16]);
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;

    let [r0, r1, r2, r3, r4] = poly1305_extract_limbs(&r_bytes);
    zeroize_bytes(&mut r_bytes);

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for chunk in msg.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;
        let [m0, m1, m2, m3, m4] = poly1305_extract_limbs(&block);
        h0 += m0;
        h1 += m1;
        h2 += m2;
        h3 += m3;
        h4 += m4;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        h0 = d0 & 0x3ff_ffff;
        d1 += c;
        c = d1 >> 26;
        h1 = d1 & 0x3ff_ffff;
        d2 += c;
        c = d2 >> 26;
        h2 = d2 & 0x3ff_ffff;
        d3 += c;
        c = d3 >> 26;
        h3 = d3 & 0x3ff_ffff;
        d4 += c;
        c = d4 >> 26;
        h4 = d4 & 0x3ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;
    }

    let mut c = h1 >> 26;
    h1 &= 0x3ff_ffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ff_ffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ff_ffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ff_ffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ff_ffff;
    h1 += c;

    // Constant-time conditional reduction modulo 2^130 - 5.
    let mut g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ff_ffff;
    let mut g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ff_ffff;
    let mut g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ff_ffff;
    let mut g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ff_ffff;
    let g4_sum = h4 + c;
    let mask = 0u64.wrapping_sub(g4_sum >> 26);
    let g4 = g4_sum & 0x3ff_ffff;

    h0 = (h0 & !mask) | (g0 & mask);
    h1 = (h1 & !mask) | (g1 & mask);
    h2 = (h2 & !mask) | (g2 & mask);
    h3 = (h3 & !mask) | (g3 & mask);
    h4 = (h4 & !mask) | (g4 & mask);

    let mut w0 = (h0 | (h1 << 26)) & 0xffff_ffff;
    let mut w1 = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
    let mut w2 = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
    let mut w3 = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;

    w0 += u64::from(u32::from_le_bytes([key[16], key[17], key[18], key[19]]));
    w1 += u64::from(u32::from_le_bytes([key[20], key[21], key[22], key[23]])) + (w0 >> 32);
    w0 &= 0xffff_ffff;
    w2 += u64::from(u32::from_le_bytes([key[24], key[25], key[26], key[27]])) + (w1 >> 32);
    w1 &= 0xffff_ffff;
    w3 += u64::from(u32::from_le_bytes([key[28], key[29], key[30], key[31]])) + (w2 >> 32);
    w2 &= 0xffff_ffff;
    w3 &= 0xffff_ffff;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&(w0 as u32).to_le_bytes());
    tag[4..8].copy_from_slice(&(w1 as u32).to_le_bytes());
    tag[8..12].copy_from_slice(&(w2 as u32).to_le_bytes());
    tag[12..16].copy_from_slice(&(w3 as u32).to_le_bytes());
    tag
}

fn poly1305_aead_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    let mut mac_data = Vec::with_capacity(aad.len() + aad_pad + ciphertext.len() + ct_pad + 16);
    mac_data.extend_from_slice(aad);
    mac_data.resize(mac_data.len() + aad_pad, 0);
    mac_data.extend_from_slice(ciphertext);
    mac_data.resize(mac_data.len() + ct_pad, 0);
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305_mac(otk, &mac_data)
}

pub(crate) fn chacha20_poly1305_seal_raw(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let mut otk = poly1305_key_gen(key, nonce);
    let ct = chacha20_xor(key, 1, nonce, plaintext);
    let tag = poly1305_aead_tag(&otk, aad, &ct);
    zeroize_bytes(&mut otk);
    (ct, tag)
}

pub(crate) fn chacha20_poly1305_open_raw(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, String> {
    let mut otk = poly1305_key_gen(key, nonce);
    let expected_tag = poly1305_aead_tag(&otk, aad, ciphertext);
    zeroize_bytes(&mut otk);
    if !constant_time_bytes_equal(&expected_tag, tag) {
        return Err("decryption failed: authentication tag mismatch".into());
    }
    Ok(chacha20_xor(key, 1, nonce, ciphertext))
}

pub(crate) fn chacha20_poly1305_encrypt_token(
    secret: &str,
    plaintext: &str,
    aad: &[u8],
) -> Result<String, String> {
    seal_salted_aead_token(
        "cc20p1305",
        PBKDF2_CHACHA_DOMAIN,
        secret,
        plaintext,
        |key, nonce, pt| chacha20_poly1305_seal_raw(key, nonce, aad, pt),
    )
}

pub(crate) fn chacha20_poly1305_decrypt_token(
    secret: &str,
    token: &str,
    aad: &[u8],
) -> Result<String, String> {
    open_salted_aead_token(
        "cc20p1305",
        "ChaCha20-Poly1305",
        PBKDF2_CHACHA_DOMAIN,
        secret,
        token,
        |key, nonce, ct, tag| chacha20_poly1305_open_raw(key, nonce, aad, ct, tag),
    )
}

// ---------------------------------------------------------------------------
// Outbound SSRF Protection (IPv4 / IPv6 + URL + DNS Resolution)
// ---------------------------------------------------------------------------

pub(crate) fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 0
        || o[0] == 10
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (18..=19).contains(&o[1]))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 224
}

pub(crate) fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return true;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(v4);
    }
    let seg = ip.segments();
    // Deprecated IPv4-compatible ::/96 and SIIT IPv4-translated ::ffff:0:0:0/96
    if seg[..6] == [0, 0, 0, 0, 0, 0] || seg[..6] == [0, 0, 0, 0, 0xffff, 0] {
        return is_private_ipv4(Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
    }
    // Discard-only 100::/64 (RFC 6666)
    if seg[..4] == [0x0100, 0, 0, 0] {
        return true;
    }
    // NAT64 well-known 64:ff9b::/96 or local-use 64:ff9b:1::/48
    if seg[0] == 0x0064 && seg[1] == 0xff9b {
        if seg[2] == 1 {
            return true;
        }
        if seg[2..6] == [0, 0, 0, 0] {
            return is_private_ipv4(Ipv4Addr::new(
                (seg[6] >> 8) as u8,
                (seg[6] & 0xff) as u8,
                (seg[7] >> 8) as u8,
                (seg[7] & 0xff) as u8,
            ));
        }
    }
    // Deprecated 6to4 (2002::/16) and Teredo (2001::/32) tunneling prefixes
    if seg[0] == 0x2002 || (seg[0] == 0x2001 && seg[1] == 0) {
        return true;
    }
    // Benchmarking (2001:2::/48), ORCHIDv1/v2 (2001:10::/28, 2001:20::/28),
    // documentation (2001:db8::/32, 3fff::/20), ULA (fc00::/7), link-local (fe80::/10),
    // and deprecated site-local (fec0::/10).
    (seg[0] & 0xfe00) == 0xfc00
        || (seg[0] & 0xffc0) == 0xfe80
        || (seg[0] & 0xffc0) == 0xfec0
        || (seg[0] == 0x2001
            && ((seg[1] == 0x0002 && seg[2] == 0)
                || (seg[1] & 0xfff0) == 0x0010
                || (seg[1] & 0xfff0) == 0x0020
                || seg[1] == 0x0db8))
        || (seg[0] == 0x3fff && (seg[1] & 0xf000) == 0)
}

pub(crate) fn is_private_ip_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

pub(crate) fn is_private_ip_str(raw: &str) -> bool {
    let mut s = raw.trim();
    if let Some(stripped) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        s = stripped;
    }
    if let Some((addr, _zone)) = s.split_once('%') {
        s = addr;
    }
    let Ok(ip) = s.parse::<IpAddr>() else {
        return false;
    };
    is_private_ip_addr(ip)
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedPublicUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub origin: String,
    pub url: String,
}

fn parse_aton_part(part: &str) -> Option<u32> {
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    if part.len() > 1 && part.starts_with('0') && part.bytes().all(|b| matches!(b, b'0'..=b'7')) {
        return u32::from_str_radix(&part[1..], 8).ok();
    }
    part.parse::<u32>().ok()
}

fn parse_numeric_ipv4_obfuscation(host: &str) -> Option<Ipv4Addr> {
    if host.is_empty() {
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut nums = Vec::with_capacity(parts.len());
    for p in parts {
        if p.is_empty() {
            return None;
        }
        nums.push(parse_aton_part(p)?);
    }
    let val = match nums.as_slice() {
        [a] => *a,
        [a, b] if *a <= 0xff && *b <= 0x00ff_ffff => (a << 24) | b,
        [a, b, c] if *a <= 0xff && *b <= 0xff && *c <= 0xffff => (a << 24) | (b << 16) | c,
        [a, b, c, d] if *a <= 0xff && *b <= 0xff && *c <= 0xff && *d <= 0xff => {
            (a << 24) | (b << 16) | (c << 8) | d
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(val))
}

fn parse_http_url_parts(raw_url: &str, allow_http: bool) -> Result<ValidatedPublicUrl, String> {
    let trimmed = raw_url.trim();
    if trimmed.len() > 8192 {
        return Err("invalid URL: exceeds 8192 byte limit".into());
    }
    if trimmed.bytes().any(|b| b.is_ascii_control()) {
        return Err("invalid URL: control characters are not allowed".into());
    }
    let (scheme_raw, rest) = trimmed
        .split_once("://")
        .ok_or_else(|| "invalid URL: missing scheme".to_string())?;
    let scheme = scheme_raw.to_ascii_lowercase();
    match scheme.as_str() {
        "https" => {}
        "http" if allow_http => {}
        "http" => return Err("unsafe URL blocked: https required".into()),
        _ => return Err(format!("invalid URL scheme '{scheme}'")),
    }
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    if authority.is_empty() {
        return Err("invalid URL: missing host".into());
    }
    if authority.bytes().any(|b| b.is_ascii_whitespace()) || !authority.is_ascii() {
        return Err("invalid URL authority characters".into());
    }
    if authority.contains(['@', '\\']) {
        return Err("URL credentials or unsafe authority characters are not allowed".into());
    }

    let (host_raw, port) = if let Some(after_open) = authority.strip_prefix('[') {
        let close_idx = after_open
            .find(']')
            .ok_or_else(|| "invalid IPv6 URL host".to_string())?;
        let ip_part = &after_open[..close_idx];
        let rem = &after_open[close_idx + 1..];
        let port = if rem.is_empty() {
            if scheme == "https" { 443 } else { 80 }
        } else if let Some(port_str) = rem.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .ok()
                .filter(|&p| p > 0)
                .ok_or_else(|| "invalid URL port".to_string())?
        } else {
            return Err("invalid IPv6 authority".into());
        };
        (ip_part, port)
    } else if let Some((h, p_str)) = authority.rsplit_once(':') {
        let port = p_str
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .ok_or_else(|| "invalid URL port".to_string())?;
        (h, port)
    } else {
        (authority, if scheme == "https" { 443 } else { 80 })
    };

    let host_norm = host_raw.trim_end_matches('.').to_ascii_lowercase();
    if host_norm.is_empty() {
        return Err("invalid URL: empty host".into());
    }
    let authority_canonical = if host_norm.contains(':') {
        format!("[{host_norm}]")
    } else {
        host_norm.clone()
    };
    let default_port = if scheme == "https" { 443 } else { 80 };
    let origin = if port == default_port {
        format!("{scheme}://{authority_canonical}")
    } else {
        format!("{scheme}://{authority_canonical}:{port}")
    };
    Ok(ValidatedPublicUrl {
        scheme,
        host: host_norm,
        port,
        origin,
        url: trimmed.to_string(),
    })
}

#[cfg_attr(not(feature = "native-services"), allow(dead_code))]
fn is_metadata_or_unspecified_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_unspecified() || mapped.is_link_local();
            }
            v6.is_unspecified()
                || v6.is_unicast_link_local()
                || (v6.segments()[0] == 0xfd00 && v6.segments()[1] == 0x0ec2)
        }
    }
}

#[cfg_attr(not(feature = "native-services"), allow(dead_code))]
pub(crate) fn validate_general_http_url(raw_url: &str) -> Result<ValidatedPublicUrl, String> {
    let parsed = parse_http_url_parts(raw_url, true)?;
    let host = &parsed.host;
    if host == "metadata.google.internal" || host == "metadata.goog" {
        return Err(format!("unsafe metadata host '{host}' is blocked"));
    }
    let ip_candidate = host.split_once('%').map(|(a, _)| a).unwrap_or(host);
    if let Ok(ip) = ip_candidate.parse::<IpAddr>()
        && is_metadata_or_unspecified_ip(ip)
    {
        return Err(format!("unsafe link-local/metadata IP '{host}' is blocked"));
    }
    if let Some(obf_v4) = parse_numeric_ipv4_obfuscation(host)
        && (obf_v4.is_unspecified() || obf_v4.is_link_local())
    {
        return Err(format!(
            "unsafe link-local/metadata IP '{obf_v4}' is blocked"
        ));
    }
    Ok(parsed)
}

pub(crate) fn validate_public_url(
    raw_url: &str,
    allow_http: bool,
) -> Result<ValidatedPublicUrl, String> {
    let parsed = parse_http_url_parts(raw_url, allow_http)?;
    let host_norm = &parsed.host;
    if host_norm == "localhost"
        || host_norm.ends_with(".localhost")
        || host_norm.ends_with(".local")
        || host_norm.ends_with(".internal")
        || host_norm.ends_with(".home.arpa")
    {
        return Err(format!("unsafe target host '{host_norm}' is blocked"));
    }
    let ip_candidate = host_norm
        .split_once('%')
        .map(|(a, _)| a)
        .unwrap_or(host_norm);
    if let Ok(ip) = ip_candidate.parse::<IpAddr>()
        && is_private_ip_addr(ip)
    {
        return Err(format!("unsafe target IP '{host_norm}' is blocked"));
    }
    if let Some(obf_v4) = parse_numeric_ipv4_obfuscation(host_norm)
        && is_private_ipv4(obf_v4)
    {
        return Err(format!("unsafe target IP '{obf_v4}' is blocked"));
    }
    Ok(parsed)
}

pub(crate) fn resolve_public_url_addrs(
    url: &ValidatedPublicUrl,
) -> Result<Vec<SocketAddr>, String> {
    let clean_host = url
        .host
        .split_once('%')
        .map(|(a, _)| a)
        .unwrap_or(&url.host);
    let addrs: Vec<SocketAddr> = (clean_host, url.port)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve host '{}': {e}", url.host))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("no DNS records found for '{}'", url.host));
    }
    for addr in &addrs {
        if is_private_ip_addr(addr.ip()) {
            return Err(format!(
                "unsafe DNS resolution for '{}' -> '{}' blocked",
                url.host,
                addr.ip()
            ));
        }
    }
    Ok(addrs)
}

#[cfg_attr(not(feature = "native-services"), allow(dead_code))]
fn is_http_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

#[cfg_attr(not(feature = "native-services"), allow(dead_code))]
pub(crate) fn validate_http_header_pair(
    name: &str,
    value: &str,
    allow_host: bool,
) -> Result<(), String> {
    if name.is_empty() || name.len() > 256 || !name.bytes().all(is_http_tchar) {
        return Err(format!("invalid HTTP header name '{name}'"));
    }
    if !allow_host
        && (name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(format!("restricted HTTP header '{name}' is not allowed"));
    }
    if value.len() > 16 * 1024 || value.bytes().any(|b| b != b'\t' && (b < 0x20 || b == 0x7f)) {
        return Err(format!(
            "invalid HTTP header value for '{name}': control characters or length overflow"
        ));
    }
    Ok(())
}

#[cfg_attr(not(feature = "native-services"), allow(dead_code))]
pub(crate) fn read_to_end_limited<R: std::io::Read>(
    reader: R,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut limited = std::io::Read::take(reader, (max_bytes as u64).saturating_add(1));
    std::io::Read::read_to_end(&mut limited, &mut buf).map_err(|e| e.to_string())?;
    if buf.len() > max_bytes {
        return Err(format!("{label} exceeded {max_bytes} byte limit"));
    }
    Ok(buf)
}

include!("shared_bounds.rs");

#[cfg_attr(not(feature = "native-services"), allow(dead_code))]
pub(crate) fn resolve_redirect_location(
    base_url: &str,
    origin: &str,
    location: &str,
) -> Result<String, String> {
    let loc = location.trim();
    if loc.bytes().any(|b| b.is_ascii_control()) {
        return Err("redirect location contains invalid control characters".into());
    }
    if loc
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
        || loc
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
    {
        return Ok(loc.to_string());
    }
    if loc.starts_with("//") {
        let scheme = base_url
            .split_once("://")
            .map(|(s, _)| s)
            .unwrap_or("https");
        return Ok(format!("{scheme}:{loc}"));
    }
    if loc.starts_with('/') {
        return Ok(format!("{origin}{loc}"));
    }
    Err("relative redirect without leading '/' blocked".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_sbox_ct_is_bijective_and_matches_fips_197() {
        let mut seen = [false; 256];
        for x in 0u8..=255 {
            let y = aes_sbox_ct(x);
            assert!(!seen[y as usize], "duplicate S-box output at 0x{x:02x}");
            seen[y as usize] = true;
        }
        assert_eq!(aes_sbox_ct(0x00), 0x63);
        assert_eq!(aes_sbox_ct(0x01), 0x7c);
        assert_eq!(aes_sbox_ct(0x53), 0xed);
        assert_eq!(aes_sbox_ct(0xff), 0x16);

        // FIPS-197 Appendix C.3 AES-256 ECB exact known-answer vector
        let key: [u8; 32] =
            hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .try_into()
                .unwrap();
        let pt: [u8; 16] = hex_to_bytes("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        let rk = aes256_expand_key(&key);
        let ct = aes256_encrypt_block(&rk, &pt);
        assert_eq!(bytes_to_hex(&ct), "8ea2b7ca516745bfeafc49904b496089");
    }

    #[test]
    fn aes_256_gcm_nist_vector_and_token_roundtrip() {
        // NIST SP 800-38D Test Case 14 (256-bit key, 96-bit IV, 128-bit PT, empty AAD)
        let key: [u8; 32] =
            hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .try_into()
                .unwrap();
        let iv: [u8; 12] = hex_to_bytes("000000000000000000000000")
            .unwrap()
            .try_into()
            .unwrap();
        let pt = hex_to_bytes("00000000000000000000000000000000").unwrap();
        let (ct, tag) = aes_gcm_seal_raw(&key, &iv, &[], &pt);
        assert_eq!(bytes_to_hex(&ct), "cea7403d4d606b6e074ec5d3baf39d18");
        assert_eq!(bytes_to_hex(&tag), "d0d1c8a799996bf0265b98b5d48ab919");
        let dec = aes_gcm_open_raw(&key, &iv, &[], &ct, &tag).unwrap();
        assert_eq!(dec, pt);

        // Salted PBKDF2 v2 token roundtrip, per-encryption uniqueness, and tamper/downgrade rejection
        let tok =
            aes_gcm_encrypt_token("super-secret-master-key", "kovrek-mfa-secret", b"ctx").unwrap();
        let tok2 =
            aes_gcm_encrypt_token("super-secret-master-key", "kovrek-mfa-secret", b"ctx").unwrap();
        assert!(tok.starts_with("v2:"));
        assert_ne!(
            tok, tok2,
            "distinct CSPRNG salts and IVs must produce distinct ciphertexts"
        );
        assert_eq!(
            aes_gcm_decrypt_token("super-secret-master-key", &tok, b"ctx").unwrap(),
            "kovrek-mfa-secret"
        );
        assert!(aes_gcm_decrypt_token("wrong-key", &tok, b"ctx").is_err());
        assert!(aes_gcm_decrypt_token("super-secret-master-key", &tok, b"wrong-ctx").is_err());
        let last_flip = if tok.ends_with('0') { '1' } else { '0' };
        let tampered = format!("{}{last_flip}", &tok[..tok.len() - 1]);
        assert!(aes_gcm_decrypt_token("super-secret-master-key", &tampered, b"ctx").is_err());
        // Legacy unsalted 3-part tokens must be rejected
        assert!(aes_gcm_decrypt_token(
            "super-secret-master-key",
            "000000000000000000000000:d0d1c8a799996bf0265b98b5d48ab919:cea7403d4d606b6e074ec5d3baf39d18",
            b"ctx"
        ).is_err());
    }

    #[test]
    fn base32_hmac_sha1_and_totp_rfc_vectors() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("mzxw6ytboi======").unwrap(), b"foobar");

        // RFC 6238 SHA-1 Appendix B vector (secret = "12345678901234567890", T=59s -> 94287082, 6 digits = 287082)
        let secret_b32 = base32_encode(b"12345678901234567890");
        assert_eq!(totp_code_at(&secret_b32, 59, 8, 30).unwrap(), "94287082");
        let code6 = totp_code_at(&secret_b32, 59, 6, 30).unwrap();
        assert_eq!(code6, "287082");
        assert!(verify_totp_at(&secret_b32, &code6, 60, 1));
        assert!(!verify_totp_at(&secret_b32, "000000", 60, 1));
    }

    #[test]
    fn ssrf_blocks_private_ips_and_obfuscated_urls() {
        for priv_ip in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.10",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1%lo0",
            "fc00::1",
            "[::ffff:127.0.0.1]",
            "::ffff:169.254.169.254",
            "::ffff:0:127.0.0.1",
            "192.88.99.1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "2001:20::1",
            "2002:0808:0808::1",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::1",
            "3fff::1",
        ] {
            assert!(
                is_private_ip_str(priv_ip),
                "expected private IP for {priv_ip}"
            );
        }
        assert!(!is_private_ip_str("8.8.8.8"));
        assert!(!is_private_ip_str("2606:4700:4700::1111"));

        assert!(validate_public_url("http://localhost:8080/hook", true).is_err());
        assert!(validate_public_url("https://user:pass@example.com/hook", true).is_err());
        assert!(validate_public_url("file:///etc/passwd", true).is_err());
        assert!(validate_public_url("http://169.254.169.254/latest/meta-data", true).is_err());
        assert!(validate_public_url("http://2130706433/admin", true).is_err());
        assert!(validate_public_url("http://0x7f000001/admin", true).is_err());
        assert!(validate_public_url("http://0177.0.0.1/admin", true).is_err());
        assert!(validate_public_url("http://127.1/admin", true).is_err());
        assert!(validate_public_url("http://evil.com\\@127.0.0.1/admin", true).is_err());
        assert!(validate_public_url("http://[::ffff:127.0.0.1]/admin", true).is_err());
        assert!(validate_public_url("https://[2001::1]/admin", true).is_err());
        assert!(validate_public_url("https://[64:ff9b::169.254.169.254]/", true).is_err());
        assert!(validate_public_url("https://example.com\r\nHost: evil", true).is_err());
        assert!(validate_public_url("https://ex ample.com/hook", true).is_err());
        assert!(validate_public_url("https://évil.com/hook", true).is_err());
        assert!(validate_public_url("http://example.com/hook", false).is_err());
        let ok = validate_public_url("https://example.com/webhooks/helm", false).unwrap();
        assert_eq!(ok.origin, "https://example.com");
    }

    #[test]
    fn hkdf_sha256_rfc5869_vectors() {
        // RFC 5869 Appendix A.1 (basic test case)
        let ikm1 = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt1 = hex_to_bytes("000102030405060708090a0b0c").unwrap();
        let info1 = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm1 = hkdf_sha256_bytes(&ikm1, &salt1, &info1, 42).unwrap();
        assert_eq!(
            bytes_to_hex(&okm1),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        // RFC 5869 Appendix A.3 (empty salt and empty info)
        let ikm3 = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let okm3 = hkdf_sha256_bytes(&ikm3, &[], &[], 42).unwrap();
        assert_eq!(
            bytes_to_hex(&okm3),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );

        assert!(hkdf_sha256_bytes(&ikm3, &[], &[], 0).is_err());
        assert!(hkdf_sha256_bytes(&ikm3, &[], &[], 8161).is_err());
    }

    #[test]
    fn chacha20_poly1305_rfc8439_vectors_and_token_tamper_checks() {
        // RFC 8439 Section 2.8.2 AEAD official test vector
        let key: [u8; 32] =
            hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = hex_to_bytes("070000004041424344454647")
            .unwrap()
            .try_into()
            .unwrap();
        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let (ct, tag) = chacha20_poly1305_seal_raw(&key, &nonce, &aad, pt);
        assert_eq!(
            bytes_to_hex(&ct),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(bytes_to_hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");
        let opened = chacha20_poly1305_open_raw(&key, &nonce, &aad, &ct, &tag).unwrap();
        assert_eq!(opened, pt);

        // Salted PBKDF2 cc20p1305 token roundtrip & tamper/AAD/cross-cipher checks
        let tok =
            chacha20_poly1305_encrypt_token("vault-master", "secret-doc-payload", b"hdr").unwrap();
        let tok2 =
            chacha20_poly1305_encrypt_token("vault-master", "secret-doc-payload", b"hdr").unwrap();
        assert!(tok.starts_with("cc20p1305:"));
        assert_ne!(tok, tok2);
        assert_eq!(
            chacha20_poly1305_decrypt_token("vault-master", &tok, b"hdr").unwrap(),
            "secret-doc-payload"
        );
        assert!(chacha20_poly1305_decrypt_token("wrong-master", &tok, b"hdr").is_err());
        assert!(chacha20_poly1305_decrypt_token("vault-master", &tok, b"bad-hdr").is_err());
        let last_flip = if tok.ends_with('0') { '1' } else { '0' };
        let tampered = format!("{}{last_flip}", &tok[..tok.len() - 1]);
        assert!(chacha20_poly1305_decrypt_token("vault-master", &tampered, b"hdr").is_err());
        // Cross-cipher token downgrade/confusion must fail cleanly
        assert!(aes_gcm_decrypt_token("vault-master", &tok, b"hdr").is_err());
    }
}
