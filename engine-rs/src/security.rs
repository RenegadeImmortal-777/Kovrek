//! Security primitives: CSPRNG tokens, HTML escaping, Base32/TOTP (RFC 6238),
//! pure-Rust AES-256-GCM authenticated encryption, and SSRF URL/IP validation.
#![allow(clippy::needless_range_loop)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::value::constant_time_strings_equal;

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
    let max_win = window.min(10) as i64;
    let base_step = (timestamp_secs / 30) as i64;
    for delta in -max_win..=max_win {
        let step_secs = ((base_step + delta).max(0) as u64) * 30;
        if let Ok(expected) = totp_code_at(secret_b32, step_secs, 6, 30)
            && constant_time_strings_equal(&expected, trimmed)
        {
            return true;
        }
    }
    false
}

pub(crate) fn totp_code_now(secret_b32: &str) -> Result<String, String> {
    totp_code_at(secret_b32, unix_now_secs(), 6, 30)
}

pub(crate) fn verify_totp_now(secret_b32: &str, code: &str, window: u32) -> bool {
    verify_totp_at(secret_b32, code, unix_now_secs(), window)
}

// ---------------------------------------------------------------------------
// Pure-Rust AES-256-GCM (NIST FIPS 197 + SP 800-38D)
// ---------------------------------------------------------------------------

#[rustfmt::skip]
const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const RCON: [u8; 8] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

fn aes256_expand_key(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut w = [[0u8; 4]; 60];
    for i in 0..8 {
        w[i] = [key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]];
    }
    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = [
                AES_SBOX[temp[1] as usize] ^ RCON[i / 8],
                AES_SBOX[temp[2] as usize],
                AES_SBOX[temp[3] as usize],
                AES_SBOX[temp[0] as usize],
            ];
        } else if i % 8 == 4 {
            temp = [
                AES_SBOX[temp[0] as usize],
                AES_SBOX[temp[1] as usize],
                AES_SBOX[temp[2] as usize],
                AES_SBOX[temp[3] as usize],
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
    rk
}

#[inline]
fn xtime(a: u8) -> u8 {
    (a << 1) ^ (((a >> 7) & 1) * 0x1b)
}

fn aes256_encrypt_block(rk: &[[u8; 16]; 15], input: &[u8; 16]) -> [u8; 16] {
    let mut s = *input;
    for i in 0..16 {
        s[i] ^= rk[0][i];
    }
    for round in 1..=14 {
        for b in &mut s {
            *b = AES_SBOX[*b as usize];
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

fn ghash_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        if ((x >> (127 - i)) & 1) == 1 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb == 1 {
            v ^= R;
        }
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

fn derive_aes256_key(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

pub(crate) fn aes_gcm_seal_raw(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let rk = aes256_expand_key(key);
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
    (ct, tag)
}

pub(crate) fn aes_gcm_open_raw(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, String> {
    let rk = aes256_expand_key(key);
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
        return Err("decryption failed: authentication tag mismatch".into());
    }
    let mut ctr0 = j0;
    inc32(&mut ctr0);
    Ok(gctr(&rk, ctr0, ciphertext))
}

pub(crate) fn aes_gcm_encrypt_token(
    secret: &str,
    plaintext: &str,
    aad: &[u8],
) -> Result<String, String> {
    if secret.is_empty() {
        return Err("encryption key must not be empty".into());
    }
    let key = derive_aes256_key(secret);
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let (ct, tag) = aes_gcm_seal_raw(&key, &iv, aad, plaintext.as_bytes());
    Ok(format!(
        "{}:{}:{}",
        bytes_to_hex(&iv),
        bytes_to_hex(&tag),
        bytes_to_hex(&ct)
    ))
}

pub(crate) fn aes_gcm_decrypt_token(
    secret: &str,
    token: &str,
    aad: &[u8],
) -> Result<String, String> {
    if secret.is_empty() {
        return Err("decryption key must not be empty".into());
    }
    let parts: Vec<&str> = token.trim().split(':').collect();
    if parts.len() != 3 {
        return Err("invalid encrypted payload format (expected iv:tag:ciphertext)".into());
    }
    let iv_vec = hex_to_bytes(parts[0])?;
    let tag_vec = hex_to_bytes(parts[1])?;
    let ct = hex_to_bytes(parts[2])?;
    let iv: [u8; 12] = iv_vec
        .try_into()
        .map_err(|_| "invalid AES-GCM IV length (expected 12 bytes)".to_string())?;
    let tag: [u8; 16] = tag_vec
        .try_into()
        .map_err(|_| "invalid AES-GCM tag length (expected 16 bytes)".to_string())?;
    let key = derive_aes256_key(secret);
    let pt = aes_gcm_open_raw(&key, &iv, aad, &ct, &tag)?;
    String::from_utf8(pt).map_err(|e| format!("decrypted payload is not valid UTF-8: {e}"))
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
    // Deprecated IPv4-compatible ::/96
    if seg[..6] == [0, 0, 0, 0, 0, 0] {
        return is_private_ipv4(Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
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
    // 6to4 (2002::/16) carrying embedded IPv4
    if seg[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            (seg[1] & 0xff) as u8,
            (seg[2] >> 8) as u8,
            (seg[2] & 0xff) as u8,
        );
        if is_private_ipv4(embedded) {
            return true;
        }
    }
    // ULA fc00::/7, link-local fe80::/10, deprecated site-local fec0::/10, doc 2001:db8::/32
    (seg[0] & 0xfe00) == 0xfc00
        || (seg[0] & 0xffc0) == 0xfe80
        || (seg[0] & 0xffc0) == 0xfec0
        || (seg[0] == 0x2001 && seg[1] == 0x0db8)
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

pub(crate) fn validate_public_url(
    raw_url: &str,
    allow_http: bool,
) -> Result<ValidatedPublicUrl, String> {
    let trimmed = raw_url.trim();
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
        .unwrap_or(&host_norm);
    if let Ok(ip) = ip_candidate.parse::<IpAddr>()
        && is_private_ip_addr(ip)
    {
        return Err(format!("unsafe target IP '{host_norm}' is blocked"));
    }
    if let Some(obf_v4) = parse_numeric_ipv4_obfuscation(&host_norm)
        && is_private_ipv4(obf_v4)
    {
        return Err(format!("unsafe target IP '{obf_v4}' is blocked"));
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

#[cfg(test)]
mod tests {
    use super::*;

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

        // Token roundtrip + tamper rejection
        let tok =
            aes_gcm_encrypt_token("super-secret-master-key", "kovrek-mfa-secret", b"ctx").unwrap();
        assert_eq!(
            aes_gcm_decrypt_token("super-secret-master-key", &tok, b"ctx").unwrap(),
            "kovrek-mfa-secret"
        );
        assert!(aes_gcm_decrypt_token("wrong-key", &tok, b"ctx").is_err());
        assert!(aes_gcm_decrypt_token("super-secret-master-key", &tok, b"wrong-ctx").is_err());
        let tampered = format!("{}0", &tok[..tok.len() - 1]);
        assert!(aes_gcm_decrypt_token("super-secret-master-key", &tampered, b"ctx").is_err());
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
        assert!(validate_public_url("http://example.com/hook", false).is_err());
        let ok = validate_public_url("https://example.com/webhooks/helm", false).unwrap();
        assert_eq!(ok.origin, "https://example.com");
    }
}
