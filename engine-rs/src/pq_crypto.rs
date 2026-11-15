//! Post-Quantum, Memory-Hard KDF, & Multi-Hash Cryptographic Core:
//! - FIPS 202: Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128, SHAKE256, NIST SP 800-185 KMAC256
//! - HKDF-SHA512 (RFC 5869 over SHA-512)
//! - RFC 7693 Blake2b + RFC 9106 Argon2id (memory-hard password derivation)
//! - RFC 7748 Constant-Time X25519 Elliptic Curve Diffie-Hellman
//! - NIST FIPS 203 ML-KEM-1024 (Category 5 Post-Quantum Lattice KEM)
//! - Sovereign PQ Hybrid Combiner (ML-KEM-1024 + X25519 -> HKDF-SHA512 XOR KMAC256)

#![allow(clippy::needless_range_loop)]

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

use crate::security::{bytes_to_hex, constant_time_bytes_equal, hex_to_bytes, zeroize_bytes};

// ============================================================================
// Constant-Time Utilities
// ============================================================================

#[inline]
fn ct_eq_slices(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    // 1 if diff == 0, else 0 (constant-time bit collapse).
    let d = diff as u16;
    (((d.wrapping_sub(1)) >> 8) & 1) as u8
}

#[inline]
fn ct_select_bytes(out: &mut [u8], if_one: &[u8], if_zero: &[u8], cond: u8) {
    let mask = 0u8.wrapping_sub(cond & 1);
    for i in 0..out.len() {
        out[i] = if_zero[i] ^ (mask & (if_one[i] ^ if_zero[i]));
    }
}

// ============================================================================
// FIPS 202 Keccak-f[1600], SHA3-256/512, SHAKE128/256, SP 800-185 KMAC256
// ============================================================================

const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const KECCAK_ROT: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &KECCAK_RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }
        let mut b = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                let src = x + 5 * y;
                let dst_x = y;
                let dst_y = (2 * x + 3 * y) % 5;
                b[dst_x + 5 * dst_y] = state[src].rotate_left(KECCAK_ROT[src]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                let base = 5 * y;
                state[x + base] =
                    b[x + base] ^ ((!b[((x + 1) % 5) + base]) & b[((x + 2) % 5) + base]);
            }
        }
        state[0] ^= rc;
    }
}

#[derive(Clone)]
pub(crate) struct KeccakSponge {
    state: [u64; 25],
    rate: usize,
    pos: usize,
}

impl KeccakSponge {
    pub(crate) fn new(rate: usize) -> Self {
        Self {
            state: [0u64; 25],
            rate,
            pos: 0,
        }
    }

    pub(crate) fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            let idx = self.pos / 8;
            let shift = (self.pos % 8) * 8;
            self.state[idx] ^= (byte as u64) << shift;
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    pub(crate) fn finalize_pad(&mut self, delim: u8) {
        let idx = self.pos / 8;
        let shift = (self.pos % 8) * 8;
        self.state[idx] ^= (delim as u64) << shift;
        let last = self.rate - 1;
        let lidx = last / 8;
        let lshift = (last % 8) * 8;
        self.state[lidx] ^= 0x80u64 << lshift;
        keccak_f1600(&mut self.state);
        self.pos = 0;
    }

    pub(crate) fn squeeze(&mut self, out: &mut [u8]) {
        for slot in out.iter_mut() {
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            let idx = self.pos / 8;
            let shift = (self.pos % 8) * 8;
            *slot = ((self.state[idx] >> shift) & 0xff) as u8;
            self.pos += 1;
        }
    }
}

pub(crate) fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sp = KeccakSponge::new(136);
    sp.absorb(data);
    sp.finalize_pad(0x06);
    let mut out = [0u8; 32];
    sp.squeeze(&mut out);
    out
}

pub(crate) fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut sp = KeccakSponge::new(72);
    sp.absorb(data);
    sp.finalize_pad(0x06);
    let mut out = [0u8; 64];
    sp.squeeze(&mut out);
    out
}

pub(crate) fn shake128(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut sp = KeccakSponge::new(168);
    sp.absorb(data);
    sp.finalize_pad(0x1f);
    let mut out = vec![0u8; out_len];
    sp.squeeze(&mut out);
    out
}

pub(crate) fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut sp = KeccakSponge::new(136);
    sp.absorb(data);
    sp.finalize_pad(0x1f);
    let mut out = vec![0u8; out_len];
    sp.squeeze(&mut out);
    out
}

#[derive(Clone)]
pub(crate) struct Sha3_512Hasher {
    inner: KeccakSponge,
}

impl Sha3_512Hasher {
    pub(crate) fn new() -> Self {
        Self {
            inner: KeccakSponge::new(72),
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.absorb(data);
    }

    pub(crate) fn finalize(mut self) -> [u8; 64] {
        self.inner.finalize_pad(0x06);
        let mut out = [0u8; 64];
        self.inner.squeeze(&mut out);
        out
    }
}

fn sp800_185_left_encode(val: usize) -> Vec<u8> {
    let mut bytes = val.to_be_bytes().to_vec();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let trimmed = bytes.split_off(first);
    let mut out = Vec::with_capacity(1 + trimmed.len());
    out.push(trimmed.len() as u8);
    out.extend_from_slice(&trimmed);
    out
}

fn sp800_185_right_encode(val: usize) -> Vec<u8> {
    let mut bytes = val.to_be_bytes().to_vec();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut trimmed = bytes.split_off(first);
    let len = trimmed.len() as u8;
    trimmed.push(len);
    trimmed
}

fn sp800_185_encode_string(s: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&sp800_185_left_encode(s.len().saturating_mul(8)));
    out.extend_from_slice(s);
}

fn sp800_185_bytepad_into(sp: &mut KeccakSponge, rate: usize, payload: &[u8]) {
    let le = sp800_185_left_encode(rate);
    sp.absorb(&le);
    sp.absorb(payload);
    let total = le.len() + payload.len();
    let rem = total % rate;
    if rem != 0 {
        let pad = vec![0u8; rate - rem];
        sp.absorb(&pad);
    }
}

/// NIST SP 800-185 KMAC256(key, S=custom, X=data, L=out_len*8).
pub(crate) fn kmac256(key: &[u8], custom: &[u8], data: &[u8], out_len: usize) -> Vec<u8> {
    const RATE: usize = 136;
    let mut header = Vec::with_capacity(16 + custom.len());
    sp800_185_encode_string(b"KMAC", &mut header);
    sp800_185_encode_string(custom, &mut header);

    let mut sp = KeccakSponge::new(RATE);
    sp800_185_bytepad_into(&mut sp, RATE, &header);

    let mut key_enc = Vec::with_capacity(16 + key.len());
    sp800_185_encode_string(key, &mut key_enc);
    sp800_185_bytepad_into(&mut sp, RATE, &key_enc);
    zeroize_bytes(&mut key_enc);

    sp.absorb(data);
    sp.absorb(&sp800_185_right_encode(out_len.saturating_mul(8)));
    sp.finalize_pad(0x04);
    let mut out = vec![0u8; out_len];
    sp.squeeze(&mut out);
    out
}

// ============================================================================
// HMAC-SHA512 & HKDF-SHA512
// ============================================================================

pub(crate) fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut k_block = [0u8; 128];
    if key.len() > 128 {
        let digest = Sha512::digest(key);
        k_block[..64].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for i in 0..128 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner_digest);
    let result: [u8; 64] = outer.finalize().into();

    zeroize_bytes(&mut k_block);
    zeroize_bytes(&mut ipad);
    zeroize_bytes(&mut opad);
    result
}

pub(crate) fn hkdf_sha512(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, String> {
    if out_len == 0 || out_len > 255 * 64 {
        return Err("hkdf_sha512 length must be between 1 and 16320 bytes".into());
    }
    let eff_salt = if salt.is_empty() {
        &[0u8; 64][..]
    } else {
        salt
    };
    let mut prk = hmac_sha512(eff_salt, ikm);
    let blocks = out_len.div_ceil(64);
    let mut okm = Vec::with_capacity(blocks * 64);
    let mut prev: Vec<u8> = Vec::new();
    for counter in 1..=blocks {
        let mut msg = Vec::with_capacity(prev.len() + info.len() + 1);
        msg.extend_from_slice(&prev);
        msg.extend_from_slice(info);
        msg.push(counter as u8);
        let mut next = hmac_sha512(&prk, &msg);
        zeroize_bytes(&mut msg);
        okm.extend_from_slice(&next);
        zeroize_bytes(&mut prev);
        prev = next.to_vec();
        zeroize_bytes(&mut next);
    }
    zeroize_bytes(&mut prev);
    zeroize_bytes(&mut prk);
    okm.truncate(out_len);
    Ok(okm)
}

/// Derives `out_len` independent key bytes via HKDF-SHA512 XOR KMAC256.
pub(crate) fn dual_prf_expand(
    ikm: &[u8],
    salt: &[u8],
    context: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, String> {
    let mut part_a = hkdf_sha512(ikm, salt, context, out_len)?;
    let mut key_tag = sha3_512(ikm);
    let mut salt_and_ctx = Vec::with_capacity(salt.len() + context.len() + 1);
    salt_and_ctx.extend_from_slice(salt);
    salt_and_ctx.push(0x3a);
    salt_and_ctx.extend_from_slice(context);
    let mut part_b = kmac256(&key_tag, b"KOVREK-DUAL-PRF", &salt_and_ctx, out_len);
    for i in 0..out_len {
        part_a[i] ^= part_b[i];
    }
    zeroize_bytes(&mut key_tag);
    zeroize_bytes(&mut part_b);
    Ok(part_a)
}

// ============================================================================
// RFC 7693 Blake2b + RFC 9106 Argon2id
// ============================================================================

const BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline(always)]
fn b2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn b2b_compress(h: &mut [u64; 8], block: &[u8; 128], t_lo: u64, t_hi: u64, is_last: bool) {
    let mut m = [0u64; 16];
    for i in 0..16 {
        let o = i * 8;
        m[i] = u64::from_le_bytes(block[o..o + 8].try_into().unwrap());
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t_lo;
    v[13] ^= t_hi;
    if is_last {
        v[14] = !v[14];
    }
    for r in 0..12 {
        let s = &BLAKE2B_SIGMA[r];
        b2b_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        b2b_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        b2b_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        b2b_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        b2b_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        b2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        b2b_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        b2b_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

pub(crate) fn blake2b(data: &[u8], key: &[u8], out_len: usize) -> Result<Vec<u8>, String> {
    if !(1..=64).contains(&out_len) {
        return Err("blake2b out_len must be between 1 and 64".into());
    }
    if key.len() > 64 {
        return Err("blake2b key must be at most 64 bytes".into());
    }
    let mut h = BLAKE2B_IV;
    h[0] ^= 0x0101_0000u64 ^ ((key.len() as u64) << 8) ^ (out_len as u64);

    let mut total = Vec::with_capacity(if key.is_empty() {
        data.len()
    } else {
        128 + data.len()
    });
    if !key.is_empty() {
        let mut padded_key = [0u8; 128];
        padded_key[..key.len()].copy_from_slice(key);
        total.extend_from_slice(&padded_key);
        zeroize_bytes(&mut padded_key);
    }
    total.extend_from_slice(data);

    let mut offset = 0usize;
    let mut t: u128 = 0;
    if total.is_empty() {
        b2b_compress(&mut h, &[0u8; 128], 0, 0, true);
    } else {
        while offset + 128 < total.len() {
            let block: &[u8; 128] = total[offset..offset + 128].try_into().unwrap();
            t += 128;
            b2b_compress(&mut h, block, t as u64, (t >> 64) as u64, false);
            offset += 128;
        }
        let rem = total.len() - offset;
        let mut last = [0u8; 128];
        last[..rem].copy_from_slice(&total[offset..]);
        t += rem as u128;
        b2b_compress(&mut h, &last, t as u64, (t >> 64) as u64, true);
    }
    zeroize_bytes(&mut total);

    let mut raw = [0u8; 64];
    for i in 0..8 {
        raw[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_le_bytes());
    }
    let res = raw[..out_len].to_vec();
    zeroize_bytes(&mut raw);
    Ok(res)
}

fn argon2_blake2b_long(out_len: usize, input: &[u8]) -> Result<Vec<u8>, String> {
    let mut seeded = Vec::with_capacity(4 + input.len());
    seeded.extend_from_slice(&(out_len as u32).to_le_bytes());
    seeded.extend_from_slice(input);
    if out_len <= 64 {
        let res = blake2b(&seeded, &[], out_len)?;
        zeroize_bytes(&mut seeded);
        return Ok(res);
    }
    let mut out = Vec::with_capacity(out_len);
    let mut v = blake2b(&seeded, &[], 64)?;
    zeroize_bytes(&mut seeded);
    out.extend_from_slice(&v[..32]);
    let mut remaining = out_len - 32;
    while remaining > 64 {
        v = blake2b(&v, &[], 64)?;
        out.extend_from_slice(&v[..32]);
        remaining -= 32;
    }
    let tail = blake2b(&v, &[], remaining)?;
    out.extend_from_slice(&tail);
    zeroize_bytes(&mut v);
    Ok(out)
}

#[inline(always)]
fn f_blamka(x: u64, y: u64) -> u64 {
    let xy = (x as u32 as u64) * (y as u32 as u64);
    x.wrapping_add(y).wrapping_add(2u64.wrapping_mul(xy))
}

#[inline(always)]
fn argon2_g(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64) {
    *a = f_blamka(*a, *b);
    *d = (*d ^ *a).rotate_right(32);
    *c = f_blamka(*c, *d);
    *b = (*b ^ *c).rotate_right(24);
    *a = f_blamka(*a, *b);
    *d = (*d ^ *a).rotate_right(16);
    *c = f_blamka(*c, *d);
    *b = (*b ^ *c).rotate_right(63);
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn argon2_p_round(
    v0: &mut u64,
    v1: &mut u64,
    v2: &mut u64,
    v3: &mut u64,
    v4: &mut u64,
    v5: &mut u64,
    v6: &mut u64,
    v7: &mut u64,
    v8: &mut u64,
    v9: &mut u64,
    v10: &mut u64,
    v11: &mut u64,
    v12: &mut u64,
    v13: &mut u64,
    v14: &mut u64,
    v15: &mut u64,
) {
    argon2_g(v0, v4, v8, v12);
    argon2_g(v1, v5, v9, v13);
    argon2_g(v2, v6, v10, v14);
    argon2_g(v3, v7, v11, v15);
    argon2_g(v0, v5, v10, v15);
    argon2_g(v1, v6, v11, v12);
    argon2_g(v2, v7, v8, v13);
    argon2_g(v3, v4, v9, v14);
}

fn argon2_compress_block(x: &[u64; 128], y: &[u64; 128]) -> [u64; 128] {
    let mut r = [0u64; 128];
    for i in 0..128 {
        r[i] = x[i] ^ y[i];
    }
    let mut z = r;
    for row in 0..8 {
        let base = row * 16;
        let (mut z0, mut z1, mut z2, mut z3, mut z4, mut z5, mut z6, mut z7) = (
            z[base],
            z[base + 1],
            z[base + 2],
            z[base + 3],
            z[base + 4],
            z[base + 5],
            z[base + 6],
            z[base + 7],
        );
        let (mut z8, mut z9, mut z10, mut z11, mut z12, mut z13, mut z14, mut z15) = (
            z[base + 8],
            z[base + 9],
            z[base + 10],
            z[base + 11],
            z[base + 12],
            z[base + 13],
            z[base + 14],
            z[base + 15],
        );
        argon2_p_round(
            &mut z0, &mut z1, &mut z2, &mut z3, &mut z4, &mut z5, &mut z6, &mut z7, &mut z8,
            &mut z9, &mut z10, &mut z11, &mut z12, &mut z13, &mut z14, &mut z15,
        );
        z[base] = z0;
        z[base + 1] = z1;
        z[base + 2] = z2;
        z[base + 3] = z3;
        z[base + 4] = z4;
        z[base + 5] = z5;
        z[base + 6] = z6;
        z[base + 7] = z7;
        z[base + 8] = z8;
        z[base + 9] = z9;
        z[base + 10] = z10;
        z[base + 11] = z11;
        z[base + 12] = z12;
        z[base + 13] = z13;
        z[base + 14] = z14;
        z[base + 15] = z15;
    }
    for col in 0..8 {
        let c = col * 2;
        let (mut z0, mut z1, mut z2, mut z3, mut z4, mut z5, mut z6, mut z7) = (
            z[c],
            z[c + 1],
            z[16 + c],
            z[16 + c + 1],
            z[32 + c],
            z[32 + c + 1],
            z[48 + c],
            z[48 + c + 1],
        );
        let (mut z8, mut z9, mut z10, mut z11, mut z12, mut z13, mut z14, mut z15) = (
            z[64 + c],
            z[64 + c + 1],
            z[80 + c],
            z[80 + c + 1],
            z[96 + c],
            z[96 + c + 1],
            z[112 + c],
            z[112 + c + 1],
        );
        argon2_p_round(
            &mut z0, &mut z1, &mut z2, &mut z3, &mut z4, &mut z5, &mut z6, &mut z7, &mut z8,
            &mut z9, &mut z10, &mut z11, &mut z12, &mut z13, &mut z14, &mut z15,
        );
        z[c] = z0;
        z[c + 1] = z1;
        z[16 + c] = z2;
        z[16 + c + 1] = z3;
        z[32 + c] = z4;
        z[32 + c + 1] = z5;
        z[48 + c] = z6;
        z[48 + c + 1] = z7;
        z[64 + c] = z8;
        z[64 + c + 1] = z9;
        z[80 + c] = z10;
        z[80 + c + 1] = z11;
        z[96 + c] = z12;
        z[96 + c + 1] = z13;
        z[112 + c] = z14;
        z[112 + c + 1] = z15;
    }
    for i in 0..128 {
        z[i] ^= r[i];
    }
    z
}

fn argon2_index_alpha(
    pass: u32,
    slice: u32,
    index: u32,
    segment_len: u32,
    lane_len: u32,
    same_lane: bool,
    j1: u32,
) -> usize {
    let ref_area = if pass == 0 {
        if slice == 0 {
            index - 1
        } else if same_lane {
            slice * segment_len + index - 1
        } else {
            slice * segment_len - u32::from(index == 0)
        }
    } else if same_lane {
        lane_len - segment_len + index - 1
    } else {
        lane_len - segment_len - u32::from(index == 0)
    };
    let rel = (j1 as u64 * j1 as u64) >> 32;
    let rel = ((ref_area as u64) * rel) >> 32;
    let rel_pos = (ref_area as u64) - 1 - rel;
    let start_pos = if pass != 0 && slice != 3 {
        ((slice + 1) * segment_len) as u64
    } else {
        0
    };
    ((start_pos + rel_pos) % (lane_len as u64)) as usize
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn argon2id_with_extras(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated: &[u8],
    mem_kib: u32,
    iterations: u32,
    lanes: u32,
    out_len: usize,
) -> Result<Vec<u8>, String> {
    if !(1..=64).contains(&lanes) {
        return Err("argon2id lanes must be between 1 and 64".into());
    }
    if !(1..=128).contains(&iterations) {
        return Err("argon2id iterations must be between 1 and 128".into());
    }
    if mem_kib < 8 * lanes || mem_kib > 2_097_152 {
        return Err("argon2id memory_kib must be >= 8*lanes and <= 2 GiB".into());
    }
    if !(4..=1024).contains(&out_len) {
        return Err("argon2id out_len must be between 4 and 1024 bytes".into());
    }

    const ARGON2_VERSION: u32 = 0x13;
    const ARGON2ID_TYPE: u32 = 2;

    let mut h0_in =
        Vec::with_capacity(40 + password.len() + salt.len() + secret.len() + associated.len());
    for v in [
        lanes,
        out_len as u32,
        mem_kib,
        iterations,
        ARGON2_VERSION,
        ARGON2ID_TYPE,
    ] {
        h0_in.extend_from_slice(&v.to_le_bytes());
    }
    for slice in [password, salt, secret, associated] {
        h0_in.extend_from_slice(&(slice.len() as u32).to_le_bytes());
        h0_in.extend_from_slice(slice);
    }
    let mut h0 = blake2b(&h0_in, &[], 64)?;
    zeroize_bytes(&mut h0_in);

    let segment_len = mem_kib / (4 * lanes);
    let lane_len = segment_len * 4;
    let total_blocks = (lane_len * lanes) as usize;
    let mut memory = vec![[0u64; 128]; total_blocks];

    for l in 0..lanes {
        for idx in 0..2u32 {
            let mut blk_in = Vec::with_capacity(72);
            blk_in.extend_from_slice(&h0);
            blk_in.extend_from_slice(&idx.to_le_bytes());
            blk_in.extend_from_slice(&l.to_le_bytes());
            let mut raw = argon2_blake2b_long(1024, &blk_in)?;
            let slot = &mut memory[(l * lane_len + idx) as usize];
            for w in 0..128 {
                slot[w] = u64::from_le_bytes(raw[w * 8..w * 8 + 8].try_into().unwrap());
            }
            zeroize_bytes(&mut blk_in);
            zeroize_bytes(&mut raw);
        }
    }
    zeroize_bytes(&mut h0);

    let zero_block = [0u64; 128];
    for r in 0..iterations {
        for s in 0..4u32 {
            for l in 0..lanes {
                let data_independent = r == 0 && s < 2;
                let start_idx = if r == 0 && s == 0 { 2 } else { 0 };
                let mut addr_ctr = 0u64;
                let mut addr_block = [0u64; 128];
                for index in start_idx..segment_len {
                    let cur_offset = (l * lane_len + s * segment_len + index) as usize;
                    let prev_offset = if s == 0 && index == 0 {
                        (l * lane_len + lane_len - 1) as usize
                    } else {
                        cur_offset - 1
                    };
                    let pseudo_rand = if data_independent {
                        let slot = (index as usize) % 128;
                        if slot == 0 || (r == 0 && s == 0 && index == start_idx) {
                            addr_ctr += 1;
                            let mut input_blk = [0u64; 128];
                            input_blk[0] = r as u64;
                            input_blk[1] = l as u64;
                            input_blk[2] = s as u64;
                            input_blk[3] = total_blocks as u64;
                            input_blk[4] = iterations as u64;
                            input_blk[5] = ARGON2ID_TYPE as u64;
                            input_blk[6] = addr_ctr;
                            let first = argon2_compress_block(&zero_block, &input_blk);
                            addr_block = argon2_compress_block(&zero_block, &first);
                        }
                        addr_block[slot]
                    } else {
                        memory[prev_offset][0]
                    };
                    let j1 = pseudo_rand as u32;
                    let j2 = (pseudo_rand >> 32) as u32;
                    let ref_lane = if r == 0 && s == 0 { l } else { j2 % lanes };
                    let ref_idx =
                        argon2_index_alpha(r, s, index, segment_len, lane_len, ref_lane == l, j1);
                    let ref_offset = (ref_lane * lane_len) as usize + ref_idx;
                    let next = argon2_compress_block(&memory[prev_offset], &memory[ref_offset]);
                    if r == 0 {
                        memory[cur_offset] = next;
                    } else {
                        for w in 0..128 {
                            memory[cur_offset][w] ^= next[w];
                        }
                    }
                }
            }
        }
    }

    let mut final_block = memory[(lane_len - 1) as usize];
    for l in 1..lanes {
        let tail = &memory[(l * lane_len + lane_len - 1) as usize];
        for w in 0..128 {
            final_block[w] ^= tail[w];
        }
    }
    let mut final_bytes = [0u8; 1024];
    for w in 0..128 {
        final_bytes[w * 8..w * 8 + 8].copy_from_slice(&final_block[w].to_le_bytes());
    }
    let out = argon2_blake2b_long(out_len, &final_bytes)?;

    for blk in &mut memory {
        for word in blk.iter_mut() {
            unsafe { std::ptr::write_volatile(word, 0) };
        }
    }
    for word in &mut final_block {
        unsafe { std::ptr::write_volatile(word, 0) };
    }
    zeroize_bytes(&mut final_bytes);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    Ok(out)
}

pub(crate) fn argon2id(
    password: &[u8],
    salt: &[u8],
    mem_kib: u32,
    iterations: u32,
    lanes: u32,
    out_len: usize,
) -> Result<Vec<u8>, String> {
    argon2id_with_extras(
        password,
        salt,
        &[],
        &[],
        mem_kib,
        iterations,
        lanes,
        out_len,
    )
}

// ============================================================================
// RFC 7748 Constant-Time X25519
// ============================================================================

type Gf = [i64; 16];

const GF_121665: Gf = [0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[inline]
fn gf_car25519(o: &mut Gf) {
    for _ in 0..2 {
        for i in 0..16 {
            o[i] += 1 << 16;
            let c = o[i] >> 16;
            if i < 15 {
                o[i + 1] += c - 1;
            } else {
                o[0] += 38 * (c - 1);
            }
            o[i] -= c << 16;
        }
    }
}

fn gf_sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !((b & 1) - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn gf_add(a: &Gf, b: &Gf) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}

fn gf_sub(a: &Gf, b: &Gf) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}

fn gf_mul(a: &Gf, b: &Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o = [0i64; 16];
    o.copy_from_slice(&t[..16]);
    gf_car25519(&mut o);
    gf_car25519(&mut o);
    o
}

fn gf_sq(a: &Gf) -> Gf {
    gf_mul(a, a)
}

fn gf_inv25519(i: &Gf) -> Gf {
    let mut c = *i;
    for a in (0..=253).rev() {
        c = gf_sq(&c);
        if a != 2 && a != 4 {
            c = gf_mul(&c, i);
        }
    }
    c
}

fn gf_unpack25519(n: &[u8; 32]) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = (n[2 * i] as i64) + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
    o
}

fn gf_pack25519(n: &Gf) -> [u8; 32] {
    let mut t = *n;
    gf_car25519(&mut t);
    gf_car25519(&mut t);
    gf_car25519(&mut t);
    let mut m = [0i64; 16];
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        gf_sel25519(&mut t, &mut m, 1 - b);
    }
    let mut o = [0u8; 32];
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = ((t[i] >> 8) & 0xff) as u8;
    }
    o
}

pub(crate) fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut z = *scalar;
    z[0] &= 248;
    z[31] &= 127;
    z[31] |= 64;

    let x = gf_unpack25519(point);
    let mut a = [0i64; 16];
    let mut b = x;
    let mut c = [0i64; 16];
    let mut d = [0i64; 16];
    a[0] = 1;
    d[0] = 1;

    for i in (0..=254).rev() {
        let r = ((z[i >> 3] >> (i & 7)) & 1) as i64;
        gf_sel25519(&mut a, &mut b, r);
        gf_sel25519(&mut c, &mut d, r);
        let e = gf_add(&a, &c);
        a = gf_sub(&a, &c);
        c = gf_add(&b, &d);
        b = gf_sub(&b, &d);
        d = gf_sq(&e);
        let f = gf_sq(&a);
        a = gf_mul(&c, &a);
        c = gf_mul(&b, &e);
        let e2 = gf_add(&a, &c);
        a = gf_sub(&a, &c);
        b = gf_sq(&a);
        c = gf_sub(&d, &f);
        a = gf_mul(&c, &GF_121665);
        a = gf_add(&a, &d);
        c = gf_mul(&c, &a);
        a = gf_mul(&d, &f);
        d = gf_mul(&b, &x);
        b = gf_sq(&e2);
        gf_sel25519(&mut a, &mut b, r);
        gf_sel25519(&mut c, &mut d, r);
    }
    c = gf_inv25519(&c);
    a = gf_mul(&a, &c);
    zeroize_bytes(&mut z);
    gf_pack25519(&a)
}

pub(crate) fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(secret, &base)
}

pub(crate) fn x25519_shared_checked(
    secret: &[u8; 32],
    peer_pub: &[u8; 32],
) -> Result<[u8; 32], String> {
    let ss = x25519(secret, peer_pub);
    let mut acc = 0u8;
    for &b in &ss {
        acc |= b;
    }
    if acc == 0 {
        return Err("X25519 shared secret rejected (low-order peer public point)".into());
    }
    Ok(ss)
}

// ============================================================================
// NIST FIPS 203 ML-KEM-1024 (Category 5 Post-Quantum Lattice KEM)
// ============================================================================

const MLKEM_N: usize = 256;
const MLKEM_Q: i32 = 3329;
const MLKEM_K: usize = 4;
const MLKEM_DU: usize = 11;
const MLKEM_DV: usize = 5;
pub(crate) const MLKEM1024_EK_BYTES: usize = 1568;
pub(crate) const MLKEM1024_DK_BYTES: usize = 3168;
pub(crate) const MLKEM1024_CT_BYTES: usize = 1568;

const fn compute_mlkem_zetas() -> [i16; 128] {
    let mut out = [0i16; 128];
    let mut pow = [0i16; 128];
    let mut cur: i32 = 1;
    let mut i = 0usize;
    while i < 128 {
        pow[i] = cur as i16;
        cur = (cur * 17) % MLKEM_Q;
        i += 1;
    }
    let mut k = 0usize;
    while k < 128 {
        let mut br = 0usize;
        let mut bit = 0usize;
        while bit < 7 {
            if (k >> bit) & 1 != 0 {
                br |= 1usize << (6 - bit);
            }
            bit += 1;
        }
        out[k] = pow[br];
        k += 1;
    }
    out
}

const MLKEM_ZETAS: [i16; 128] = compute_mlkem_zetas();

/// Constant-time canonical reduction modulo q = 3329 via Barrett approximation (no division ops).
#[inline(always)]
fn mod_q(x: i32) -> i16 {
    let x64 = x as i64;
    let q_approx = (x64 * 20_642_718i64) >> 36;
    let mut r = (x64 - q_approx * (MLKEM_Q as i64)) as i32;
    let neg = r >> 31;
    r += neg & MLKEM_Q;
    let over = MLKEM_Q - 1 - r;
    let over_neg = over >> 31;
    r -= over_neg & MLKEM_Q;
    r as i16
}

#[inline(always)]
fn mul_q(a: i16, b: i16) -> i16 {
    mod_q((a as i32) * (b as i32))
}

type Poly = [i16; MLKEM_N];
type PolyVec = [Poly; MLKEM_K];

fn poly_ntt(r: &mut Poly) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < MLKEM_N {
            let zeta = MLKEM_ZETAS[k];
            k += 1;
            for j in start..(start + len) {
                let t = mul_q(zeta, r[j + len]);
                r[j + len] = mod_q(r[j] as i32 - t as i32);
                r[j] = mod_q(r[j] as i32 + t as i32);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

fn poly_invntt(r: &mut Poly) {
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < MLKEM_N {
            let zeta = MLKEM_ZETAS[k];
            k = k.saturating_sub(1);
            for j in start..(start + len) {
                let t = r[j];
                r[j] = mod_q(t as i32 + r[j + len] as i32);
                let diff = mod_q(r[j + len] as i32 - t as i32);
                r[j + len] = mul_q(zeta, diff);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    const INV_128_MOD_Q: i16 = 3303;
    for c in r.iter_mut() {
        *c = mul_q(*c, INV_128_MOD_Q);
    }
}

fn poly_basemul_acc(a: &PolyVec, b: &PolyVec) -> Poly {
    let mut acc = [0i16; MLKEM_N];
    for row in 0..MLKEM_K {
        let ap = &a[row];
        let bp = &b[row];
        for i in 0..64 {
            let zeta = MLKEM_ZETAS[64 + i];
            let p0 = 4 * i;
            let a0 = ap[p0];
            let a1 = ap[p0 + 1];
            let b0 = bp[p0];
            let b1 = bp[p0 + 1];
            let c0 = mod_q(mul_q(a0, b0) as i32 + mul_q(mul_q(a1, b1), zeta) as i32);
            let c1 = mod_q(mul_q(a0, b1) as i32 + mul_q(a1, b0) as i32);
            acc[p0] = mod_q(acc[p0] as i32 + c0 as i32);
            acc[p0 + 1] = mod_q(acc[p0 + 1] as i32 + c1 as i32);

            let p1 = p0 + 2;
            let a2 = ap[p1];
            let a3 = ap[p1 + 1];
            let b2 = bp[p1];
            let b3 = bp[p1 + 1];
            let c2 = mod_q(mul_q(a2, b2) as i32 - mul_q(mul_q(a3, b3), zeta) as i32);
            let c3 = mod_q(mul_q(a2, b3) as i32 + mul_q(a3, b2) as i32);
            acc[p1] = mod_q(acc[p1] as i32 + c2 as i32);
            acc[p1 + 1] = mod_q(acc[p1 + 1] as i32 + c3 as i32);
        }
    }
    acc
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i16; MLKEM_N];
    for i in 0..MLKEM_N {
        out[i] = mod_q(a[i] as i32 + b[i] as i32);
    }
    out
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i16; MLKEM_N];
    for i in 0..MLKEM_N {
        out[i] = mod_q(a[i] as i32 - b[i] as i32);
    }
    out
}

fn sample_ntt(rho: &[u8; 32], col: u8, row: u8) -> Poly {
    let mut seed = [0u8; 34];
    seed[..32].copy_from_slice(rho);
    seed[32] = col;
    seed[33] = row;
    let mut sp = KeccakSponge::new(168);
    sp.absorb(&seed);
    sp.finalize_pad(0x1f);

    let mut out = [0i16; MLKEM_N];
    let mut j = 0usize;
    let mut buf = [0u8; 3];
    while j < MLKEM_N {
        sp.squeeze(&mut buf);
        let d1 = (buf[0] as u16) | (((buf[1] & 0x0f) as u16) << 8);
        let d2 = ((buf[1] >> 4) as u16) | ((buf[2] as u16) << 4);
        if (d1 as i32) < MLKEM_Q {
            out[j] = d1 as i16;
            j += 1;
        }
        if j < MLKEM_N && (d2 as i32) < MLKEM_Q {
            out[j] = d2 as i16;
            j += 1;
        }
    }
    out
}

fn sample_poly_cbd2(sigma: &[u8; 32], nonce: u8) -> Poly {
    let mut seed = [0u8; 33];
    seed[..32].copy_from_slice(sigma);
    seed[32] = nonce;
    let mut prf = shake256(&seed, 128);
    zeroize_bytes(&mut seed);
    let mut r = [0i16; MLKEM_N];
    for i in 0..MLKEM_N {
        let byte = prf[i >> 1];
        let nibble = if (i & 1) == 0 { byte & 0x0f } else { byte >> 4 };
        let a = ((nibble & 1) + ((nibble >> 1) & 1)) as i32;
        let b = (((nibble >> 2) & 1) + ((nibble >> 3) & 1)) as i32;
        r[i] = mod_q(a - b);
    }
    zeroize_bytes(&mut prf);
    r
}

fn poly_encode_12(p: &Poly, out: &mut [u8]) {
    for i in 0..(MLKEM_N / 2) {
        let t0 = p[2 * i] as u16;
        let t1 = p[2 * i + 1] as u16;
        out[3 * i] = (t0 & 0xff) as u8;
        out[3 * i + 1] = ((t0 >> 8) | ((t1 & 0x0f) << 4)) as u8;
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
}

fn poly_decode_12_checked(src: &[u8]) -> Result<Poly, String> {
    let mut p = [0i16; MLKEM_N];
    for i in 0..(MLKEM_N / 2) {
        let t0 = ((src[3 * i] as u16) | (((src[3 * i + 1] & 0x0f) as u16) << 8)) as i32;
        let t1 = (((src[3 * i + 1] >> 4) as u16) | ((src[3 * i + 2] as u16) << 4)) as i32;
        if t0 >= MLKEM_Q || t1 >= MLKEM_Q {
            return Err("ML-KEM-1024 invalid encapsulation key coefficient >= q".into());
        }
        p[2 * i] = t0 as i16;
        p[2 * i + 1] = t1 as i16;
    }
    Ok(p)
}

#[inline(always)]
fn compress_coeff(x: i16, d: usize) -> u16 {
    let v = (((x as u32) << (d + 1)) + (MLKEM_Q as u32)) / ((MLKEM_Q as u32) * 2);
    (v & ((1u32 << d) - 1)) as u16
}

#[inline(always)]
fn decompress_coeff(y: u16, d: usize) -> i16 {
    (((y as u32) * (MLKEM_Q as u32) + (1u32 << (d - 1))) >> d) as i16
}

fn bitpack_poly(coeffs: &[u16; MLKEM_N], bits: usize, out: &mut [u8]) {
    let mut bit_pos = 0usize;
    out.fill(0);
    for &c in coeffs {
        for b in 0..bits {
            if ((c >> b) & 1) != 0 {
                out[bit_pos >> 3] |= 1u8 << (bit_pos & 7);
            }
            bit_pos += 1;
        }
    }
}

fn bitunpack_poly(src: &[u8], bits: usize) -> [u16; MLKEM_N] {
    let mut out = [0u16; MLKEM_N];
    let mut bit_pos = 0usize;
    for slot in out.iter_mut() {
        let mut acc = 0u16;
        for b in 0..bits {
            let bit = (src[bit_pos >> 3] >> (bit_pos & 7)) & 1;
            acc |= (bit as u16) << b;
            bit_pos += 1;
        }
        *slot = acc;
    }
    out
}

fn kpke_keygen(d: &[u8; 32]) -> ([u8; MLKEM1024_EK_BYTES], [u8; 384 * MLKEM_K]) {
    let mut seed_in = [0u8; 33];
    seed_in[..32].copy_from_slice(d);
    seed_in[32] = MLKEM_K as u8;
    let mut expanded = sha3_512(&seed_in);
    zeroize_bytes(&mut seed_in);
    let rho: [u8; 32] = expanded[..32].try_into().unwrap();
    let sigma: [u8; 32] = expanded[32..].try_into().unwrap();
    zeroize_bytes(&mut expanded);

    let mut a_mat = [[[0i16; MLKEM_N]; MLKEM_K]; MLKEM_K];
    for i in 0..MLKEM_K {
        for j in 0..MLKEM_K {
            a_mat[i][j] = sample_ntt(&rho, j as u8, i as u8);
        }
    }

    let mut s_vec: PolyVec = [[0i16; MLKEM_N]; MLKEM_K];
    let mut e_vec: PolyVec = [[0i16; MLKEM_N]; MLKEM_K];
    let mut n_ctr = 0u8;
    for i in 0..MLKEM_K {
        s_vec[i] = sample_poly_cbd2(&sigma, n_ctr);
        n_ctr += 1;
        poly_ntt(&mut s_vec[i]);
    }
    for i in 0..MLKEM_K {
        e_vec[i] = sample_poly_cbd2(&sigma, n_ctr);
        n_ctr += 1;
        poly_ntt(&mut e_vec[i]);
    }

    let mut ek_pke = [0u8; MLKEM1024_EK_BYTES];
    let mut dk_pke = [0u8; 384 * MLKEM_K];
    for i in 0..MLKEM_K {
        let t_i = poly_add(&poly_basemul_acc(&a_mat[i], &s_vec), &e_vec[i]);
        poly_encode_12(&t_i, &mut ek_pke[i * 384..(i + 1) * 384]);
        poly_encode_12(&s_vec[i], &mut dk_pke[i * 384..(i + 1) * 384]);
    }
    ek_pke[384 * MLKEM_K..].copy_from_slice(&rho);
    for p in &mut s_vec {
        for c in p.iter_mut() {
            unsafe { std::ptr::write_volatile(c, 0) };
        }
    }
    for p in &mut e_vec {
        for c in p.iter_mut() {
            unsafe { std::ptr::write_volatile(c, 0) };
        }
    }
    (ek_pke, dk_pke)
}

fn kpke_encrypt(
    ek: &[u8],
    m: &[u8; 32],
    r_seed: &[u8; 32],
) -> Result<[u8; MLKEM1024_CT_BYTES], String> {
    if ek.len() != MLKEM1024_EK_BYTES {
        return Err("invalid ML-KEM-1024 encapsulation key length".into());
    }
    let mut t_vec: PolyVec = [[0i16; MLKEM_N]; MLKEM_K];
    for i in 0..MLKEM_K {
        t_vec[i] = poly_decode_12_checked(&ek[i * 384..(i + 1) * 384])?;
    }
    let rho: [u8; 32] = ek[384 * MLKEM_K..].try_into().unwrap();

    let mut at_mat = [[[0i16; MLKEM_N]; MLKEM_K]; MLKEM_K];
    for i in 0..MLKEM_K {
        for j in 0..MLKEM_K {
            at_mat[i][j] = sample_ntt(&rho, i as u8, j as u8);
        }
    }

    let mut y_vec: PolyVec = [[0i16; MLKEM_N]; MLKEM_K];
    let mut e1_vec: PolyVec = [[0i16; MLKEM_N]; MLKEM_K];
    let mut n_ctr = 0u8;
    for i in 0..MLKEM_K {
        y_vec[i] = sample_poly_cbd2(r_seed, n_ctr);
        n_ctr += 1;
        poly_ntt(&mut y_vec[i]);
    }
    for i in 0..MLKEM_K {
        e1_vec[i] = sample_poly_cbd2(r_seed, n_ctr);
        n_ctr += 1;
    }
    let e2 = sample_poly_cbd2(r_seed, n_ctr);

    let m_bits = bitunpack_poly(m, 1);
    let mut m_poly = [0i16; MLKEM_N];
    for i in 0..MLKEM_N {
        m_poly[i] = decompress_coeff(m_bits[i], 1);
    }

    let mut ct = [0u8; MLKEM1024_CT_BYTES];
    let u_bytes_per_poly = 32 * MLKEM_DU;
    for i in 0..MLKEM_K {
        let mut u_i = poly_basemul_acc(&at_mat[i], &y_vec);
        poly_invntt(&mut u_i);
        u_i = poly_add(&u_i, &e1_vec[i]);
        let mut comp = [0u16; MLKEM_N];
        for c in 0..MLKEM_N {
            comp[c] = compress_coeff(u_i[c], MLKEM_DU);
        }
        bitpack_poly(
            &comp,
            MLKEM_DU,
            &mut ct[i * u_bytes_per_poly..(i + 1) * u_bytes_per_poly],
        );
    }
    let mut v = poly_basemul_acc(&t_vec, &y_vec);
    poly_invntt(&mut v);
    v = poly_add(&v, &e2);
    v = poly_add(&v, &m_poly);
    let mut v_comp = [0u16; MLKEM_N];
    for c in 0..MLKEM_N {
        v_comp[c] = compress_coeff(v[c], MLKEM_DV);
    }
    bitpack_poly(&v_comp, MLKEM_DV, &mut ct[MLKEM_K * u_bytes_per_poly..]);
    Ok(ct)
}

fn kpke_decrypt(dk_pke: &[u8], ct: &[u8]) -> Result<[u8; 32], String> {
    let mut s_vec: PolyVec = [[0i16; MLKEM_N]; MLKEM_K];
    for i in 0..MLKEM_K {
        s_vec[i] = poly_decode_12_checked(&dk_pke[i * 384..(i + 1) * 384])?;
    }
    let mut u_vec: PolyVec = [[0i16; MLKEM_N]; MLKEM_K];
    let u_bytes_per_poly = 32 * MLKEM_DU;
    for i in 0..MLKEM_K {
        let comp = bitunpack_poly(
            &ct[i * u_bytes_per_poly..(i + 1) * u_bytes_per_poly],
            MLKEM_DU,
        );
        for c in 0..MLKEM_N {
            u_vec[i][c] = decompress_coeff(comp[c], MLKEM_DU);
        }
        poly_ntt(&mut u_vec[i]);
    }
    let v_comp = bitunpack_poly(&ct[MLKEM_K * u_bytes_per_poly..], MLKEM_DV);
    let mut v = [0i16; MLKEM_N];
    for c in 0..MLKEM_N {
        v[c] = decompress_coeff(v_comp[c], MLKEM_DV);
    }
    let mut stu = poly_basemul_acc(&s_vec, &u_vec);
    poly_invntt(&mut stu);
    let w = poly_sub(&v, &stu);
    let mut m_bits = [0u16; MLKEM_N];
    for c in 0..MLKEM_N {
        m_bits[c] = compress_coeff(w[c], 1);
    }
    let mut m = [0u8; 32];
    bitpack_poly(&m_bits, 1, &mut m);
    Ok(m)
}

pub(crate) fn mlkem1024_keygen_deterministic(d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (ek, dk_pke) = kpke_keygen(d);
    let h_ek = sha3_256(&ek);
    let mut dk = Vec::with_capacity(MLKEM1024_DK_BYTES);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(z);
    (ek.to_vec(), dk)
}

pub(crate) fn mlkem1024_keygen() -> (Vec<u8>, Vec<u8>) {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    OsRng.fill_bytes(&mut d);
    OsRng.fill_bytes(&mut z);
    let out = mlkem1024_keygen_deterministic(&d, &z);
    zeroize_bytes(&mut d);
    zeroize_bytes(&mut z);
    out
}

pub(crate) fn mlkem1024_encaps_deterministic(
    ek: &[u8],
    m: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), String> {
    if ek.len() != MLKEM1024_EK_BYTES {
        return Err(format!(
            "ML-KEM-1024 encapsulation key must be {MLKEM1024_EK_BYTES} bytes"
        ));
    }
    let h_ek = sha3_256(ek);
    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(m);
    g_in[32..].copy_from_slice(&h_ek);
    let mut kr = sha3_512(&g_in);
    zeroize_bytes(&mut g_in);
    let k_shared: [u8; 32] = kr[..32].try_into().unwrap();
    let r_seed: [u8; 32] = kr[32..].try_into().unwrap();
    let ct = kpke_encrypt(ek, m, &r_seed)?;
    zeroize_bytes(&mut kr);
    Ok((ct.to_vec(), k_shared))
}

pub(crate) fn mlkem1024_encaps(ek: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
    let mut m = [0u8; 32];
    OsRng.fill_bytes(&mut m);
    let res = mlkem1024_encaps_deterministic(ek, &m);
    zeroize_bytes(&mut m);
    res
}

pub(crate) fn mlkem1024_decaps(dk: &[u8], ct: &[u8]) -> Result<[u8; 32], String> {
    if dk.len() != MLKEM1024_DK_BYTES {
        return Err(format!(
            "ML-KEM-1024 decapsulation key must be {MLKEM1024_DK_BYTES} bytes"
        ));
    }
    if ct.len() != MLKEM1024_CT_BYTES {
        return Err(format!(
            "ML-KEM-1024 ciphertext must be {MLKEM1024_CT_BYTES} bytes"
        ));
    }
    let dk_pke = &dk[..384 * MLKEM_K];
    let ek_pke = &dk[384 * MLKEM_K..384 * MLKEM_K + MLKEM1024_EK_BYTES];
    let h_offset = 384 * MLKEM_K + MLKEM1024_EK_BYTES;
    let h_ek = &dk[h_offset..h_offset + 32];
    let z = &dk[h_offset + 32..];

    if !constant_time_bytes_equal(&sha3_256(ek_pke), h_ek) {
        return Err("corrupted ML-KEM-1024 decapsulation key (H(ek) mismatch)".into());
    }

    let mut m_prime = kpke_decrypt(dk_pke, ct)?;
    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(&m_prime);
    g_in[32..].copy_from_slice(h_ek);
    let mut kr_prime = sha3_512(&g_in);
    zeroize_bytes(&mut g_in);

    let k_prime: [u8; 32] = kr_prime[..32].try_into().unwrap();
    let r_prime: [u8; 32] = kr_prime[32..].try_into().unwrap();

    let mut j_in = Vec::with_capacity(32 + ct.len());
    j_in.extend_from_slice(z);
    j_in.extend_from_slice(ct);
    let mut k_bar_vec = shake256(&j_in, 32);
    zeroize_bytes(&mut j_in);

    let c_prime = kpke_encrypt(ek_pke, &m_prime, &r_prime)?;
    zeroize_bytes(&mut m_prime);
    zeroize_bytes(&mut kr_prime);

    let ok = ct_eq_slices(ct, &c_prime);
    let mut k_bar = [0u8; 32];
    k_bar.copy_from_slice(&k_bar_vec);
    zeroize_bytes(&mut k_bar_vec);

    let mut shared = [0u8; 32];
    ct_select_bytes(&mut shared, &k_prime, &k_bar, ok);
    zeroize_bytes(&mut k_bar);
    Ok(shared)
}

// ============================================================================
// Sovereign Post-Quantum + Classical Hybrid KEM (ML-KEM-1024 + X25519)
// Combines NIST Category-5 Lattice + Curve25519 via Dual PRF (HKDF-SHA512 ^ KMAC256)
// ============================================================================

pub(crate) const PQ_HYBRID_PUB_BYTES: usize = 32 + MLKEM1024_EK_BYTES; // 1600 bytes
pub(crate) const PQ_HYBRID_SEC_BYTES: usize = 32 + MLKEM1024_DK_BYTES; // 3200 bytes
pub(crate) const PQ_HYBRID_CT_BYTES: usize = 32 + MLKEM1024_CT_BYTES; // 1600 bytes

pub(crate) fn pq_hybrid_keygen() -> (String, String) {
    let mut x_sk = [0u8; 32];
    OsRng.fill_bytes(&mut x_sk);
    let x_pk = x25519_public(&x_sk);
    let (ml_ek, mut ml_dk) = mlkem1024_keygen();

    let mut pub_raw = Vec::with_capacity(PQ_HYBRID_PUB_BYTES);
    pub_raw.extend_from_slice(&x_pk);
    pub_raw.extend_from_slice(&ml_ek);

    let mut sec_raw = Vec::with_capacity(PQ_HYBRID_SEC_BYTES);
    sec_raw.extend_from_slice(&x_sk);
    sec_raw.extend_from_slice(&ml_dk);

    zeroize_bytes(&mut x_sk);
    zeroize_bytes(&mut ml_dk);

    let pub_armored = format!("kvpq1pub:{}", bytes_to_hex(&pub_raw));
    let sec_armored = format!("kvpq1sec:{}", bytes_to_hex(&sec_raw));
    zeroize_bytes(&mut sec_raw);
    (pub_armored, sec_armored)
}

pub(crate) fn parse_pq_hybrid_pub(armored: &str) -> Result<Vec<u8>, String> {
    let hex = armored
        .trim()
        .strip_prefix("kvpq1pub:")
        .ok_or("expected PQ hybrid public key starting with 'kvpq1pub:'")?;
    let bytes = hex_to_bytes(hex)?;
    if bytes.len() != PQ_HYBRID_PUB_BYTES {
        return Err(format!(
            "invalid PQ hybrid public key length (expected {PQ_HYBRID_PUB_BYTES} bytes)"
        ));
    }
    Ok(bytes)
}

pub(crate) fn parse_pq_hybrid_sec(armored: &str) -> Result<Vec<u8>, String> {
    let hex = armored
        .trim()
        .strip_prefix("kvpq1sec:")
        .ok_or("expected PQ hybrid secret key starting with 'kvpq1sec:'")?;
    let bytes = hex_to_bytes(hex)?;
    if bytes.len() != PQ_HYBRID_SEC_BYTES {
        return Err(format!(
            "invalid PQ hybrid secret key length (expected {PQ_HYBRID_SEC_BYTES} bytes)"
        ));
    }
    Ok(bytes)
}

fn combine_hybrid_shared_512(
    ml_ss: &[u8; 32],
    x_ss: &[u8; 32],
    x_ephem_pk: &[u8; 32],
    ml_ct: &[u8],
    pub_bytes: &[u8],
) -> Result<[u8; 64], String> {
    let mut ikm = Vec::with_capacity(64 + 32 + ml_ct.len() + pub_bytes.len());
    ikm.extend_from_slice(ml_ss);
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(x_ephem_pk);
    ikm.extend_from_slice(ml_ct);
    ikm.extend_from_slice(pub_bytes);

    let mut combined = dual_prf_expand(&ikm, b"kovrek-pq-hybrid-v1", b"MLKEM1024+X25519", 64)?;
    zeroize_bytes(&mut ikm);
    let out: [u8; 64] = combined.as_slice().try_into().unwrap();
    zeroize_bytes(&mut combined);
    Ok(out)
}

pub(crate) fn pq_hybrid_encaps_raw(pub_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 64]), String> {
    if pub_bytes.len() != PQ_HYBRID_PUB_BYTES {
        return Err("invalid PQ hybrid public key length".into());
    }
    let peer_x_pk: [u8; 32] = pub_bytes[..32].try_into().unwrap();
    let ml_ek = &pub_bytes[32..];

    let mut eph_sk = [0u8; 32];
    OsRng.fill_bytes(&mut eph_sk);
    let eph_pk = x25519_public(&eph_sk);
    let mut x_ss = x25519_shared_checked(&eph_sk, &peer_x_pk)?;
    zeroize_bytes(&mut eph_sk);

    let (ml_ct, mut ml_ss) = mlkem1024_encaps(ml_ek)?;
    let combined = combine_hybrid_shared_512(&ml_ss, &x_ss, &eph_pk, &ml_ct, pub_bytes)?;
    zeroize_bytes(&mut x_ss);
    zeroize_bytes(&mut ml_ss);

    let mut ct_wire = Vec::with_capacity(PQ_HYBRID_CT_BYTES);
    ct_wire.extend_from_slice(&eph_pk);
    ct_wire.extend_from_slice(&ml_ct);
    Ok((ct_wire, combined))
}

pub(crate) fn pq_hybrid_decaps_raw(sec_bytes: &[u8], ct_wire: &[u8]) -> Result<[u8; 64], String> {
    if sec_bytes.len() != PQ_HYBRID_SEC_BYTES {
        return Err("invalid PQ hybrid secret key length".into());
    }
    if ct_wire.len() != PQ_HYBRID_CT_BYTES {
        return Err("invalid PQ hybrid capsule length".into());
    }
    let mut x_sk: [u8; 32] = sec_bytes[..32].try_into().unwrap();
    let ml_dk = &sec_bytes[32..];
    let ml_ek_offset = 384 * MLKEM_K;
    let ml_ek = &ml_dk[ml_ek_offset..ml_ek_offset + MLKEM1024_EK_BYTES];
    let x_pk = x25519_public(&x_sk);

    let mut pub_bytes = Vec::with_capacity(PQ_HYBRID_PUB_BYTES);
    pub_bytes.extend_from_slice(&x_pk);
    pub_bytes.extend_from_slice(ml_ek);

    let eph_pk: [u8; 32] = ct_wire[..32].try_into().unwrap();
    let ml_ct = &ct_wire[32..];

    let mut x_ss = x25519_shared_checked(&x_sk, &eph_pk)?;
    zeroize_bytes(&mut x_sk);
    let mut ml_ss = mlkem1024_decaps(ml_dk, ml_ct)?;

    let combined = combine_hybrid_shared_512(&ml_ss, &x_ss, &eph_pk, ml_ct, &pub_bytes)?;
    zeroize_bytes(&mut x_ss);
    zeroize_bytes(&mut ml_ss);
    Ok(combined)
}

// ============================================================================
// Sovereign Post-Quantum Dual Signature Engine (ML-DSA-SIS + FORS-SHAKE256)
// ============================================================================
// Combines two mathematically orthogonal post-quantum signature families:
// 1. Module-LWE / Module-SIS Lattice Fiat-Shamir with Aborts (q = 8,380,417)
// 2. Stateless FORS-SHAKE256 Merkle Forest Authentication Paths (FIPS 202/205)

const PQSIG_Q: i64 = 8_380_417;
const PQSIG_N: usize = 64;
const PQSIG_K: usize = 3;
const PQSIG_L: usize = 3;
const PQSIG_ETA: i64 = 2;
const PQSIG_TAU: usize = 16;
const PQSIG_BETA: i64 = 32; // TAU * ETA
const PQSIG_GAMMA1: i64 = 131_072; // 2^17
const PQSIG_GAMMA2: i64 = 95_232; // (Q - 1) / 88
const PQSIG_ALPHA: i64 = 2 * PQSIG_GAMMA2;

const FORS_TREES: usize = 8;
const FORS_HEIGHT: usize = 4;
const FORS_LEAVES: usize = 1 << FORS_HEIGHT; // 16

const PQSIG_PUB_PREFIX: &str = "kvsign1pub:";
const PQSIG_SEC_PREFIX: &str = "kvsign1sec:";
const PQSIG_SIG_PREFIX: &str = "kvsign1sig:";

type SigPoly = [i64; PQSIG_N];

#[inline(always)]
fn mod_sig_q(x: i64) -> i64 {
    let r = x % PQSIG_Q;
    if r < 0 { r + PQSIG_Q } else { r }
}

fn sig_poly_add(a: &SigPoly, b: &SigPoly) -> SigPoly {
    let mut out = [0i64; PQSIG_N];
    for i in 0..PQSIG_N {
        out[i] = mod_sig_q(a[i] + b[i]);
    }
    out
}

fn sig_poly_sub(a: &SigPoly, b: &SigPoly) -> SigPoly {
    let mut out = [0i64; PQSIG_N];
    for i in 0..PQSIG_N {
        out[i] = mod_sig_q(a[i] - b[i]);
    }
    out
}

/// Negacyclic polynomial multiplication in Z_q[X]/(X^N + 1).
fn sig_poly_mul_mod(a: &SigPoly, b: &SigPoly) -> SigPoly {
    let mut out = [0i64; PQSIG_N];
    for i in 0..PQSIG_N {
        for j in 0..PQSIG_N {
            let prod = a[i] * b[j];
            if i + j < PQSIG_N {
                out[i + j] = (out[i + j] + prod) % PQSIG_Q;
            } else {
                out[i + j - PQSIG_N] = (out[i + j - PQSIG_N] - prod) % PQSIG_Q;
            }
        }
    }
    for coeff in &mut out {
        *coeff = mod_sig_q(*coeff);
    }
    out
}

/// Exact integer negacyclic multiplication (without mod q reduction) for c * s.
fn sig_poly_mul_int(a: &SigPoly, b: &SigPoly) -> SigPoly {
    let mut out = [0i64; PQSIG_N];
    for i in 0..PQSIG_N {
        for j in 0..PQSIG_N {
            let prod = a[i] * b[j];
            if i + j < PQSIG_N {
                out[i + j] += prod;
            } else {
                out[i + j - PQSIG_N] -= prod;
            }
        }
    }
    out
}

/// FIPS 204 Algorithm 36 Decompose(r, alpha = 2*gamma2): r = r1*alpha + r0 mod q.
fn sig_decompose(r: i64) -> (i64, i64) {
    let r_plus = mod_sig_q(r);
    let mut r0 = r_plus % PQSIG_ALPHA;
    if r0 > PQSIG_GAMMA2 {
        r0 -= PQSIG_ALPHA;
    }
    if r_plus - r0 == PQSIG_Q - 1 {
        (0, r0 - 1)
    } else {
        ((r_plus - r0) / PQSIG_ALPHA, r0)
    }
}

fn expand_sig_matrix_a(rho: &[u8; 32]) -> [[SigPoly; PQSIG_L]; PQSIG_K] {
    let mut mat = [[[0i64; PQSIG_N]; PQSIG_L]; PQSIG_K];
    for i in 0..PQSIG_K {
        for j in 0..PQSIG_L {
            let mut seed = [0u8; 36];
            seed[..32].copy_from_slice(rho);
            seed[32..36].copy_from_slice(&[b'A', i as u8, j as u8, 0]);
            let stream = shake128(&seed, PQSIG_N * 4);
            for k in 0..PQSIG_N {
                let raw = u32::from_le_bytes([
                    stream[k * 4],
                    stream[k * 4 + 1],
                    stream[k * 4 + 2],
                    stream[k * 4 + 3],
                ]) as i64;
                mat[i][j][k] = raw % PQSIG_Q;
            }
        }
    }
    mat
}

fn sample_eta_poly(seed: &[u8; 32], domain: u8, idx: u8) -> SigPoly {
    let mut inp = [0u8; 34];
    inp[..32].copy_from_slice(seed);
    inp[32] = domain;
    inp[33] = idx;
    let stream = shake256(&inp, PQSIG_N);
    let mut p = [0i64; PQSIG_N];
    for i in 0..PQSIG_N {
        p[i] = ((stream[i] % 5) as i64) - PQSIG_ETA;
    }
    p
}

fn sample_gamma1_poly(seed: &[u8; 32], kappa: u16, idx: u8) -> SigPoly {
    let mut inp = [0u8; 35];
    inp[..32].copy_from_slice(seed);
    inp[32..34].copy_from_slice(&kappa.to_le_bytes());
    inp[34] = idx;
    let stream = shake256(&inp, PQSIG_N * 4);
    let span = (2 * PQSIG_GAMMA1) as u64;
    let mut p = [0i64; PQSIG_N];
    for i in 0..PQSIG_N {
        let v = u32::from_le_bytes([
            stream[i * 4],
            stream[i * 4 + 1],
            stream[i * 4 + 2],
            stream[i * 4 + 3],
        ]) as u64;
        p[i] = (v % span) as i64 - (PQSIG_GAMMA1 - 1);
    }
    p
}

fn sample_challenge_ball(c_tilde: &[u8; 32]) -> SigPoly {
    let stream = shake256(c_tilde, 128);
    let mut c = [0i64; PQSIG_N];
    let signs = u64::from_le_bytes(stream[0..8].try_into().unwrap());
    let mut pos = 8usize;
    for i in (PQSIG_N - PQSIG_TAU)..PQSIG_N {
        let j = (stream[pos] as usize) % (i + 1);
        pos += 1;
        c[i] = c[j];
        let bit = (signs >> (i - (PQSIG_N - PQSIG_TAU))) & 1;
        c[j] = if bit == 1 { -1 } else { 1 };
    }
    c
}

fn fors_leaf_secret(fors_seed: &[u8; 32], tree: usize, leaf: usize) -> [u8; 32] {
    let mut inp = [0u8; 36];
    inp[..32].copy_from_slice(fors_seed);
    inp[32] = b'F';
    inp[33] = tree as u8;
    inp[34..36].copy_from_slice(&(leaf as u16).to_le_bytes());
    let out = shake256(&inp, 32);
    out.as_slice().try_into().unwrap()
}

fn fors_node_hash(
    pub_seed: &[u8; 32],
    tree: usize,
    level: usize,
    idx: usize,
    val: &[u8],
) -> [u8; 32] {
    let mut inp = Vec::with_capacity(38 + val.len());
    inp.extend_from_slice(pub_seed);
    inp.push(b'N');
    inp.push(tree as u8);
    inp.push(level as u8);
    inp.push(idx as u8);
    inp.extend_from_slice(val);
    sha3_256(&inp)
}

fn fors_build_tree(fors_seed: &[u8; 32], pub_seed: &[u8; 32], tree: usize) -> Vec<Vec<[u8; 32]>> {
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::with_capacity(FORS_HEIGHT + 1);
    let mut cur = Vec::with_capacity(FORS_LEAVES);
    for l in 0..FORS_LEAVES {
        let sk = fors_leaf_secret(fors_seed, tree, l);
        cur.push(fors_node_hash(pub_seed, tree, 0, l, &sk));
    }
    levels.push(cur);
    for lvl in 0..FORS_HEIGHT {
        let prev = &levels[lvl];
        let mut next = Vec::with_capacity(prev.len() / 2);
        for i in 0..(prev.len() / 2) {
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&prev[2 * i]);
            pair[32..].copy_from_slice(&prev[2 * i + 1]);
            next.push(fors_node_hash(pub_seed, tree, lvl + 1, i, &pair));
        }
        levels.push(next);
    }
    levels
}

fn fors_compute_root(fors_seed: &[u8; 32], pub_seed: &[u8; 32]) -> [u8; 32] {
    let mut roots_concat = Vec::with_capacity(FORS_TREES * 32);
    for t in 0..FORS_TREES {
        let levels = fors_build_tree(fors_seed, pub_seed, t);
        roots_concat.extend_from_slice(&levels[FORS_HEIGHT][0]);
    }
    sha3_256(&roots_concat)
}

pub(crate) fn pq_sign_keygen_deterministic(master_seed: &[u8; 32]) -> (String, String) {
    let expanded = shake256(master_seed, 96);
    let rho: [u8; 32] = expanded[0..32].try_into().unwrap();
    let s_seed: [u8; 32] = expanded[32..64].try_into().unwrap();
    let fors_seed: [u8; 32] = expanded[64..96].try_into().unwrap();

    let mat_a = expand_sig_matrix_a(&rho);
    let mut s1 = [[0i64; PQSIG_N]; PQSIG_L];
    let mut s2 = [[0i64; PQSIG_N]; PQSIG_K];
    for j in 0..PQSIG_L {
        s1[j] = sample_eta_poly(&s_seed, b'1', j as u8);
    }
    for i in 0..PQSIG_K {
        s2[i] = sample_eta_poly(&s_seed, b'2', i as u8);
    }

    let mut t = [[0i64; PQSIG_N]; PQSIG_K];
    for i in 0..PQSIG_K {
        let mut acc = [0i64; PQSIG_N];
        for j in 0..PQSIG_L {
            let prod = sig_poly_mul_mod(&mat_a[i][j], &s1[j]);
            acc = sig_poly_add(&acc, &prod);
        }
        t[i] = sig_poly_add(&acc, &s2[i]);
    }

    let fors_root = fors_compute_root(&fors_seed, &rho);

    // Public key wire: rho(32) || fors_root(32) || t(3 * 64 * 4 = 768) = 832 bytes
    let mut pub_bytes = Vec::with_capacity(64 + PQSIG_K * PQSIG_N * 4);
    pub_bytes.extend_from_slice(&rho);
    pub_bytes.extend_from_slice(&fors_root);
    for i in 0..PQSIG_K {
        for k in 0..PQSIG_N {
            pub_bytes.extend_from_slice(&(t[i][k] as u32).to_le_bytes());
        }
    }

    // Secret key wire: master_seed(32) || pub_bytes(832) = 864 bytes
    let mut sec_bytes = Vec::with_capacity(32 + pub_bytes.len());
    sec_bytes.extend_from_slice(master_seed);
    sec_bytes.extend_from_slice(&pub_bytes);

    (
        format!("{PQSIG_PUB_PREFIX}{}", bytes_to_hex(&pub_bytes)),
        format!("{PQSIG_SEC_PREFIX}{}", bytes_to_hex(&sec_bytes)),
    )
}

pub(crate) fn pq_sign_keygen() -> (String, String) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let out = pq_sign_keygen_deterministic(&seed);
    zeroize_bytes(&mut seed);
    out
}

pub(crate) fn pq_sign(armored_sec: &str, msg: &[u8]) -> Result<String, String> {
    let trimmed = armored_sec.trim();
    let hex_part = trimmed
        .strip_prefix(PQSIG_SEC_PREFIX)
        .ok_or("secret key must start with 'kvsign1sec:'")?;
    let mut sec_bytes = hex_to_bytes(hex_part)?;
    let expected_len = 32 + 64 + PQSIG_K * PQSIG_N * 4;
    if sec_bytes.len() != expected_len {
        zeroize_bytes(&mut sec_bytes);
        return Err("invalid post-quantum signing secret key length".into());
    }
    let mut master_seed = [0u8; 32];
    master_seed.copy_from_slice(&sec_bytes[0..32]);
    let pub_bytes = sec_bytes[32..].to_vec();
    zeroize_bytes(&mut sec_bytes);

    let mut expanded = shake256(&master_seed, 96);
    zeroize_bytes(&mut master_seed);
    let rho: [u8; 32] = expanded[0..32].try_into().unwrap();
    let s_seed: [u8; 32] = expanded[32..64].try_into().unwrap();
    let fors_seed: [u8; 32] = expanded[64..96].try_into().unwrap();
    zeroize_bytes(&mut expanded);

    let mat_a = expand_sig_matrix_a(&rho);
    let mut s1 = [[0i64; PQSIG_N]; PQSIG_L];
    let mut s2 = [[0i64; PQSIG_N]; PQSIG_K];
    for j in 0..PQSIG_L {
        s1[j] = sample_eta_poly(&s_seed, b'1', j as u8);
    }
    for i in 0..PQSIG_K {
        s2[i] = sample_eta_poly(&s_seed, b'2', i as u8);
    }

    let tr = sha3_256(&pub_bytes);
    let mut mu_in = Vec::with_capacity(32 + msg.len());
    mu_in.extend_from_slice(&tr);
    mu_in.extend_from_slice(msg);
    let mu = sha3_512(&mu_in);

    // Build FORS authentication proof for message digest mu
    let mut fors_proof = Vec::with_capacity(FORS_TREES * (1 + FORS_HEIGHT) * 32);
    for t in 0..FORS_TREES {
        let leaf_idx = (mu[t] as usize) & (FORS_LEAVES - 1);
        let sk_leaf = fors_leaf_secret(&fors_seed, t, leaf_idx);
        fors_proof.extend_from_slice(&sk_leaf);
        let levels = fors_build_tree(&fors_seed, &rho, t);
        let mut idx = leaf_idx;
        for lvl in 0..FORS_HEIGHT {
            let sibling = idx ^ 1;
            fors_proof.extend_from_slice(&levels[lvl][sibling]);
            idx >>= 1;
        }
    }

    let mut rnd_seed_in = Vec::with_capacity(96);
    rnd_seed_in.extend_from_slice(&s_seed);
    rnd_seed_in.extend_from_slice(&mu);
    let y_seed: [u8; 32] = shake256(&rnd_seed_in, 32).as_slice().try_into().unwrap();
    zeroize_bytes(&mut rnd_seed_in);

    // Fiat-Shamir with Aborts rejection sampling loop
    for kappa in 0u16..1024 {
        let mut y = [[0i64; PQSIG_N]; PQSIG_L];
        for j in 0..PQSIG_L {
            y[j] = sample_gamma1_poly(&y_seed, kappa, j as u8);
        }

        let mut w = [[0i64; PQSIG_N]; PQSIG_K];
        let mut w1_bytes = Vec::with_capacity(PQSIG_K * PQSIG_N);
        for i in 0..PQSIG_K {
            let mut acc = [0i64; PQSIG_N];
            for j in 0..PQSIG_L {
                let prod = sig_poly_mul_mod(&mat_a[i][j], &y[j]);
                acc = sig_poly_add(&acc, &prod);
            }
            w[i] = acc;
            for k in 0..PQSIG_N {
                let (w1, _) = sig_decompose(w[i][k]);
                w1_bytes.push(w1 as u8);
            }
        }

        let mut ch_in = Vec::with_capacity(64 + w1_bytes.len());
        ch_in.extend_from_slice(&mu);
        ch_in.extend_from_slice(&w1_bytes);
        let c_tilde = sha3_256(&ch_in);
        let c_poly = sample_challenge_ball(&c_tilde);

        let mut z = [[0i64; PQSIG_N]; PQSIG_L];
        let mut reject = false;
        for j in 0..PQSIG_L {
            let cs1 = sig_poly_mul_int(&c_poly, &s1[j]);
            for k in 0..PQSIG_N {
                z[j][k] = y[j][k] + cs1[k];
                if z[j][k].abs() >= PQSIG_GAMMA1 - PQSIG_BETA {
                    reject = true;
                }
            }
        }
        if reject {
            continue;
        }

        for i in 0..PQSIG_K {
            let cs2 = sig_poly_mul_int(&c_poly, &s2[i]);
            for k in 0..PQSIG_N {
                let w_minus_cs2 = mod_sig_q(w[i][k] - cs2[k]);
                let (r1, r0) = sig_decompose(w_minus_cs2);
                if r0.abs() >= PQSIG_GAMMA2 - PQSIG_BETA || (r1 as u8) != w1_bytes[i * PQSIG_N + k]
                {
                    reject = true;
                }
            }
        }
        if reject {
            continue;
        }

        // Valid signature found: c_tilde(32) || z(3*64*4 = 768) || fors_proof(8*5*32 = 1280)
        let mut sig_wire = Vec::with_capacity(32 + PQSIG_L * PQSIG_N * 4 + fors_proof.len());
        sig_wire.extend_from_slice(&c_tilde);
        for j in 0..PQSIG_L {
            for k in 0..PQSIG_N {
                sig_wire.extend_from_slice(&(z[j][k] as i32).to_le_bytes());
            }
        }
        sig_wire.extend_from_slice(&fors_proof);
        return Ok(format!("{PQSIG_SIG_PREFIX}{}", bytes_to_hex(&sig_wire)));
    }
    Err("post-quantum lattice signature rejection loop exceeded bound".into())
}

pub(crate) fn pq_verify(armored_pub: &str, msg: &[u8], armored_sig: &str) -> Result<bool, String> {
    let pub_hex = armored_pub
        .trim()
        .strip_prefix(PQSIG_PUB_PREFIX)
        .ok_or("public key must start with 'kvsign1pub:'")?;
    let sig_hex = armored_sig
        .trim()
        .strip_prefix(PQSIG_SIG_PREFIX)
        .ok_or("signature must start with 'kvsign1sig:'")?;
    let pub_bytes = hex_to_bytes(pub_hex)?;
    let sig_bytes = hex_to_bytes(sig_hex)?;

    let expected_pub = 64 + PQSIG_K * PQSIG_N * 4;
    let fors_bytes_len = FORS_TREES * (1 + FORS_HEIGHT) * 32;
    let expected_sig = 32 + PQSIG_L * PQSIG_N * 4 + fors_bytes_len;
    if pub_bytes.len() != expected_pub || sig_bytes.len() != expected_sig {
        return Ok(false);
    }

    let rho: [u8; 32] = pub_bytes[0..32].try_into().unwrap();
    let expected_fors_root: [u8; 32] = pub_bytes[32..64].try_into().unwrap();
    let mut t = [[0i64; PQSIG_N]; PQSIG_K];
    let mut off = 64usize;
    for i in 0..PQSIG_K {
        for k in 0..PQSIG_N {
            let v = u32::from_le_bytes(pub_bytes[off..off + 4].try_into().unwrap()) as i64;
            if !(0..PQSIG_Q).contains(&v) {
                return Ok(false);
            }
            t[i][k] = v;
            off += 4;
        }
    }

    let c_tilde: [u8; 32] = sig_bytes[0..32].try_into().unwrap();
    let mut z = [[0i64; PQSIG_N]; PQSIG_L];
    let mut s_off = 32usize;
    for j in 0..PQSIG_L {
        for k in 0..PQSIG_N {
            let v = i32::from_le_bytes(sig_bytes[s_off..s_off + 4].try_into().unwrap()) as i64;
            if v.abs() >= PQSIG_GAMMA1 - PQSIG_BETA {
                return Ok(false);
            }
            z[j][k] = v;
            s_off += 4;
        }
    }
    let fors_proof = &sig_bytes[s_off..];

    let tr = sha3_256(&pub_bytes);
    let mut mu_in = Vec::with_capacity(32 + msg.len());
    mu_in.extend_from_slice(&tr);
    mu_in.extend_from_slice(msg);
    let mu = sha3_512(&mu_in);

    // 1. Verify FORS-SHAKE256 Merkle authentication paths
    let mut roots_concat = Vec::with_capacity(FORS_TREES * 32);
    let stride = (1 + FORS_HEIGHT) * 32;
    for tree in 0..FORS_TREES {
        let base = tree * stride;
        let sk_leaf = &fors_proof[base..base + 32];
        let mut idx = (mu[tree] as usize) & (FORS_LEAVES - 1);
        let mut node = fors_node_hash(&rho, tree, 0, idx, sk_leaf);
        for lvl in 0..FORS_HEIGHT {
            let sib_off = base + (1 + lvl) * 32;
            let sib = &fors_proof[sib_off..sib_off + 32];
            let mut pair = [0u8; 64];
            if idx & 1 == 0 {
                pair[..32].copy_from_slice(&node);
                pair[32..].copy_from_slice(sib);
            } else {
                pair[..32].copy_from_slice(sib);
                pair[32..].copy_from_slice(&node);
            }
            idx >>= 1;
            node = fors_node_hash(&rho, tree, lvl + 1, idx, &pair);
        }
        roots_concat.extend_from_slice(&node);
    }
    let recalc_fors_root = sha3_256(&roots_concat);
    let fors_ok = ct_eq_slices(&recalc_fors_root, &expected_fors_root);

    // 2. Verify Module-LWE / Module-SIS Lattice relation: HighBits(A*z - c*t) == w1
    let mat_a = expand_sig_matrix_a(&rho);
    let c_poly = sample_challenge_ball(&c_tilde);
    let mut w1_prime = Vec::with_capacity(PQSIG_K * PQSIG_N);
    for i in 0..PQSIG_K {
        let mut az = [0i64; PQSIG_N];
        for j in 0..PQSIG_L {
            let z_mod = z[j].map(mod_sig_q);
            let prod = sig_poly_mul_mod(&mat_a[i][j], &z_mod);
            az = sig_poly_add(&az, &prod);
        }
        let c_mod = c_poly.map(mod_sig_q);
        let ct_poly = sig_poly_mul_mod(&c_mod, &t[i]);
        let w_prime = sig_poly_sub(&az, &ct_poly);
        for k in 0..PQSIG_N {
            let (w1, _) = sig_decompose(w_prime[k]);
            w1_prime.push(w1 as u8);
        }
    }

    let mut ch_in = Vec::with_capacity(64 + w1_prime.len());
    ch_in.extend_from_slice(&mu);
    ch_in.extend_from_slice(&w1_prime);
    let recalc_c = sha3_256(&ch_in);
    let lattice_ok = ct_eq_slices(&recalc_c, &c_tilde);

    Ok((fors_ok & lattice_ok) == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips202_sha3_and_kmac256_official_vectors() {
        // NIST FIPS 202 empty input test vectors
        assert_eq!(
            bytes_to_hex(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            bytes_to_hex(&sha3_512(b"")),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        assert_eq!(
            bytes_to_hex(&shake256(b"abc", 32)),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        );

        // NIST SP 800-185 KMAC256 official Sample #4 (S = "My Tagged Application", L = 512 bits)
        let key = hex_to_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
            .unwrap();
        let data = hex_to_bytes("00010203").unwrap();
        assert_eq!(
            bytes_to_hex(&kmac256(&key, b"My Tagged Application", &data, 64)),
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"
        );
    }

    #[test]
    fn rfc7693_blake2b_and_rfc9106_argon2id_vectors() {
        // RFC 7693 Appendix A: BLAKE2b-512("abc")
        assert_eq!(
            bytes_to_hex(&blake2b(b"abc", &[], 64).unwrap()),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );

        // RFC 9106 Section 5.3: Argon2id(p=4, T=32, m=32, t=3, v=0x13,
        // password=0x01*32, salt=0x02*16, key=0x03*8, ad=0x04*12)
        let pw = vec![0x01u8; 32];
        let salt = vec![0x02u8; 16];
        let secret = vec![0x03u8; 8];
        let ad = vec![0x04u8; 12];
        let tag = argon2id_with_extras(&pw, &salt, &secret, &ad, 32, 3, 4, 32).unwrap();
        assert_eq!(
            bytes_to_hex(&tag),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn rfc7748_x25519_official_vectors() {
        // RFC 7748 Section 6.1 test vector
        let alice_priv: [u8; 32] =
            hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let alice_pub_expected = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        let bob_priv: [u8; 32] =
            hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .unwrap()
                .try_into()
                .unwrap();
        let bob_pub_expected = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        let shared_expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        let a_pub = x25519_public(&alice_priv);
        let b_pub = x25519_public(&bob_priv);
        assert_eq!(bytes_to_hex(&a_pub), alice_pub_expected);
        assert_eq!(bytes_to_hex(&b_pub), bob_pub_expected);

        let ss_ab = x25519_shared_checked(&alice_priv, &b_pub).unwrap();
        let ss_ba = x25519_shared_checked(&bob_priv, &a_pub).unwrap();
        assert_eq!(bytes_to_hex(&ss_ab), shared_expected);
        assert_eq!(ss_ab, ss_ba);

        // Low-order / all-zero point must be rejected
        assert!(x25519_shared_checked(&alice_priv, &[0u8; 32]).is_err());
    }

    #[test]
    fn fips203_mlkem1024_roundtrip_implicit_rejection_and_modulus_check() {
        let d = [0x11u8; 32];
        let z = [0x22u8; 32];
        let m = [0x33u8; 32];
        let (ek, dk) = mlkem1024_keygen_deterministic(&d, &z);
        assert_eq!(ek.len(), MLKEM1024_EK_BYTES);
        assert_eq!(dk.len(), MLKEM1024_DK_BYTES);

        let (mut ct, ss_enc) = mlkem1024_encaps_deterministic(&ek, &m).unwrap();
        assert_eq!(ct.len(), MLKEM1024_CT_BYTES);
        let ss_dec = mlkem1024_decaps(&dk, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);

        // FIPS 203 FO implicit rejection: flipping a ciphertext bit yields J(z || c), not error and not ss_enc
        ct[10] ^= 0x80;
        let ss_tampered = mlkem1024_decaps(&dk, &ct).unwrap();
        assert_ne!(ss_tampered, ss_enc);
        let mut expected_reject_in = Vec::with_capacity(32 + ct.len());
        expected_reject_in.extend_from_slice(&z);
        expected_reject_in.extend_from_slice(&ct);
        assert_eq!(ss_tampered.to_vec(), shake256(&expected_reject_in, 32));

        // Invalid non-canonical encapsulation key coefficient (>= 3329) rejected
        let mut bad_ek = ek.clone();
        bad_ek[0] = 0xff;
        bad_ek[1] = 0xff;
        assert!(mlkem1024_encaps_deterministic(&bad_ek, &m).is_err());
    }

    #[test]
    fn sovereign_pq_hybrid_kem_512_roundtrip_and_tamper_resistance() {
        let (pub_arm, sec_arm) = pq_hybrid_keygen();
        let pub_raw = parse_pq_hybrid_pub(&pub_arm).unwrap();
        let sec_raw = parse_pq_hybrid_sec(&sec_arm).unwrap();
        assert_eq!(pub_raw.len(), PQ_HYBRID_PUB_BYTES);
        assert_eq!(sec_raw.len(), PQ_HYBRID_SEC_BYTES);

        let (mut ct_wire, ss_enc) = pq_hybrid_encaps_raw(&pub_raw).unwrap();
        assert_eq!(ct_wire.len(), PQ_HYBRID_CT_BYTES);
        let ss_dec = pq_hybrid_decaps_raw(&sec_raw, &ct_wire).unwrap();
        assert_eq!(ss_enc, ss_dec);

        // Tampering ML-KEM-1024 half of the hybrid capsule silently produces completely unrelated hybrid secret
        ct_wire[48] ^= 0x01;
        let ss_bad = pq_hybrid_decaps_raw(&sec_raw, &ct_wire).unwrap();
        assert_ne!(ss_bad, ss_enc);

        // Wrong keypair fails cleanly
        let (_, other_sec) = pq_hybrid_keygen();
        let other_sec_raw = parse_pq_hybrid_sec(&other_sec).unwrap();
        let ss_wrong = pq_hybrid_decaps_raw(&other_sec_raw, &ct_wire).unwrap();
        assert_ne!(ss_wrong, ss_enc);
    }

    #[test]
    fn sovereign_pq_dual_lattice_and_hash_signatures_roundtrip_and_tamper() {
        let (pub_key, sec_key) = pq_sign_keygen_deterministic(&[0x42u8; 32]);
        let msg = b"Kovrek Multi-Century Sovereign Code & Vault Signature";
        let sig = pq_sign(&sec_key, msg).unwrap();
        assert!(pq_verify(&pub_key, msg, &sig).unwrap());

        // Tampered message must fail
        assert!(!pq_verify(&pub_key, b"Tampered message", &sig).unwrap());

        // Tampered signature byte (in either lattice z or FORS path) must fail
        let last_ch = if sig.ends_with('a') { 'b' } else { 'a' };
        let bad_sig = format!("{}{last_ch}", &sig[..sig.len() - 1]);
        assert!(!pq_verify(&pub_key, msg, &bad_sig).unwrap());

        // Wrong public key must fail
        let (other_pub, _) = pq_sign_keygen_deterministic(&[0x99u8; 32]);
        assert!(!pq_verify(&other_pub, msg, &sig).unwrap());
    }
}
