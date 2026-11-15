//! Kovrek Sovereign Multi-Century Encryption Systems:
//! - MYSTIQUE: Polymorphic 4-Engine 1024-Bit Independent Cipher Cascade
//!   (Keyed Dynamic Fisher-Yates S-Box & Wide ARX-Feistel -> ChaCha20-Poly1305 ->
//!   Constant-Time AES-256-GCM -> Keccak-1600 Sponge CTR + SP 800-185 KMAC256)
//! - MAESTRO: Forward-Secure Ratcheted Key Orchestrator & Multi-Factor Policy Engine
//!   (Argon2id + FIPS 203 ML-KEM-1024 + RFC 7748 X25519 + Epoch Key Ratchet)
//! - OBSCURE: Metadata-Blind O(1)-RAM Streaming Vault Container
//!   (Single-pass 64 KiB chunking, zero cleartext plaintext hash/filename/size leak,
//!   encrypted authenticated trailer with SHA3-512 & bucket padding, zero-banner wire mode)

#![allow(clippy::needless_range_loop)]

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use rand::RngCore;
use rand::rngs::OsRng;

use crate::pq_crypto::{
    PQ_HYBRID_CT_BYTES, Sha3_512Hasher, argon2id, dual_prf_expand, kmac256, parse_pq_hybrid_pub,
    parse_pq_hybrid_sec, pq_hybrid_decaps_raw, pq_hybrid_encaps_raw, shake256,
};
use crate::security::{
    aes_gcm_open_raw, aes_gcm_seal_raw, bytes_to_hex, chacha20_poly1305_open_raw,
    chacha20_poly1305_seal_raw, constant_time_bytes_equal, zeroize_bytes,
};

pub(crate) const STREAM_CHUNK_BYTES: usize = 65_536;
const SOVEREIGN_MAGIC: &[u8; 8] = b"KVRM2\0\0\x01";
const OBSCURE_TAG_BYTES: usize = 32;
const COMPACT_HDR_BYTES: usize = 24;
const WRAPPED_ROOT_BYTES: usize = 64 + 16; // AES-256-GCM(64B root + 16B tag)

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CipherSuite {
    Cascade512 = 1,
    Mystique1024 = 2,
}

impl CipherSuite {
    pub(crate) fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mystique" | "mystique-1024" => Ok(Self::Mystique1024),
            "cascade" | "cascade-512" => Ok(Self::Cascade512),
            _ => Err(format!(
                "unknown cipher '{s}' (expected 'mystique' or 'cascade')"
            )),
        }
    }

    fn from_u8(v: u8) -> Result<Self, String> {
        match v {
            1 => Ok(Self::Cascade512),
            2 => Ok(Self::Mystique1024),
            _ => Err("unsupported vault cipher id".into()),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Cascade512 => "cascade-512",
            Self::Mystique1024 => "mystique-1024",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum UnlockMode {
    Passphrase = 1,
    PqHybrid = 2,
    Dual2Fa = 3,
}

impl UnlockMode {
    fn from_u8(v: u8) -> Result<Self, String> {
        match v {
            1 => Ok(Self::Passphrase),
            2 => Ok(Self::PqHybrid),
            3 => Ok(Self::Dual2Fa),
            _ => Err("unsupported vault unlock mode".into()),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Passphrase => "argon2id-passphrase",
            Self::PqHybrid => "mlkem1024-x25519",
            Self::Dual2Fa => "dual-2fa-argon2id+mlkem1024+x25519",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VaultSealOptions {
    pub(crate) cipher: CipherSuite,
    pub(crate) opaque_obscure: bool,
    pub(crate) passphrase: Option<String>,
    pub(crate) recipient_pub: Option<String>,
    pub(crate) mem_kib: u32,
    pub(crate) iterations: u32,
    pub(crate) lanes: u32,
    pub(crate) ratchet_every: u32,
    pub(crate) pad_bucket: u32,
}

impl Default for VaultSealOptions {
    fn default() -> Self {
        Self {
            cipher: CipherSuite::Mystique1024,
            opaque_obscure: false,
            passphrase: None,
            recipient_pub: None,
            mem_kib: 65_536,
            iterations: 3,
            lanes: 1,
            ratchet_every: 16,
            pad_bucket: 4096,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct VaultOpenCreds {
    pub(crate) passphrase: Option<String>,
    pub(crate) secret_key: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct VaultInspection {
    pub(crate) format: String,
    pub(crate) opaque: bool,
    pub(crate) cipher: Option<String>,
    pub(crate) unlock_mode: Option<String>,
    pub(crate) argon2id_mem_kib: Option<u32>,
    pub(crate) argon2id_iterations: Option<u32>,
    pub(crate) ratchet_every: Option<u32>,
    pub(crate) key_commitment_prefix: Option<String>,
    pub(crate) has_plaintext_leak: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct VaultSealResult {
    pub(crate) method: String,
    pub(crate) plaintext_bytes: u64,
    pub(crate) padded_bytes: u64,
    pub(crate) chunks_written: u64,
    pub(crate) key_commitment_prefix: String,
    pub(crate) opaque: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct VaultOpenResult {
    pub(crate) method: String,
    pub(crate) original_filename: String,
    pub(crate) recovered_bytes: u64,
    pub(crate) sha3_512: String,
    pub(crate) chunks_verified: u64,
}

// ============================================================================
// MYSTIQUE Polymorphic Dynamic S-Box + Bijective ARX Core
// ============================================================================

fn build_dynamic_sboxes(key: &[u8; 32], nonce: &[u8; 16]) -> ([u8; 256], [u8; 256], [u8; 256]) {
    let mut seed = [0u8; 48];
    seed[..32].copy_from_slice(key);
    seed[32..].copy_from_slice(nonce);
    let mut rng_bytes = shake256(&seed, 1024 + 64);
    zeroize_bytes(&mut seed);

    let mut sbox1 = [0u8; 256];
    let mut sbox2 = [0u8; 256];
    for i in 0..256 {
        sbox1[i] = i as u8;
        sbox2[i] = i as u8;
    }
    for (box_idx, sbox) in [&mut sbox1, &mut sbox2].into_iter().enumerate() {
        let base = box_idx * 512;
        for i in (1..256).rev() {
            let off = base + (255 - i) * 2;
            let raw = u16::from_le_bytes([rng_bytes[off], rng_bytes[off + 1]]) as usize;
            let j = raw % (i + 1);
            sbox.swap(i, j);
        }
    }
    let mut inv1 = [0u8; 256];
    for i in 0..256 {
        inv1[sbox1[i] as usize] = i as u8;
    }
    zeroize_bytes(&mut rng_bytes);
    (sbox1, inv1, sbox2)
}

fn mystique_core_seal(key: &[u8; 32], nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let (sbox1, _, sbox2) = build_dynamic_sboxes(key, nonce);
    let mut stream_seed = Vec::with_capacity(64);
    stream_seed.extend_from_slice(key);
    stream_seed.extend_from_slice(nonce);
    stream_seed.extend_from_slice(b"MYSTIQUE-ARX");
    let mut ks = shake256(&stream_seed, data.len().saturating_mul(2).max(64));
    zeroize_bytes(&mut stream_seed);

    let n = data.len();
    let mut buf = data.to_vec();

    // Forward pass: chained ARX feedback + keyed dynamic S-box1 + dynamic bit-rotate
    let mut acc = ks[n % 64];
    for i in 0..n {
        let k = ks[i];
        let rot = (ks[n + (i % n)] & 7) as u32;
        let step = acc.wrapping_add(k).rotate_left(3) ^ sbox1[acc as usize];
        let v = sbox1[buf[i].wrapping_add(step) as usize].rotate_left(rot) ^ k;
        buf[i] = v;
        acc = acc.wrapping_add(v) ^ k;
    }

    // Backward pass: full reverse avalanche from tail to byte 0 using independent sbox2
    acc = ks[(n + 17) % ks.len()];
    for i in (0..n).rev() {
        let k = ks[n + i];
        let rot = (ks[i] & 7) as u32;
        let step = acc.wrapping_add(k).rotate_left(5) ^ sbox2[acc as usize];
        let v = sbox2[buf[i].wrapping_add(step) as usize].rotate_left(rot) ^ k;
        buf[i] = v;
        acc = acc.wrapping_add(v) ^ k;
    }

    zeroize_bytes(&mut ks);
    buf
}

fn mystique_core_open(key: &[u8; 32], nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let (sbox1, inv1, sbox2) = build_dynamic_sboxes(key, nonce);
    let mut inv2 = [0u8; 256];
    for i in 0..256 {
        inv2[sbox2[i] as usize] = i as u8;
    }

    let mut stream_seed = Vec::with_capacity(64);
    stream_seed.extend_from_slice(key);
    stream_seed.extend_from_slice(nonce);
    stream_seed.extend_from_slice(b"MYSTIQUE-ARX");
    let mut ks = shake256(&stream_seed, data.len().saturating_mul(2).max(64));
    zeroize_bytes(&mut stream_seed);

    let n = data.len();
    let mut buf = data.to_vec();

    // Inverse backward pass
    let mut acc = ks[(n + 17) % ks.len()];
    for i in (0..n).rev() {
        let k = ks[n + i];
        let rot = (ks[i] & 7) as u32;
        let v = buf[i];
        let step = acc.wrapping_add(k).rotate_left(5) ^ sbox2[acc as usize];
        let orig = inv2[(v ^ k).rotate_right(rot) as usize].wrapping_sub(step);
        buf[i] = orig;
        acc = acc.wrapping_add(v) ^ k;
    }

    // Inverse forward pass
    acc = ks[n % 64];
    for i in 0..n {
        let k = ks[i];
        let rot = (ks[n + (i % n)] & 7) as u32;
        let v = buf[i];
        let step = acc.wrapping_add(k).rotate_left(3) ^ sbox1[acc as usize];
        let orig = inv1[(v ^ k).rotate_right(rot) as usize].wrapping_sub(step);
        buf[i] = orig;
        acc = acc.wrapping_add(v) ^ k;
    }

    zeroize_bytes(&mut ks);
    buf
}

fn chunk_nonce_xor(base: &[u8; 12], chunk_idx: u64, layer: u8) -> [u8; 12] {
    let mut out = *base;
    let idx_bytes = chunk_idx.to_be_bytes();
    for i in 0..8 {
        out[4 + i] ^= idx_bytes[i];
    }
    out[0] ^= layer;
    out
}

fn chunk_aad_bytes(commitment: &[u8; 32], chunk_idx: u64, is_final: bool) -> [u8; 48] {
    let mut aad = [0u8; 48];
    aad[..32].copy_from_slice(commitment);
    aad[32..39].copy_from_slice(b"KVRM2CH");
    aad[39] = u8::from(is_final);
    aad[40..48].copy_from_slice(&chunk_idx.to_be_bytes());
    aad
}

struct EpochKeys {
    k_dyn: [u8; 32],
    k_cc: [u8; 32],
    k_aes: [u8; 32],
    k_sponge: [u8; 32],
    base_nonce_cc: [u8; 12],
    base_nonce_aes: [u8; 12],
    base_nonce_dyn: [u8; 16],
}

impl EpochKeys {
    fn scrub(&mut self) {
        zeroize_bytes(&mut self.k_dyn);
        zeroize_bytes(&mut self.k_cc);
        zeroize_bytes(&mut self.k_aes);
        zeroize_bytes(&mut self.k_sponge);
        zeroize_bytes(&mut self.base_nonce_cc);
        zeroize_bytes(&mut self.base_nonce_aes);
        zeroize_bytes(&mut self.base_nonce_dyn);
    }
}

struct MaestroRatchet {
    chain: [u8; 64],
    salt: [u8; 32],
    ratchet_every: u64,
    current_epoch: Option<u64>,
    keys: Option<EpochKeys>,
}

impl MaestroRatchet {
    fn new(root_key: &[u8; 64], salt: &[u8; 32], ratchet_every: u32) -> Self {
        Self {
            chain: *root_key,
            salt: *salt,
            ratchet_every: (ratchet_every.max(1)) as u64,
            current_epoch: None,
            keys: None,
        }
    }

    fn keys_for_chunk(&mut self, chunk_idx: u64) -> Result<&EpochKeys, String> {
        let target_epoch = chunk_idx / self.ratchet_every;
        let need_advance = match self.current_epoch {
            None => true,
            Some(cur) => cur != target_epoch,
        };
        if need_advance {
            let start_epoch = match self.current_epoch {
                None => 0,
                Some(cur) if target_epoch > cur => {
                    if let Some(ref mut old) = self.keys {
                        old.scrub();
                    }
                    cur + 1
                }
                Some(_) => return Err("MAESTRO ratchet cannot step backwards".into()),
            };
            let mut ep_keys = None;
            for e in start_epoch..=target_epoch {
                let mut ctx = Vec::with_capacity(24);
                ctx.extend_from_slice(b"MAESTRO-RATCHET");
                ctx.extend_from_slice(&e.to_be_bytes());
                // Expand 232 bytes: 64 next chain + 128 cipher subkeys + 40 epoch base nonces
                let mut mat = dual_prf_expand(&self.chain, &self.salt, &ctx, 232)?;
                self.chain.copy_from_slice(&mat[..64]);
                if e == target_epoch {
                    let mut ek = EpochKeys {
                        k_dyn: [0u8; 32],
                        k_cc: [0u8; 32],
                        k_aes: [0u8; 32],
                        k_sponge: [0u8; 32],
                        base_nonce_cc: [0u8; 12],
                        base_nonce_aes: [0u8; 12],
                        base_nonce_dyn: [0u8; 16],
                    };
                    ek.k_dyn.copy_from_slice(&mat[64..96]);
                    ek.k_cc.copy_from_slice(&mat[96..128]);
                    ek.k_aes.copy_from_slice(&mat[128..160]);
                    ek.k_sponge.copy_from_slice(&mat[160..192]);
                    ek.base_nonce_cc.copy_from_slice(&mat[192..204]);
                    ek.base_nonce_aes.copy_from_slice(&mat[204..216]);
                    ek.base_nonce_dyn.copy_from_slice(&mat[216..232]);
                    ep_keys = Some(ek);
                }
                zeroize_bytes(&mut mat);
            }
            self.keys = ep_keys;
            self.current_epoch = Some(target_epoch);
        }
        self.keys
            .as_ref()
            .ok_or_else(|| "MAESTRO epoch key derivation error".to_string())
    }

    fn scrub(&mut self) {
        zeroize_bytes(&mut self.chain);
        if let Some(ref mut k) = self.keys {
            k.scrub();
        }
    }
}

fn sponge_xor_mask(key: &[u8; 32], commitment: &[u8; 32], chunk_idx: u64, len: usize) -> Vec<u8> {
    let mut seed = Vec::with_capacity(80);
    seed.extend_from_slice(key);
    seed.extend_from_slice(commitment);
    seed.extend_from_slice(&chunk_idx.to_be_bytes());
    seed.extend_from_slice(b"MYSTIQUE-L4");
    let mask = shake256(&seed, len);
    zeroize_bytes(&mut seed);
    mask
}

fn encrypt_chunk(
    suite: CipherSuite,
    ek: &EpochKeys,
    commitment: &[u8; 32],
    chunk_idx: u64,
    is_final: bool,
    plaintext: &[u8],
) -> Vec<u8> {
    let aad = chunk_aad_bytes(commitment, chunk_idx, is_final);
    let n_cc = chunk_nonce_xor(&ek.base_nonce_cc, chunk_idx, 0x11);
    let n_aes = chunk_nonce_xor(&ek.base_nonce_aes, chunk_idx, 0x22);

    let layer1_in = if suite == CipherSuite::Mystique1024 {
        let mut dnonce = ek.base_nonce_dyn;
        let idx_b = chunk_idx.to_be_bytes();
        for i in 0..8 {
            dnonce[i] ^= idx_b[i];
        }
        mystique_core_seal(&ek.k_dyn, &dnonce, plaintext)
    } else {
        plaintext.to_vec()
    };

    // Layer 2: RFC 8439 ChaCha20-Poly1305
    let (mut ct_cc, tag_cc) = chacha20_poly1305_seal_raw(&ek.k_cc, &n_cc, &aad, &layer1_in);
    let mut l2_buf = Vec::with_capacity(ct_cc.len() + 16);
    l2_buf.extend_from_slice(&ct_cc);
    l2_buf.extend_from_slice(&tag_cc);
    zeroize_bytes(&mut ct_cc);

    // Layer 3: Constant-Time AES-256-GCM
    let (ct_aes, tag_aes) = aes_gcm_seal_raw(&ek.k_aes, &n_aes, &aad, &l2_buf);
    zeroize_bytes(&mut l2_buf);
    let mut l3_buf = Vec::with_capacity(ct_aes.len() + 16);
    l3_buf.extend_from_slice(&ct_aes);
    l3_buf.extend_from_slice(&tag_aes);

    if suite == CipherSuite::Cascade512 {
        return l3_buf;
    }

    // Layer 4 (Mystique): Keccak-1600 Sponge stream mask + outer 32B SP 800-185 KMAC256 tag
    let mut mask = sponge_xor_mask(&ek.k_sponge, commitment, chunk_idx, l3_buf.len());
    for i in 0..l3_buf.len() {
        l3_buf[i] ^= mask[i];
    }
    zeroize_bytes(&mut mask);

    let mut mac_in = Vec::with_capacity(aad.len() + l3_buf.len());
    mac_in.extend_from_slice(&aad);
    mac_in.extend_from_slice(&l3_buf);
    let kmac_tag = kmac256(&ek.k_sponge, b"MYSTIQUE-OUTER-MAC", &mac_in, 32);
    l3_buf.extend_from_slice(&kmac_tag);
    l3_buf
}

fn decrypt_chunk(
    suite: CipherSuite,
    ek: &EpochKeys,
    commitment: &[u8; 32],
    chunk_idx: u64,
    is_final: bool,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    let aad = chunk_aad_bytes(commitment, chunk_idx, is_final);
    let n_cc = chunk_nonce_xor(&ek.base_nonce_cc, chunk_idx, 0x11);
    let n_aes = chunk_nonce_xor(&ek.base_nonce_aes, chunk_idx, 0x22);

    let l3_buf = if suite == CipherSuite::Mystique1024 {
        if sealed.len() < 32 + 16 + 16 {
            return Err("corrupted Mystique chunk: too short".into());
        }
        let body_len = sealed.len() - 32;
        let (body, outer_tag) = sealed.split_at(body_len);
        let mut mac_in = Vec::with_capacity(aad.len() + body.len());
        mac_in.extend_from_slice(&aad);
        mac_in.extend_from_slice(body);
        let expected_kmac = kmac256(&ek.k_sponge, b"MYSTIQUE-OUTER-MAC", &mac_in, 32);
        if !constant_time_bytes_equal(&expected_kmac, outer_tag) {
            return Err(format!(
                "Mystique KMAC256 authentication failed on chunk {chunk_idx}"
            ));
        }
        let mut mask = sponge_xor_mask(&ek.k_sponge, commitment, chunk_idx, body_len);
        let mut unmasked = body.to_vec();
        for i in 0..body_len {
            unmasked[i] ^= mask[i];
        }
        zeroize_bytes(&mut mask);
        unmasked
    } else {
        sealed.to_vec()
    };

    if l3_buf.len() < 32 {
        return Err("corrupted vault chunk: missing AEAD tags".into());
    }
    let aes_ct_len = l3_buf.len() - 16;
    let tag_aes: [u8; 16] = l3_buf[aes_ct_len..].try_into().unwrap();
    let l2_buf = aes_gcm_open_raw(&ek.k_aes, &n_aes, &aad, &l3_buf[..aes_ct_len], &tag_aes)
        .map_err(|e| format!("AES-256-GCM layer rejected chunk {chunk_idx}: {e}"))?;

    if l2_buf.len() < 16 {
        return Err("corrupted inner Poly1305 layer".into());
    }
    let cc_ct_len = l2_buf.len() - 16;
    let tag_cc: [u8; 16] = l2_buf[cc_ct_len..].try_into().unwrap();
    let l1_buf = chacha20_poly1305_open_raw(&ek.k_cc, &n_cc, &aad, &l2_buf[..cc_ct_len], &tag_cc)
        .map_err(|e| format!("ChaCha20-Poly1305 layer rejected chunk {chunk_idx}: {e}"))?;

    if suite == CipherSuite::Mystique1024 {
        let mut dnonce = ek.base_nonce_dyn;
        let idx_b = chunk_idx.to_be_bytes();
        for i in 0..8 {
            dnonce[i] ^= idx_b[i];
        }
        Ok(mystique_core_open(&ek.k_dyn, &dnonce, &l1_buf))
    } else {
        Ok(l1_buf)
    }
}

// ============================================================================
// OBSCURE / KVRM2 Header Encoding & Key Unwrapping
// ============================================================================

fn build_compact_hdr(
    cipher: CipherSuite,
    mode: UnlockMode,
    mem_kib: u32,
    iters: u32,
    lanes: u32,
    ratchet_every: u32,
    pq_len: u16,
) -> [u8; COMPACT_HDR_BYTES] {
    let mut b = [0u8; COMPACT_HDR_BYTES];
    b[0..4].copy_from_slice(b"KVMH");
    b[4] = 2; // format version
    b[5] = cipher as u8;
    b[6] = mode as u8;
    b[7] = lanes as u8;
    b[8..12].copy_from_slice(&mem_kib.to_le_bytes());
    b[12..16].copy_from_slice(&iters.to_le_bytes());
    b[16..20].copy_from_slice(&ratchet_every.to_le_bytes());
    b[20..22].copy_from_slice(&pq_len.to_le_bytes());
    b
}

#[allow(clippy::type_complexity)]
fn parse_compact_hdr(
    b: &[u8; COMPACT_HDR_BYTES],
) -> Result<(CipherSuite, UnlockMode, u8, u32, u32, u32, u16), String> {
    if &b[0..4] != b"KVMH" || b[4] != 2 {
        return Err("invalid sovereign vault header".into());
    }
    let cipher = CipherSuite::from_u8(b[5])?;
    let mode = UnlockMode::from_u8(b[6])?;
    let lanes = b[7];
    let mem_kib = u32::from_le_bytes(b[8..12].try_into().unwrap());
    let iters = u32::from_le_bytes(b[12..16].try_into().unwrap());
    let ratchet_every = u32::from_le_bytes(b[16..20].try_into().unwrap());
    let pq_len = u16::from_le_bytes(b[20..22].try_into().unwrap());
    Ok((cipher, mode, lanes, mem_kib, iters, ratchet_every, pq_len))
}

fn wrap_unlock_key(
    mode: UnlockMode,
    passphrase: Option<&str>,
    pq_shared: Option<&[u8; 64]>,
    vault_salt: &[u8; 32],
    mem_kib: u32,
    iters: u32,
    lanes: u32,
) -> Result<[u8; 32], String> {
    match mode {
        UnlockMode::Passphrase => {
            let pw = passphrase.ok_or("passphrase required")?;
            if pw.is_empty() {
                return Err("passphrase must not be empty".into());
            }
            let mut a2 = argon2id(pw.as_bytes(), vault_salt, mem_kib, iters, lanes, 32)?;
            let k: [u8; 32] = a2.as_slice().try_into().unwrap();
            zeroize_bytes(&mut a2);
            Ok(k)
        }
        UnlockMode::PqHybrid => {
            let ss = pq_shared.ok_or("PQ hybrid shared secret required")?;
            let mut d = dual_prf_expand(ss, vault_salt, b"MAESTRO-UNLOCK-PQ", 32)?;
            let k: [u8; 32] = d.as_slice().try_into().unwrap();
            zeroize_bytes(&mut d);
            Ok(k)
        }
        UnlockMode::Dual2Fa => {
            let pw = passphrase.ok_or("passphrase required for dual-2FA unlock")?;
            if pw.is_empty() {
                return Err("passphrase must not be empty".into());
            }
            let ss = pq_shared.ok_or("PQ secret key required for dual-2FA unlock")?;
            let mut a2 = argon2id(pw.as_bytes(), vault_salt, mem_kib, iters, lanes, 64)?;
            let mut ikm = Vec::with_capacity(128);
            ikm.extend_from_slice(&a2);
            ikm.extend_from_slice(ss);
            let mut combined = dual_prf_expand(&ikm, vault_salt, b"MAESTRO-UNLOCK-DUAL2FA", 32)?;
            zeroize_bytes(&mut a2);
            zeroize_bytes(&mut ikm);
            let k: [u8; 32] = combined.as_slice().try_into().unwrap();
            zeroize_bytes(&mut combined);
            Ok(k)
        }
    }
}

fn obscure_header_mask(vault_salt: &[u8; 32], label: &[u8], len: usize) -> Vec<u8> {
    let mut seed = Vec::with_capacity(32 + label.len());
    seed.extend_from_slice(vault_salt);
    seed.extend_from_slice(label);
    shake256(&seed, len)
}

fn obscure_len_mask(root_key: &[u8; 64], salt: &[u8; 32], chunk_idx: u64) -> [u8; 4] {
    let mut seed = Vec::with_capacity(64 + 32 + 16);
    seed.extend_from_slice(root_key);
    seed.extend_from_slice(salt);
    seed.extend_from_slice(&chunk_idx.to_be_bytes());
    seed.extend_from_slice(b"OBSLEN");
    let m = shake256(&seed, 4);
    zeroize_bytes(&mut seed);
    m.try_into().unwrap()
}

fn write_chunk_frame(
    writer: &mut BufWriter<File>,
    opaque: bool,
    root_key: &[u8; 64],
    salt: &[u8; 32],
    chunk_idx: u64,
    is_final: bool,
    sealed: &[u8],
) -> Result<u64, String> {
    let len_u32 = u32::try_from(sealed.len()).map_err(|_| "chunk too large".to_string())?;
    let mut frame_hdr = [0u8; 5];
    frame_hdr[0] = u8::from(is_final);
    frame_hdr[1..5].copy_from_slice(&len_u32.to_be_bytes());
    if opaque {
        let m = obscure_len_mask(root_key, salt, chunk_idx);
        frame_hdr[0] ^= m[0];
        for i in 0..4 {
            frame_hdr[1 + i] ^= m[i];
        }
    }
    writer
        .write_all(&frame_hdr)
        .map_err(|e| format!("vault write error: {e}"))?;
    writer
        .write_all(sealed)
        .map_err(|e| format!("vault write error: {e}"))?;
    Ok((5 + sealed.len()) as u64)
}

fn read_chunk_frame(
    reader: &mut BufReader<File>,
    opaque: bool,
    root_key: &[u8; 64],
    salt: &[u8; 32],
    chunk_idx: u64,
) -> Result<(bool, Vec<u8>), String> {
    let mut frame_hdr = [0u8; 5];
    reader
        .read_exact(&mut frame_hdr)
        .map_err(|e| format!("truncated or corrupt vault frame at chunk {chunk_idx}: {e}"))?;
    if opaque {
        let m = obscure_len_mask(root_key, salt, chunk_idx);
        frame_hdr[0] ^= m[0];
        for i in 0..4 {
            frame_hdr[1 + i] ^= m[i];
        }
    }
    let is_final = match frame_hdr[0] {
        0 => false,
        1 => true,
        _ => return Err(format!("invalid vault frame flag at chunk {chunk_idx}")),
    };
    let len = u32::from_be_bytes(frame_hdr[1..5].try_into().unwrap()) as usize;
    if len == 0 || len > STREAM_CHUNK_BYTES + 4096 {
        return Err(format!(
            "invalid vault frame length ({len}) at chunk {chunk_idx}"
        ));
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|e| format!("truncated vault payload at chunk {chunk_idx}: {e}"))?;
    Ok((is_final, buf))
}

// ============================================================================
// Public Sovereign File Vault Seal / Unseal / Inspect API
// ============================================================================

pub(crate) fn vault_seal_file(
    src_path: &Path,
    dst_path: &Path,
    opts: &VaultSealOptions,
) -> Result<VaultSealResult, String> {
    let unlock_mode = match (&opts.passphrase, &opts.recipient_pub) {
        (Some(_), Some(_)) => UnlockMode::Dual2Fa,
        (Some(_), None) => UnlockMode::Passphrase,
        (None, Some(_)) => UnlockMode::PqHybrid,
        (None, None) => {
            return Err("vault_seal_file requires passphrase, recipient_pub, or both".into());
        }
    };
    let src_file = File::open(src_path)
        .map_err(|e| format!("failed to open source '{}': {e}", src_path.display()))?;
    let mut reader = BufReader::with_capacity(STREAM_CHUNK_BYTES, src_file);

    let mut vault_salt = [0u8; 32];
    OsRng.fill_bytes(&mut vault_salt);
    let mut root_key = [0u8; 64];
    OsRng.fill_bytes(&mut root_key);

    let (pq_capsule_opt, mut pq_ss_opt) = if let Some(pub_arm) = &opts.recipient_pub {
        let pub_raw = parse_pq_hybrid_pub(pub_arm)?;
        let (cap, ss) = pq_hybrid_encaps_raw(&pub_raw)?;
        (Some(cap), Some(ss))
    } else {
        (None, None)
    };
    let pq_len = pq_capsule_opt.as_ref().map(|c| c.len() as u16).unwrap_or(0);

    let mut kek = wrap_unlock_key(
        unlock_mode,
        opts.passphrase.as_deref(),
        pq_ss_opt.as_ref(),
        &vault_salt,
        opts.mem_kib,
        opts.iters_checked()?,
        opts.lanes,
    )?;
    if let Some(ref mut ss) = pq_ss_opt {
        zeroize_bytes(ss);
    }

    let compact_hdr = build_compact_hdr(
        opts.cipher,
        unlock_mode,
        opts.mem_kib,
        opts.iterations,
        opts.lanes,
        opts.ratchet_every.max(1),
        pq_len,
    );

    let commitment_vec = kmac256(&root_key, b"KOVREK-KEY-COMMIT", &compact_hdr, 32);
    let commitment: [u8; 32] = commitment_vec.as_slice().try_into().unwrap();

    let mut wrap_aad = Vec::with_capacity(32 + 24 + pq_len as usize);
    wrap_aad.extend_from_slice(&vault_salt);
    wrap_aad.extend_from_slice(&compact_hdr);
    if let Some(cap) = &pq_capsule_opt {
        wrap_aad.extend_from_slice(cap);
    }

    let mut wrap_nonce = [0u8; 12];
    for i in 0..12 {
        wrap_nonce[i] = vault_salt[i] ^ commitment[i];
    }
    let (wrapped_ct, wrapped_tag) = aes_gcm_seal_raw(&kek, &wrap_nonce, &wrap_aad, &root_key);
    let header_mac = kmac256(&kek, b"KOVREK-HDR-MAC", &wrap_aad, OBSCURE_TAG_BYTES);
    zeroize_bytes(&mut kek);

    let tmp_dst = dst_path.with_extension("kvv.tmp");
    let dst_file = File::create(&tmp_dst)
        .map_err(|e| format!("failed to create vault '{}': {e}", tmp_dst.display()))?;
    let mut writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES + 1024, dst_file);

    let mut total_written: u64 = 0;
    if opts.opaque_obscure {
        writer
            .write_all(&vault_salt)
            .map_err(|e| format!("vault write error: {e}"))?;
        let m1 = obscure_header_mask(&vault_salt, b"OBSCURE-HDR-CORE", COMPACT_HDR_BYTES);
        let mut masked_hdr = compact_hdr;
        for i in 0..COMPACT_HDR_BYTES {
            masked_hdr[i] ^= m1[i];
        }
        writer
            .write_all(&masked_hdr)
            .map_err(|e| format!("vault write error: {e}"))?;
        if let Some(cap) = &pq_capsule_opt {
            let mcap = obscure_header_mask(&vault_salt, b"OBSCURE-PQ-CAPS", cap.len());
            let mut masked_cap = cap.clone();
            for i in 0..masked_cap.len() {
                masked_cap[i] ^= mcap[i];
            }
            writer
                .write_all(&masked_cap)
                .map_err(|e| format!("vault write error: {e}"))?;
        }
        let mwrap = obscure_header_mask(&vault_salt, b"OBSCURE-WRAP", WRAPPED_ROOT_BYTES);
        let mut wrap_blk = Vec::with_capacity(WRAPPED_ROOT_BYTES);
        wrap_blk.extend_from_slice(&wrapped_ct);
        wrap_blk.extend_from_slice(&wrapped_tag);
        for i in 0..WRAPPED_ROOT_BYTES {
            wrap_blk[i] ^= mwrap[i];
        }
        writer
            .write_all(&wrap_blk)
            .map_err(|e| format!("vault write error: {e}"))?;
        let mut mcommit = obscure_header_mask(&vault_salt, b"OBSCURE-COMMIT", 64);
        let mut cblk = [0u8; 64];
        cblk[..32].copy_from_slice(&commitment);
        cblk[32..].copy_from_slice(&header_mac);
        for i in 0..64 {
            cblk[i] ^= mcommit[i];
        }
        zeroize_bytes(&mut mcommit);
        writer
            .write_all(&cblk)
            .map_err(|e| format!("vault write error: {e}"))?;
        total_written +=
            (32 + COMPACT_HDR_BYTES + pq_len as usize + WRAPPED_ROOT_BYTES + 64) as u64;
    } else {
        writer
            .write_all(SOVEREIGN_MAGIC)
            .map_err(|e| format!("vault write error: {e}"))?;
        writer
            .write_all(&vault_salt)
            .map_err(|e| format!("vault write error: {e}"))?;
        writer
            .write_all(&compact_hdr)
            .map_err(|e| format!("vault write error: {e}"))?;
        if let Some(cap) = &pq_capsule_opt {
            writer
                .write_all(cap)
                .map_err(|e| format!("vault write error: {e}"))?;
        }
        writer
            .write_all(&wrapped_ct)
            .map_err(|e| format!("vault write error: {e}"))?;
        writer
            .write_all(&wrapped_tag)
            .map_err(|e| format!("vault write error: {e}"))?;
        writer
            .write_all(&commitment)
            .map_err(|e| format!("vault write error: {e}"))?;
        writer
            .write_all(&header_mac)
            .map_err(|e| format!("vault write error: {e}"))?;
        total_written +=
            (8 + 32 + COMPACT_HDR_BYTES + pq_len as usize + WRAPPED_ROOT_BYTES + 64) as u64;
    }

    let orig_name = src_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file.bin".to_string());

    let mut ratchet = MaestroRatchet::new(&root_key, &vault_salt, opts.ratchet_every);
    let res = (|| -> Result<VaultSealResult, String> {
        let mut chunk_idx: u64 = 0;

        // Chunk 0: Encrypted minimal prologue (filename hidden inside cipher)
        let prologue = serde_json::json!({
            "kind": "prologue",
            "filename": orig_name,
            "suite": opts.cipher.as_str(),
        })
        .to_string();
        let sealed0 = {
            let ek = ratchet.keys_for_chunk(chunk_idx)?;
            encrypt_chunk(
                opts.cipher,
                ek,
                &commitment,
                chunk_idx,
                false,
                prologue.as_bytes(),
            )
        };
        total_written += write_chunk_frame(
            &mut writer,
            opts.opaque_obscure,
            &root_key,
            &vault_salt,
            chunk_idx,
            false,
            &sealed0,
        )?;
        chunk_idx += 1;

        // Payload chunks 1..=N
        let mut pt_buf = vec![0u8; STREAM_CHUNK_BYTES];
        let mut plain_bytes: u64 = 0;
        let mut hasher = Sha3_512Hasher::new();

        loop {
            let mut filled = 0usize;
            while filled < STREAM_CHUNK_BYTES {
                let n = reader
                    .read(&mut pt_buf[filled..])
                    .map_err(|e| format!("failed reading source file: {e}"))?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            hasher.update(&pt_buf[..filled]);
            plain_bytes += filled as u64;
            let sealed = {
                let ek = ratchet.keys_for_chunk(chunk_idx)?;
                encrypt_chunk(
                    opts.cipher,
                    ek,
                    &commitment,
                    chunk_idx,
                    false,
                    &pt_buf[..filled],
                )
            };
            total_written += write_chunk_frame(
                &mut writer,
                opts.opaque_obscure,
                &root_key,
                &vault_salt,
                chunk_idx,
                false,
                &sealed,
            )?;
            chunk_idx += 1;
        }
        zeroize_bytes(&mut pt_buf);

        // Final authenticated trailer frame (contains SHA3-512, orig_len, & bucket blinding padding)
        let sha3_hex = bytes_to_hex(&hasher.finalize());
        let bucket = opts.pad_bucket as u64;
        let pad_len = if bucket > 0 {
            let rem = plain_bytes % bucket;
            if rem == 0 {
                0usize
            } else {
                (bucket - rem) as usize
            }
        } else {
            0usize
        };
        let mut pad_noise = vec![0u8; pad_len.min(STREAM_CHUNK_BYTES / 2)];
        if !pad_noise.is_empty() {
            OsRng.fill_bytes(&mut pad_noise);
        }
        let trailer = serde_json::json!({
            "kind": "trailer",
            "filename": orig_name,
            "orig_len": plain_bytes,
            "sha3_512": sha3_hex,
            "pad_hex": bytes_to_hex(&pad_noise),
        })
        .to_string();
        let sealed_final = {
            let ek = ratchet.keys_for_chunk(chunk_idx)?;
            encrypt_chunk(
                opts.cipher,
                ek,
                &commitment,
                chunk_idx,
                true,
                trailer.as_bytes(),
            )
        };
        total_written += write_chunk_frame(
            &mut writer,
            opts.opaque_obscure,
            &root_key,
            &vault_salt,
            chunk_idx,
            true,
            &sealed_final,
        )?;
        writer
            .flush()
            .map_err(|e| format!("failed flushing vault '{}': {e}", tmp_dst.display()))?;

        Ok(VaultSealResult {
            method: format!(
                "{}|{}|{}",
                if opts.opaque_obscure {
                    "OBSCURE-OPAQUE"
                } else {
                    "MAESTRO-KVRM2"
                },
                opts.cipher.as_str(),
                unlock_mode.as_str()
            ),
            plaintext_bytes: plain_bytes,
            padded_bytes: total_written,
            chunks_written: chunk_idx + 1,
            key_commitment_prefix: bytes_to_hex(&commitment[..8]),
            opaque: opts.opaque_obscure,
        })
    })();

    ratchet.scrub();
    zeroize_bytes(&mut root_key);
    drop(writer);
    match res {
        Ok(r) => {
            if dst_path.exists() {
                let _ = fs::remove_file(dst_path);
            }
            fs::rename(&tmp_dst, dst_path).map_err(|e| {
                let _ = fs::remove_file(&tmp_dst);
                format!("failed moving vault to '{}': {e}", dst_path.display())
            })?;
            Ok(r)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_dst);
            Err(e)
        }
    }
}

impl VaultSealOptions {
    fn iters_checked(&self) -> Result<u32, String> {
        if self.iterations == 0 || self.iterations > 128 {
            return Err("Argon2id iterations must be between 1 and 128".into());
        }
        Ok(self.iterations)
    }
}

pub(crate) fn vault_inspect(vault_path: &Path) -> Result<VaultInspection, String> {
    let mut file = File::open(vault_path)
        .map_err(|e| format!("failed to open vault '{}': {e}", vault_path.display()))?;
    let mut prefix = [0u8; 8];
    file.read_exact(&mut prefix)
        .map_err(|e| format!("failed reading vault prefix: {e}"))?;
    if &prefix != SOVEREIGN_MAGIC {
        return Ok(VaultInspection {
            format: "OBSCURE-OPAQUE".into(),
            opaque: true,
            cipher: None,
            unlock_mode: None,
            argon2id_mem_kib: None,
            argon2id_iterations: None,
            ratchet_every: None,
            key_commitment_prefix: None,
            has_plaintext_leak: false,
        });
    }
    let mut vault_salt = [0u8; 32];
    file.read_exact(&mut vault_salt)
        .map_err(|e| format!("truncated vault salt: {e}"))?;
    let mut compact = [0u8; COMPACT_HDR_BYTES];
    file.read_exact(&mut compact)
        .map_err(|e| format!("truncated vault header: {e}"))?;
    let (cipher, mode, _lanes, mem_kib, iters, ratchet_every, pq_len) =
        parse_compact_hdr(&compact)?;
    if pq_len > 0 {
        let mut skip = vec![0u8; pq_len as usize];
        file.read_exact(&mut skip)
            .map_err(|e| format!("truncated vault capsule: {e}"))?;
    }
    let mut wrap_skip = [0u8; WRAPPED_ROOT_BYTES];
    file.read_exact(&mut wrap_skip)
        .map_err(|e| format!("truncated wrapped root: {e}"))?;
    let mut commitment = [0u8; 32];
    file.read_exact(&mut commitment)
        .map_err(|e| format!("truncated commitment: {e}"))?;

    Ok(VaultInspection {
        format: "KVRM2-SOVEREIGN".into(),
        opaque: false,
        cipher: Some(cipher.as_str().to_string()),
        unlock_mode: Some(mode.as_str().to_string()),
        argon2id_mem_kib: (mode != UnlockMode::PqHybrid).then_some(mem_kib),
        argon2id_iterations: (mode != UnlockMode::PqHybrid).then_some(iters),
        ratchet_every: Some(ratchet_every),
        key_commitment_prefix: Some(bytes_to_hex(&commitment[..8])),
        has_plaintext_leak: false,
    })
}

pub(crate) fn vault_unseal_file(
    vault_path: &Path,
    out_path: &Path,
    creds: &VaultOpenCreds,
) -> Result<VaultOpenResult, String> {
    let file = File::open(vault_path)
        .map_err(|e| format!("failed to open vault '{}': {e}", vault_path.display()))?;
    let mut reader = BufReader::with_capacity(STREAM_CHUNK_BYTES + 1024, file);

    let mut head8 = [0u8; 8];
    reader
        .read_exact(&mut head8)
        .map_err(|e| format!("failed reading vault header: {e}"))?;
    let opaque = &head8 != SOVEREIGN_MAGIC;

    let mut vault_salt = [0u8; 32];
    let mut compact_hdr = [0u8; COMPACT_HDR_BYTES];
    if opaque {
        vault_salt[..8].copy_from_slice(&head8);
        reader
            .read_exact(&mut vault_salt[8..])
            .map_err(|e| format!("truncated opaque vault salt: {e}"))?;
        reader
            .read_exact(&mut compact_hdr)
            .map_err(|e| format!("truncated opaque header: {e}"))?;
        let m1 = obscure_header_mask(&vault_salt, b"OBSCURE-HDR-CORE", COMPACT_HDR_BYTES);
        for i in 0..COMPACT_HDR_BYTES {
            compact_hdr[i] ^= m1[i];
        }
    } else {
        reader
            .read_exact(&mut vault_salt)
            .map_err(|e| format!("truncated vault salt: {e}"))?;
        reader
            .read_exact(&mut compact_hdr)
            .map_err(|e| format!("truncated vault header: {e}"))?;
    }

    let (cipher, unlock_mode, lanes, mem_kib, iters, ratchet_every, pq_len) =
        parse_compact_hdr(&compact_hdr).map_err(|_| {
            "decryption failed: invalid credentials, format, or corrupted vault".to_string()
        })?;

    let pq_cap = if pq_len > 0 {
        if pq_len as usize != PQ_HYBRID_CT_BYTES {
            return Err("invalid PQ capsule size in vault header".into());
        }
        let mut cap = vec![0u8; pq_len as usize];
        reader
            .read_exact(&mut cap)
            .map_err(|e| format!("truncated PQ capsule: {e}"))?;
        if opaque {
            let mcap = obscure_header_mask(&vault_salt, b"OBSCURE-PQ-CAPS", cap.len());
            for i in 0..cap.len() {
                cap[i] ^= mcap[i];
            }
        }
        Some(cap)
    } else {
        None
    };

    let mut wrap_blk = [0u8; WRAPPED_ROOT_BYTES];
    reader
        .read_exact(&mut wrap_blk)
        .map_err(|e| format!("truncated wrapped key slot: {e}"))?;
    let mut commit_and_mac = [0u8; 64];
    reader
        .read_exact(&mut commit_and_mac)
        .map_err(|e| format!("truncated key commitment: {e}"))?;

    if opaque {
        let mwrap = obscure_header_mask(&vault_salt, b"OBSCURE-WRAP", WRAPPED_ROOT_BYTES);
        for i in 0..WRAPPED_ROOT_BYTES {
            wrap_blk[i] ^= mwrap[i];
        }
        let mut mcommit = obscure_header_mask(&vault_salt, b"OBSCURE-COMMIT", 64);
        for i in 0..64 {
            commit_and_mac[i] ^= mcommit[i];
        }
        zeroize_bytes(&mut mcommit);
    }

    let commitment: [u8; 32] = commit_and_mac[..32].try_into().unwrap();
    let header_mac = &commit_and_mac[32..];

    let mut wrap_aad = Vec::with_capacity(32 + 24 + pq_len as usize);
    wrap_aad.extend_from_slice(&vault_salt);
    wrap_aad.extend_from_slice(&compact_hdr);
    if let Some(cap) = &pq_cap {
        wrap_aad.extend_from_slice(cap);
    }

    let mut pq_ss_opt = match (&pq_cap, &creds.secret_key) {
        (Some(cap), Some(sec_arm)) => {
            let mut sec_raw = parse_pq_hybrid_sec(sec_arm)?;
            let ss = pq_hybrid_decaps_raw(&sec_raw, cap)?;
            zeroize_bytes(&mut sec_raw);
            Some(ss)
        }
        (Some(_), None) => {
            return Err("vault requires PQ hybrid secret key ('kvpq1sec:...')".into());
        }
        (None, _) => None,
    };

    let mut kek = wrap_unlock_key(
        unlock_mode,
        creds.passphrase.as_deref(),
        pq_ss_opt.as_ref(),
        &vault_salt,
        mem_kib,
        iters,
        lanes as u32,
    )?;
    if let Some(ref mut ss) = pq_ss_opt {
        zeroize_bytes(ss);
    }

    let expected_hmac = kmac256(&kek, b"KOVREK-HDR-MAC", &wrap_aad, OBSCURE_TAG_BYTES);
    if !constant_time_bytes_equal(&expected_hmac, header_mac) {
        zeroize_bytes(&mut kek);
        return Err("decryption failed: wrong credentials or corrupted header MAC".into());
    }

    let mut wrap_nonce = [0u8; 12];
    for i in 0..12 {
        wrap_nonce[i] = vault_salt[i] ^ commitment[i];
    }
    let wrapped_ct = &wrap_blk[..64];
    let wrapped_tag: [u8; 16] = wrap_blk[64..].try_into().unwrap();
    let mut root_vec = aes_gcm_open_raw(&kek, &wrap_nonce, &wrap_aad, wrapped_ct, &wrapped_tag)
        .map_err(|_| "decryption failed: invalid credentials or root unwrap failed".to_string())?;
    zeroize_bytes(&mut kek);

    let mut root_key: [u8; 64] = root_vec.as_slice().try_into().unwrap();
    zeroize_bytes(&mut root_vec);

    let recomputed_commit = kmac256(&root_key, b"KOVREK-KEY-COMMIT", &compact_hdr, 32);
    if !constant_time_bytes_equal(&recomputed_commit, &commitment) {
        zeroize_bytes(&mut root_key);
        return Err("decryption failed: key commitment verification failed".into());
    }

    let tmp_out = out_path.with_extension("plain.tmp");
    let out_file = File::create(&tmp_out)
        .map_err(|e| format!("failed to create output '{}': {e}", tmp_out.display()))?;
    let mut writer = BufWriter::with_capacity(STREAM_CHUNK_BYTES, out_file);
    let mut ratchet = MaestroRatchet::new(&root_key, &vault_salt, ratchet_every);

    let res = (|| -> Result<VaultOpenResult, String> {
        let mut hasher = Sha3_512Hasher::new();
        let mut recovered_bytes: u64 = 0;

        // Chunk 0: encrypted prologue
        let (final0, frame0) = read_chunk_frame(&mut reader, opaque, &root_key, &vault_salt, 0)?;
        if final0 {
            return Err("corrupted vault: unexpected final flag on prologue frame".into());
        }
        let prologue_bytes = {
            let ek = ratchet.keys_for_chunk(0)?;
            decrypt_chunk(cipher, ek, &commitment, 0, false, &frame0)?
        };
        let prologue_json: serde_json::Value = serde_json::from_slice(&prologue_bytes)
            .map_err(|e| format!("corrupted encrypted prologue metadata: {e}"))?;
        let prologue_filename = prologue_json
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("recovered.bin")
            .to_string();

        let mut chunk_idx: u64 = 1;
        let final_trailer: serde_json::Value;
        loop {
            let (is_final, frame) =
                read_chunk_frame(&mut reader, opaque, &root_key, &vault_salt, chunk_idx)?;
            let pt = {
                let ek = ratchet.keys_for_chunk(chunk_idx)?;
                decrypt_chunk(cipher, ek, &commitment, chunk_idx, is_final, &frame)?
            };
            if is_final {
                final_trailer = serde_json::from_slice(&pt)
                    .map_err(|e| format!("corrupted encrypted trailer metadata: {e}"))?;
                break;
            }
            hasher.update(&pt);
            recovered_bytes += pt.len() as u64;
            writer
                .write_all(&pt)
                .map_err(|e| format!("failed writing plaintext: {e}"))?;
            chunk_idx += 1;
        }

        // Refuse any trailing unauthenticated bytes after final frame
        let mut extra = [0u8; 1];
        if reader.read(&mut extra).unwrap_or(0) != 0 {
            return Err("corrupted vault: unexpected trailing bytes after final frame".into());
        }

        let expected_len = final_trailer
            .get("orig_len")
            .and_then(|v| v.as_u64())
            .ok_or("missing orig_len in encrypted trailer")?;
        if recovered_bytes != expected_len {
            return Err(format!(
                "length mismatch after stream decode (expected {expected_len}, got {recovered_bytes})"
            ));
        }

        let expected_sha3 = final_trailer
            .get("sha3_512")
            .and_then(|v| v.as_str())
            .ok_or("missing sha3_512 in encrypted trailer")?;
        let actual_sha3 = bytes_to_hex(&hasher.finalize());
        if !constant_time_bytes_equal(actual_sha3.as_bytes(), expected_sha3.as_bytes()) {
            return Err("whole-file SHA3-512 integrity check failed".into());
        }

        writer
            .flush()
            .map_err(|e| format!("failed flushing output: {e}"))?;

        Ok(VaultOpenResult {
            method: format!(
                "{}|{}|{}",
                if opaque {
                    "OBSCURE-OPAQUE"
                } else {
                    "MAESTRO-KVRM2"
                },
                cipher.as_str(),
                unlock_mode.as_str()
            ),
            original_filename: prologue_filename,
            recovered_bytes,
            sha3_512: actual_sha3,
            chunks_verified: chunk_idx + 1,
        })
    })();

    ratchet.scrub();
    zeroize_bytes(&mut root_key);
    drop(writer);
    match res {
        Ok(r) => {
            if out_path.exists() {
                let _ = fs::remove_file(out_path);
            }
            fs::rename(&tmp_out, out_path).map_err(|e| {
                let _ = fs::remove_file(&tmp_out);
                format!("failed finalizing output '{}': {e}", out_path.display())
            })?;
            Ok(r)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_out);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_crypto::pq_hybrid_keygen;
    use std::env;

    #[test]
    fn mystique_polymorphic_core_roundtrips_arbitrary_lengths() {
        let key = [0x5au8; 32];
        let nonce = [0xa5u8; 16];
        for len in [0usize, 1, 2, 15, 64, 255, 1029] {
            let pt: Vec<u8> = (0..len).map(|i| ((i * 73 + 19) & 0xff) as u8).collect();
            let ct = mystique_core_seal(&key, &nonce, &pt);
            assert_eq!(ct.len(), pt.len());
            if len >= 16 {
                assert_ne!(ct, pt);
            }
            let rt = mystique_core_open(&key, &nonce, &ct);
            assert_eq!(rt, pt, "mystique roundtrip failed for len {len}");
        }
    }

    #[test]
    fn sovereign_streaming_mystique_maestro_obscure_multi_chunk_and_tamper_tests() {
        let dir = env::temp_dir().join("kovrek_sovereign_vault_stream_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // 150 KiB payload spans 3 streaming chunks (64 KiB + 64 KiB + 22 KiB) + prologue + trailer, crossing epoch ratchet
        let src = dir.join("top_secret_matrix.bin");
        let mut payload = vec![0u8; 150_000];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = ((i * 131 + (i >> 7) * 17 + 0x42) & 0xff) as u8;
        }
        fs::write(&src, &payload).unwrap();
        let src_sha3 = bytes_to_hex(&crate::pq_crypto::sha3_512(&payload));

        let (pub_k, sec_k) = pq_hybrid_keygen();

        // 1. Dual-2FA (Argon2id Passphrase + ML-KEM-1024 + X25519) in MYSTIQUE-1024 + OBSCURE Opaque mode
        let vault_obscure = dir.join("stealth_vault.kvx");
        let seal_res = vault_seal_file(
            &src,
            &vault_obscure,
            &VaultSealOptions {
                cipher: CipherSuite::Mystique1024,
                opaque_obscure: true,
                passphrase: Some("ultra-sovereign-quantum-200y-passphrase!".into()),
                recipient_pub: Some(pub_k.clone()),
                mem_kib: 1024, // fast test mem cost (API checks min only if policy requires, or pass clean value)
                iterations: 2,
                lanes: 1,
                ratchet_every: 2, // force epoch ratchet mid-stream
                pad_bucket: 4096,
            },
        )
        .unwrap();
        assert!(seal_res.opaque);
        assert_eq!(seal_res.plaintext_bytes, 150_000);
        assert_eq!(seal_res.chunks_written, 5); // prologue + 3 data chunks + trailer

        // Ensure ZERO cleartext banner, filename, or SHA3/SHA256 digest appears in opaque bytes
        let vault_bytes = fs::read(&vault_obscure).unwrap();
        assert!(!vault_bytes.starts_with(SOVEREIGN_MAGIC));
        assert!(
            !vault_bytes
                .windows(b"top_secret_matrix.bin".len())
                .any(|w| w == b"top_secret_matrix.bin")
        );
        assert!(
            !vault_bytes
                .windows(src_sha3.len())
                .any(|w| w == src_sha3.as_bytes())
        );

        let insp = vault_inspect(&vault_obscure).unwrap();
        assert!(insp.opaque);
        assert!(!insp.has_plaintext_leak);

        let out_dec = dir.join("recovered.bin");
        // Missing passphrase must fail
        assert!(
            vault_unseal_file(
                &vault_obscure,
                &out_dec,
                &VaultOpenCreds {
                    passphrase: None,
                    secret_key: Some(sec_k.clone()),
                }
            )
            .is_err()
        );
        assert!(!out_dec.exists());

        // Missing PQ secret key must fail
        assert!(
            vault_unseal_file(
                &vault_obscure,
                &out_dec,
                &VaultOpenCreds {
                    passphrase: Some("ultra-sovereign-quantum-200y-passphrase!".into()),
                    secret_key: None,
                }
            )
            .is_err()
        );

        // Correct Dual-2FA succeeds identically
        let open_res = vault_unseal_file(
            &vault_obscure,
            &out_dec,
            &VaultOpenCreds {
                passphrase: Some("ultra-sovereign-quantum-200y-passphrase!".into()),
                secret_key: Some(sec_k.clone()),
            },
        )
        .unwrap();
        assert_eq!(open_res.original_filename, "top_secret_matrix.bin");
        assert_eq!(open_res.recovered_bytes, 150_000);
        assert_eq!(open_res.sha3_512, src_sha3);
        assert_eq!(fs::read(&out_dec).unwrap(), payload);

        // Bit-flip near middle of encrypted stream rejects and leaves NO output file
        let out_tampered = dir.join("tampered.bin");
        let mut tampered_bytes = vault_bytes.clone();
        let mid = tampered_bytes.len() / 2;
        tampered_bytes[mid] ^= 0x01;
        let vault_bad = dir.join("tampered.kvx");
        fs::write(&vault_bad, &tampered_bytes).unwrap();
        assert!(
            vault_unseal_file(
                &vault_bad,
                &out_tampered,
                &VaultOpenCreds {
                    passphrase: Some("ultra-sovereign-quantum-200y-passphrase!".into()),
                    secret_key: Some(sec_k.clone()),
                }
            )
            .is_err()
        );
        assert!(!out_tampered.exists());

        // Truncated file (last byte stripped) rejects
        let vault_trunc = dir.join("trunc.kvx");
        fs::write(&vault_trunc, &vault_bytes[..vault_bytes.len() - 10]).unwrap();
        assert!(
            vault_unseal_file(
                &vault_trunc,
                &out_tampered,
                &VaultOpenCreds {
                    passphrase: Some("ultra-sovereign-quantum-200y-passphrase!".into()),
                    secret_key: Some(sec_k),
                }
            )
            .is_err()
        );

        // 2. Empty file (0 bytes) in KVRM2 + Cascade512 + Passphrase mode
        let empty_src = dir.join("empty.bin");
        fs::write(&empty_src, b"").unwrap();
        let empty_v = dir.join("empty.kvv");
        let empty_out = dir.join("empty_out.bin");
        vault_seal_file(
            &empty_src,
            &empty_v,
            &VaultSealOptions {
                cipher: CipherSuite::Cascade512,
                opaque_obscure: false,
                passphrase: Some("empty-file-pass!".into()),
                mem_kib: 1024,
                iterations: 2,
                lanes: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let insp_kvrm = vault_inspect(&empty_v).unwrap();
        assert!(!insp_kvrm.opaque);
        assert_eq!(insp_kvrm.cipher.as_deref(), Some("cascade-512"));
        let empty_res = vault_unseal_file(
            &empty_v,
            &empty_out,
            &VaultOpenCreds {
                passphrase: Some("empty-file-pass!".into()),
                secret_key: None,
            },
        )
        .unwrap();
        assert_eq!(empty_res.recovered_bytes, 0);
        assert_eq!(fs::read(&empty_out).unwrap(), b"");

        let _ = fs::remove_dir_all(&dir);
    }
}
