//! Sovereign Next-Century Subsystems for Kovrek (`quantum_ecc`):
//!
//! 1. **Exact Statevector Quantum Circuit & Entanglement Entropy Simulator**:
//!    - Simulates up to 12-qubit pure statevectors $|\psi\rangle \in \mathbb{C}^{2^n}$
//!      in double-precision complex arithmetic.
//!    - Universal gate set: `H`, `X`, `Y`, `Z`, `S`, `T`, `RX(theta)`, `RY(theta)`,
//!      `RZ(theta)`, `CNOT`, `CZ`, `SWAP`, `CCX` (Toffoli), and `QFT` (Quantum Fourier Transform).
//!    - Computes exact partial trace $\rho_A = \mathrm{Tr}_B(|\psi\rangle\langle\psi|)$ and
//!      **von Neumann entanglement entropy** $S(\rho_A) = -\mathrm{Tr}(\rho_A \log_2 \rho_A)$ via
//!      Hermitian Jacobi diagonalization.
//!    - Executes **Grover's Quantum Search Algorithm** $O(\sqrt{N})$ with phase oracle + diffusion
//!      amplification.
//!
//! 2. **Cosmic-Ray / Byzantine Self-Healing SECDED `(72, 64)` ECC Memory**:
//!    - Encodes arbitrary byte payloads into 64-bit data words protected by an 8-bit
//!      Extended Hamming `(72, 64)` Single-Error-Correcting, Double-Error-Detecting (SECDED)
//!      syndrome code plus a `SHA3-256` cryptographic integrity seal (`kvecc1:...`).
//!    - Automatically pinpoints and heals any single-bit flip in every 64-bit word (up to
//!      $N$ simultaneous bit flips across an $N$-word buffer, 1 per word) and detects
//!      uncorrectable multi-bit corruptions.
//!
//! 3. **Post-Quantum Proof-Carrying Code (PCC) Certificates**:
//!    - Runs the Kovrek formal `@verify` contract & invariant prover on `.kvr` source code,
//!      binds the `SHA3-512` source digest and formal proof telemetry into a canonical certificate,
//!      and signs it using Kovrek's `ML-DSA-SIS + FORS-SHAKE256` Post-Quantum Signature Engine.

use crate::pq_crypto::{pq_sign, pq_verify, sha3_256, sha3_512};
use crate::security::{bytes_to_hex, hex_to_bytes};
use std::f64::consts::{FRAC_1_SQRT_2, PI};

fn armor_encode(prefix: &str, data: &[u8]) -> String {
    format!("{prefix}:{}", bytes_to_hex(data))
}

fn armor_try_decode(prefix: &str, token: &str) -> Result<Vec<u8>, String> {
    let expected = format!("{prefix}:");
    let hex = token
        .trim()
        .strip_prefix(&expected)
        .ok_or_else(|| format!("expected armored token starting with '{expected}'"))?;
    hex_to_bytes(hex)
}

// ============================================================================
// 1. EXACT STATEVECTOR QUANTUM CIRCUIT & ENTANGLEMENT SIMULATOR
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Complex64 {
    pub re: f64,
    pub im: f64,
}

impl Complex64 {
    #[inline(always)]
    pub const fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    #[inline(always)]
    pub const fn zero() -> Self {
        Self { re: 0.0, im: 0.0 }
    }

    #[inline(always)]
    pub const fn one() -> Self {
        Self { re: 1.0, im: 0.0 }
    }

    #[inline(always)]
    pub fn conj(self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    #[inline(always)]
    pub fn norm_sq(self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    #[inline(always)]
    pub fn add(self, rhs: Self) -> Self {
        Self {
            re: self.re + rhs.re,
            im: self.im + rhs.im,
        }
    }

    #[inline(always)]
    pub fn sub(self, rhs: Self) -> Self {
        Self {
            re: self.re - rhs.re,
            im: self.im - rhs.im,
        }
    }

    #[inline(always)]
    pub fn mul(self, rhs: Self) -> Self {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }

    #[inline(always)]
    pub fn scale(self, s: f64) -> Self {
        Self {
            re: self.re * s,
            im: self.im * s,
        }
    }

    #[inline(always)]
    pub fn exp_i(theta: f64) -> Self {
        Self {
            re: theta.cos(),
            im: theta.sin(),
        }
    }
}

pub(crate) const MAX_SIM_QUBITS: usize = 12;

#[derive(Clone, Debug)]
pub(crate) struct QuantumCircuit {
    pub num_qubits: usize,
    pub state: Vec<Complex64>,
}

impl QuantumCircuit {
    pub fn new(num_qubits: usize) -> Result<Self, String> {
        if !(1..=MAX_SIM_QUBITS).contains(&num_qubits) {
            return Err(format!(
                "QuantumCircuit supports 1..={MAX_SIM_QUBITS} qubits (got {num_qubits})"
            ));
        }
        let dim = 1usize << num_qubits;
        let mut state = vec![Complex64::zero(); dim];
        state[0] = Complex64::one();
        Ok(Self { num_qubits, state })
    }

    fn check_qubit(&self, q: usize) -> Result<(), String> {
        if q >= self.num_qubits {
            return Err(format!(
                "qubit index {q} out of range for {}-qubit circuit",
                self.num_qubits
            ));
        }
        Ok(())
    }

    /// Apply an arbitrary 2x2 unitary matrix `[[u00, u01], [u10, u11]]` to qubit `q`.
    pub fn apply_single_qubit_unitary(
        &mut self,
        q: usize,
        u00: Complex64,
        u01: Complex64,
        u10: Complex64,
        u11: Complex64,
    ) -> Result<(), String> {
        self.check_qubit(q)?;
        let bit = 1usize << q;
        let dim = self.state.len();
        for i in 0..dim {
            if (i & bit) == 0 {
                let j = i | bit;
                let a0 = self.state[i];
                let a1 = self.state[j];
                self.state[i] = u00.mul(a0).add(u01.mul(a1));
                self.state[j] = u10.mul(a0).add(u11.mul(a1));
            }
        }
        Ok(())
    }

    pub fn h(&mut self, q: usize) -> Result<(), String> {
        let s = Complex64::new(FRAC_1_SQRT_2, 0.0);
        let ms = Complex64::new(-FRAC_1_SQRT_2, 0.0);
        self.apply_single_qubit_unitary(q, s, s, s, ms)
    }

    pub fn x(&mut self, q: usize) -> Result<(), String> {
        let z = Complex64::zero();
        let o = Complex64::one();
        self.apply_single_qubit_unitary(q, z, o, o, z)
    }

    pub fn y(&mut self, q: usize) -> Result<(), String> {
        let z = Complex64::zero();
        let mi = Complex64::new(0.0, -1.0);
        let pi = Complex64::new(0.0, 1.0);
        self.apply_single_qubit_unitary(q, z, mi, pi, z)
    }

    pub fn z(&mut self, q: usize) -> Result<(), String> {
        let z = Complex64::zero();
        let o = Complex64::one();
        let mo = Complex64::new(-1.0, 0.0);
        self.apply_single_qubit_unitary(q, o, z, z, mo)
    }

    pub fn s_gate(&mut self, q: usize) -> Result<(), String> {
        let z = Complex64::zero();
        let o = Complex64::one();
        let pi = Complex64::new(0.0, 1.0);
        self.apply_single_qubit_unitary(q, o, z, z, pi)
    }

    pub fn t_gate(&mut self, q: usize) -> Result<(), String> {
        let z = Complex64::zero();
        let o = Complex64::one();
        let t = Complex64::new(FRAC_1_SQRT_2, FRAC_1_SQRT_2);
        self.apply_single_qubit_unitary(q, o, z, z, t)
    }

    pub fn rx(&mut self, q: usize, theta: f64) -> Result<(), String> {
        let c = Complex64::new((theta * 0.5).cos(), 0.0);
        let mis = Complex64::new(0.0, -(theta * 0.5).sin());
        self.apply_single_qubit_unitary(q, c, mis, mis, c)
    }

    pub fn ry(&mut self, q: usize, theta: f64) -> Result<(), String> {
        let c = Complex64::new((theta * 0.5).cos(), 0.0);
        let s = Complex64::new((theta * 0.5).sin(), 0.0);
        let ms = Complex64::new(-(theta * 0.5).sin(), 0.0);
        self.apply_single_qubit_unitary(q, c, ms, s, c)
    }

    pub fn rz(&mut self, q: usize, theta: f64) -> Result<(), String> {
        let z = Complex64::zero();
        let e_neg = Complex64::exp_i(-theta * 0.5);
        let e_pos = Complex64::exp_i(theta * 0.5);
        self.apply_single_qubit_unitary(q, e_neg, z, z, e_pos)
    }

    pub fn cnot(&mut self, control: usize, target: usize) -> Result<(), String> {
        self.check_qubit(control)?;
        self.check_qubit(target)?;
        if control == target {
            return Err("CNOT control and target qubits must be distinct".into());
        }
        let c_bit = 1usize << control;
        let t_bit = 1usize << target;
        for i in 0..self.state.len() {
            if (i & c_bit) != 0 && (i & t_bit) == 0 {
                let j = i | t_bit;
                self.state.swap(i, j);
            }
        }
        Ok(())
    }

    pub fn cz(&mut self, control: usize, target: usize) -> Result<(), String> {
        self.check_qubit(control)?;
        self.check_qubit(target)?;
        if control == target {
            return Err("CZ control and target qubits must be distinct".into());
        }
        let mask = (1usize << control) | (1usize << target);
        for (i, amp) in self.state.iter_mut().enumerate() {
            if (i & mask) == mask {
                *amp = amp.scale(-1.0);
            }
        }
        Ok(())
    }

    pub fn swap(&mut self, q1: usize, q2: usize) -> Result<(), String> {
        self.check_qubit(q1)?;
        self.check_qubit(q2)?;
        if q1 == q2 {
            return Ok(());
        }
        let b1 = 1usize << q1;
        let b2 = 1usize << q2;
        for i in 0..self.state.len() {
            if (i & b1) == 0 && (i & b2) != 0 {
                let j = (i | b1) & !b2;
                self.state.swap(i, j);
            }
        }
        Ok(())
    }

    pub fn ccx(&mut self, c1: usize, c2: usize, target: usize) -> Result<(), String> {
        self.check_qubit(c1)?;
        self.check_qubit(c2)?;
        self.check_qubit(target)?;
        if c1 == c2 || c1 == target || c2 == target {
            return Err("CCX (Toffoli) qubits must be distinct".into());
        }
        let m_c = (1usize << c1) | (1usize << c2);
        let t_bit = 1usize << target;
        for i in 0..self.state.len() {
            if (i & m_c) == m_c && (i & t_bit) == 0 {
                let j = i | t_bit;
                self.state.swap(i, j);
            }
        }
        Ok(())
    }

    pub fn cphase(&mut self, control: usize, target: usize, theta: f64) -> Result<(), String> {
        self.check_qubit(control)?;
        self.check_qubit(target)?;
        if control == target {
            return Err("CPHASE control and target qubits must be distinct".into());
        }
        let mask = (1usize << control) | (1usize << target);
        let phase = Complex64::exp_i(theta);
        for (i, amp) in self.state.iter_mut().enumerate() {
            if (i & mask) == mask {
                *amp = amp.mul(phase);
            }
        }
        Ok(())
    }

    /// Full Quantum Fourier Transform across all circuit qubits.
    pub fn qft(&mut self) -> Result<(), String> {
        let n = self.num_qubits;
        for i in (0..n).rev() {
            self.h(i)?;
            for j in 0..i {
                let k = (i - j + 1) as i32;
                let angle = 2.0 * PI / (2.0f64.powi(k));
                self.cphase(j, i, angle)?;
            }
        }
        for i in 0..(n / 2) {
            self.swap(i, n - 1 - i)?;
        }
        Ok(())
    }

    /// Exact Born-rule measurement probability distribution $P(x) = |\langle x|\psi\rangle|^2$.
    pub fn probabilities(&self) -> Vec<f64> {
        self.state.iter().map(|c| c.norm_sq()).collect()
    }

    /// Computes the exact von Neumann entanglement entropy $S(\rho_A) = -\sum_k \lambda_k \log_2(\lambda_k)$
    /// (in bits / shannons) of subsystem $A$ (`subsystem_a_qubits`) relative to its complement $B$.
    pub fn entanglement_entropy(&self, subsystem_a_qubits: &[usize]) -> Result<f64, String> {
        for &q in subsystem_a_qubits {
            self.check_qubit(q)?;
        }
        if subsystem_a_qubits.is_empty() || subsystem_a_qubits.len() == self.num_qubits {
            return Ok(0.0);
        }
        // Deduplicate & validate subsystem A
        let mut a_qubits = Vec::with_capacity(subsystem_a_qubits.len());
        for &q in subsystem_a_qubits {
            if !a_qubits.contains(&q) {
                a_qubits.push(q);
            }
        }
        // Use the smaller of subsystem A or complement B (since S(rho_A) == S(rho_B) for pure states!)
        let b_qubits: Vec<usize> = (0..self.num_qubits)
            .filter(|q| !a_qubits.contains(q))
            .collect();
        let (sub_a, sub_b) = if a_qubits.len() <= b_qubits.len() {
            (a_qubits, b_qubits)
        } else {
            (b_qubits, a_qubits)
        };

        let dim_a = 1usize << sub_a.len();
        let dim_b = 1usize << sub_b.len();

        // Map (ia, ib) to full statevector index
        let map_index = |ia: usize, ib: usize| -> usize {
            let mut full = 0usize;
            for (bit_pos, &q) in sub_a.iter().enumerate() {
                if ((ia >> bit_pos) & 1) != 0 {
                    full |= 1usize << q;
                }
            }
            for (bit_pos, &q) in sub_b.iter().enumerate() {
                if ((ib >> bit_pos) & 1) != 0 {
                    full |= 1usize << q;
                }
            }
            full
        };

        // Construct reduced density matrix rho_A (dim_a x dim_a Hermitian)
        // Embed Hermitian complex matrix M = Re(rho_A) + i Im(rho_A) into a 2*dim_a x 2*dim_a
        // real symmetric matrix: [[Re, -Im], [Im, Re]], whose eigenvalues are doubled copies of
        // the eigenvalues of rho_A.
        let n_real = 2 * dim_a;
        let mut sym = vec![0.0f64; n_real * n_real];
        for i in 0..dim_a {
            for j in i..dim_a {
                let mut sum = Complex64::zero();
                for ib in 0..dim_b {
                    let idx_i = map_index(i, ib);
                    let idx_j = map_index(j, ib);
                    sum = sum.add(self.state[idx_i].mul(self.state[idx_j].conj()));
                }
                // Re block: (i, j) and (j, i), plus (i+dim_a, j+dim_a) and (j+dim_a, i+dim_a)
                sym[i * n_real + j] = sum.re;
                sym[j * n_real + i] = sum.re;
                sym[(i + dim_a) * n_real + (j + dim_a)] = sum.re;
                sym[(j + dim_a) * n_real + (i + dim_a)] = sum.re;

                // -Im in upper-right, +Im in lower-left (with Hermitian skew-symmetry Im[j,i] = -Im[i,j])
                sym[i * n_real + (j + dim_a)] = -sum.im;
                sym[(j + dim_a) * n_real + i] = -sum.im;

                sym[j * n_real + (i + dim_a)] = sum.im;
                sym[(i + dim_a) * n_real + j] = sum.im;
            }
        }

        let mut eigs = jacobi_real_symmetric_eigenvalues(&mut sym, n_real);
        eigs.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

        // Since the 2N x 2N real symmetric embedding duplicates each eigenvalue of rho_A twice,
        // take every second eigenvalue (index 0, 2, 4, ...).
        let mut entropy = 0.0f64;
        for k in 0..dim_a {
            let lambda = eigs[2 * k];
            if lambda > 1e-12 {
                entropy -= lambda * lambda.log2();
            }
        }
        if entropy.abs() < 1e-12 {
            entropy = 0.0;
        }
        Ok(entropy)
    }
}

/// Cyclic Jacobi eigenvalue solver for an `n x n` real symmetric matrix.
fn jacobi_real_symmetric_eigenvalues(a: &mut [f64], n: usize) -> Vec<f64> {
    for _sweep in 0..64 {
        let mut max_off = 0.0f64;
        for p in 0..n {
            for q in (p + 1)..n {
                let v = a[p * n + q].abs();
                if v > max_off {
                    max_off = v;
                }
            }
        }
        if max_off < 1e-14 {
            break;
        }
        for p in 0..n {
            for q in (p + 1)..n {
                let apq = a[p * n + q];
                if apq.abs() < 1e-15 {
                    continue;
                }
                let app = a[p * n + p];
                let aqq = a[q * n + q];
                let tau = (aqq - app) / (2.0 * apq);
                let t = if tau >= 0.0 {
                    1.0 / (tau + (1.0 + tau * tau).sqrt())
                } else {
                    -1.0 / (-tau + (1.0 + tau * tau).sqrt())
                };
                let c = 1.0 / (1.0 + t * t).sqrt();
                let s = t * c;

                a[p * n + p] = app - t * apq;
                a[q * n + q] = aqq + t * apq;
                a[p * n + q] = 0.0;
                a[q * n + p] = 0.0;

                for r in 0..n {
                    if r != p && r != q {
                        let arp = a[r * n + p];
                        let arq = a[r * n + q];
                        let new_rp = c * arp - s * arq;
                        let new_rq = s * arp + c * arq;
                        a[r * n + p] = new_rp;
                        a[p * n + r] = new_rp;
                        a[r * n + q] = new_rq;
                        a[q * n + r] = new_rq;
                    }
                }
            }
        }
    }
    (0..n).map(|i| a[i * n + i]).collect()
}

/// Runs Grover's Quantum Search Algorithm on `num_qubits` to locate `marked_state`.
/// Returns `(optimal_iterations, measured_top_state, target_probability, probabilities)`.
pub(crate) fn run_grover_search(
    num_qubits: usize,
    marked_state: usize,
) -> Result<(usize, usize, f64, Vec<f64>), String> {
    if !(2..=MAX_SIM_QUBITS).contains(&num_qubits) {
        return Err(format!(
            "Grover search requires 2..={MAX_SIM_QUBITS} qubits (got {num_qubits})"
        ));
    }
    let dim = 1usize << num_qubits;
    if marked_state >= dim {
        return Err(format!(
            "marked_state {marked_state} out of range for {num_qubits} qubits (0..{dim})"
        ));
    }

    let mut qc = QuantumCircuit::new(num_qubits)?;
    for q in 0..num_qubits {
        qc.h(q)?;
    }

    let optimal_iters = ((PI / 4.0) * (dim as f64).sqrt()).floor().max(1.0) as usize;
    let inv_dim = 2.0 / (dim as f64);

    for _ in 0..optimal_iters {
        // 1. Phase Oracle: flip phase of |marked_state>
        qc.state[marked_state] = qc.state[marked_state].scale(-1.0);

        // 2. Grover Diffusion Operator: 2|s><s| - I
        let mut mean = Complex64::zero();
        for amp in &qc.state {
            mean = mean.add(*amp);
        }
        mean = mean.scale(inv_dim);
        for amp in &mut qc.state {
            *amp = mean.sub(*amp);
        }
    }

    let probs = qc.probabilities();
    let mut best_idx = 0usize;
    let mut best_prob = -1.0f64;
    for (idx, &p) in probs.iter().enumerate() {
        if p > best_prob {
            best_prob = p;
            best_idx = idx;
        }
    }
    Ok((optimal_iters, best_idx, probs[marked_state], probs))
}

// ============================================================================
// 2. COSMIC-RAY SELF-HEALING SECDED (72, 64) ECC MEMORY
// ============================================================================

const ECC_MAGIC: &[u8; 8] = b"KVECC72\x01";

/// Computes the 8-bit Extended Hamming `(72, 64)` SECDED parity byte for a 64-bit word.
///
/// - Bits `p0..p5` (bits 0..=5 of the returned `u8`) are Hamming parity bits over the
///   71-bit standard Hamming `(71, 64)` layout where codeword positions `1..=71` hold
///   powers-of-two parity bits at `1, 2, 4, 8, 16, 32, 64`? Wait: for 64 data bits,
///   positions `1..=71` need 7 Hamming parity bits (`1, 2, 4, 8, 16, 32, 64`) plus 1 overall
///   parity bit = 8 parity bits total (`(72, 64)` SECDED)!
///
/// Specifically:
/// - Codeword positions `1..=71` consist of:
///   - 7 Hamming parity positions at $2^k$ for $k \in \{0, 1, 2, 3, 4, 5, 6\}$ (`1, 2, 4, 8, 16, 32, 64`).
///   - 64 data positions at the remaining non-power-of-two indices in `1..=71`.
/// - Bit 7 of the parity byte (`0x80`) is the overall even parity across all 64 data bits
///   and all 7 Hamming parity bits (`p0..p6`).
#[inline]
const fn data_bit_to_codeword_pos(data_bit: usize) -> usize {
    // Map data_bit in 0..64 to the non-power-of-2 position in 1..=71
    let mut pos = 3usize;
    let mut idx = 0usize;
    while pos <= 71 {
        if (pos & (pos - 1)) != 0 {
            if idx == data_bit {
                return pos;
            }
            idx += 1;
        }
        pos += 1;
    }
    0
}

const DATA_BIT_CODEWORD_POS: [usize; 64] = {
    let mut table = [0usize; 64];
    let mut i = 0;
    while i < 64 {
        table[i] = data_bit_to_codeword_pos(i);
        i += 1;
    }
    table
};

pub(crate) fn secded72_compute_parity(word: u64) -> u8 {
    let mut syndrome = 0u8;
    for (bit_idx, &pos) in DATA_BIT_CODEWORD_POS.iter().enumerate() {
        if ((word >> bit_idx) & 1) != 0 {
            syndrome ^= pos as u8;
        }
    }
    // Overall parity in bit 7 across all 64 data bits + 7 Hamming parity bits
    let total_ones = word.count_ones() + (syndrome.count_ones());
    if (total_ones & 1) != 0 {
        syndrome |= 0x80;
    }
    syndrome
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecdedWordStatus {
    Intact,
    CorrectedDataBit(usize),
    CorrectedParityBit(usize),
    UncorrectableDoubleBitError,
}

/// Decodes and self-heals a single `(64-bit word, 8-bit SECDED parity)` pair.
pub(crate) fn secded72_decode_word(word: u64, stored_parity: u8) -> (u64, u8, SecdedWordStatus) {
    let expected = secded72_compute_parity(word);
    let diff = expected ^ stored_parity;
    let hamming_syndrome = diff & 0x7F;
    let overall_parity_err = ((word.count_ones() + stored_parity.count_ones()) & 1) != 0;

    if hamming_syndrome == 0 && !overall_parity_err {
        return (word, stored_parity, SecdedWordStatus::Intact);
    }
    if hamming_syndrome == 0 && overall_parity_err {
        // Flip was in the overall parity bit (bit 7 of stored_parity)
        return (
            word,
            stored_parity ^ 0x80,
            SecdedWordStatus::CorrectedParityBit(7),
        );
    }
    if hamming_syndrome != 0 && !overall_parity_err {
        // Even number of bit flips (>= 2) with non-zero syndrome -> detected double-bit error!
        return (
            word,
            stored_parity,
            SecdedWordStatus::UncorrectableDoubleBitError,
        );
    }

    // Single-bit error at codeword position `hamming_syndrome` (or multi-bit odd error >71)
    let pos = hamming_syndrome as usize;
    if pos == 0 || pos > 71 {
        return (
            word,
            stored_parity,
            SecdedWordStatus::UncorrectableDoubleBitError,
        );
    }
    if (pos & (pos - 1)) == 0 {
        // Power of two -> flip was in one of the 7 Hamming parity bits (0..=6)
        let parity_bit = pos.trailing_zeros() as usize;
        let healed_parity = stored_parity ^ (1u8 << parity_bit);
        return (
            word,
            healed_parity,
            SecdedWordStatus::CorrectedParityBit(parity_bit),
        );
    }

    // Locate the data bit corresponding to codeword position `pos`
    for (data_bit, &cw_pos) in DATA_BIT_CODEWORD_POS.iter().enumerate() {
        if cw_pos == pos {
            let healed_word = word ^ (1u64 << data_bit);
            return (
                healed_word,
                stored_parity,
                SecdedWordStatus::CorrectedDataBit(data_bit),
            );
        }
    }

    (
        word,
        stored_parity,
        SecdedWordStatus::UncorrectableDoubleBitError,
    )
}

#[derive(Clone, Debug)]
pub(crate) struct EccDecodeReport {
    pub payload: Vec<u8>,
    pub healed: bool,
    pub corrected_bits: usize,
    pub total_words: usize,
    pub sha3_256_hex: String,
}

/// Encodes arbitrary bytes into a self-healing SECDED `(72, 64)` armored container (`kvecc1:...`).
///Even the header metadata (payload length + SHA3-256 digest) is SECDED-encoded so cosmic-ray
/// single-bit flips in the length or hash are also automatically healed!
pub(crate) fn secded_encode(payload: &[u8]) -> String {
    let digest = sha3_256(payload);
    // Construct inner frame: [u64 payload_len LE (8B)] || [sha3_256 (32B)] || [payload padded to 8B]
    let num_payload_words = payload.len().div_ceil(8);
    let total_words = 1 + 4 + num_payload_words; // 1 length word + 4 digest words + payload words

    let mut words = Vec::with_capacity(total_words);
    words.push(payload.len() as u64);
    for chunk in digest.chunks_exact(8) {
        words.push(u64::from_le_bytes(chunk.try_into().unwrap()));
    }
    for i in 0..num_payload_words {
        let start = i * 8;
        let end = (start + 8).min(payload.len());
        let mut buf = [0u8; 8];
        buf[..(end - start)].copy_from_slice(&payload[start..end]);
        words.push(u64::from_le_bytes(buf));
    }

    let mut out = Vec::with_capacity(8 + 4 + total_words * 9);
    out.extend_from_slice(ECC_MAGIC);
    out.extend_from_slice(&(total_words as u32).to_le_bytes());
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
        out.push(secded72_compute_parity(w));
    }
    armor_encode("kvecc1", &out)
}

/// Decodes and automatically heals a `kvecc1:...` SECDED container.
pub(crate) fn secded_decode_and_heal(token: &str) -> Result<EccDecodeReport, String> {
    let raw = armor_try_decode("kvecc1", token)?;
    if raw.len() < 12 + 5 * 9 {
        return Err("kvecc1 container truncated".into());
    }
    if &raw[0..8] != ECC_MAGIC {
        return Err("kvecc1 magic header mismatch".into());
    }
    let total_words = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
    if total_words < 5 || raw.len() != 12 + total_words * 9 {
        return Err("kvecc1 container word count mismatch".into());
    }

    let mut healed_words = Vec::with_capacity(total_words);
    let mut corrected_bits = 0usize;
    for i in 0..total_words {
        let offset = 12 + i * 9;
        let word = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
        let parity = raw[offset + 8];
        let (hw, _hp, status) = secded72_decode_word(word, parity);
        match status {
            SecdedWordStatus::Intact => {}
            SecdedWordStatus::CorrectedDataBit(_) | SecdedWordStatus::CorrectedParityBit(_) => {
                corrected_bits += 1;
            }
            SecdedWordStatus::UncorrectableDoubleBitError => {
                return Err(format!(
                    "SECDED (72,64) detected uncorrectable multi-bit corruption in word {i}"
                ));
            }
        }
        healed_words.push(hw);
    }

    let payload_len = healed_words[0] as usize;
    let num_payload_words = total_words - 5;
    if payload_len > num_payload_words * 8 {
        return Err("SECDED healed payload length exceeds container capacity".into());
    }

    let mut expected_digest = [0u8; 32];
    for i in 0..4 {
        expected_digest[i * 8..(i + 1) * 8].copy_from_slice(&healed_words[1 + i].to_le_bytes());
    }

    let mut payload = Vec::with_capacity(num_payload_words * 8);
    for &w in &healed_words[5..] {
        payload.extend_from_slice(&w.to_le_bytes());
    }
    payload.truncate(payload_len);

    let actual_digest = sha3_256(&payload);
    if actual_digest != expected_digest {
        return Err(
            "SECDED SHA3-256 post-heal integrity check failed (uncorrectable corruption)".into(),
        );
    }

    Ok(EccDecodeReport {
        payload,
        healed: corrected_bits > 0,
        corrected_bits,
        total_words,
        sha3_256_hex: bytes_to_hex(&actual_digest),
    })
}

/// Injects a single bit flip into word `word_index` at bit `bit_index` (`0..72`, where `0..64` is
/// the 64-bit data word and `64..72` is the 8-bit SECDED parity byte) of a `kvecc1:...` container.
pub(crate) fn secded_flip_bit(
    token: &str,
    word_index: usize,
    bit_index: usize,
) -> Result<String, String> {
    let mut raw = armor_try_decode("kvecc1", token)?;
    if raw.len() < 12 + 5 * 9 || &raw[0..8] != ECC_MAGIC {
        return Err("invalid kvecc1 container".into());
    }
    let total_words = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
    if word_index >= total_words {
        return Err(format!(
            "word_index {word_index} out of range (total_words = {total_words})"
        ));
    }
    if bit_index >= 72 {
        return Err(format!(
            "bit_index {bit_index} out of range (must be 0..72)"
        ));
    }
    let offset = 12 + word_index * 9 + (bit_index / 8);
    let bit_in_byte = bit_index % 8;
    raw[offset] ^= 1u8 << bit_in_byte;
    Ok(armor_encode("kvecc1", &raw))
}

// ============================================================================
// 3. POST-QUANTUM PROOF-CARRYING CODE (PCC) CERTIFICATES
// ============================================================================

#[derive(Clone, Debug)]
pub(crate) struct PccVerificationReport {
    pub valid: bool,
    pub sha3_512_hex: String,
    pub contracts_proven: usize,
    pub functions_checked: usize,
    pub invariants_checked: usize,
    pub engine_scheme: String,
}

/// Runs Kovrek's formal contract & invariant verifier on `source`, and if all obligations
/// are mathematically proven with 0 counterexamples, emits a canonical Post-Quantum
/// Proof-Carrying Code certificate signed with `armored_sec` (`kvsign1sec:...`).
pub(crate) fn certify_verified_source(source: &str, armored_sec: &str) -> Result<String, String> {
    let report = crate::pipeline::verify_source_strict(source)?;
    let ok = report.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    if !ok {
        let diags = report
            .get("diagnostics")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_else(|| "formal verification failed".to_string());
        return Err(format!(
            "certify_source formal verification failed: {diags}"
        ));
    }
    let checked_functions = report
        .get("functions_checked")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let checked_invariants = report
        .get("invariants_checked")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let contracts_proven = report
        .get("contracts_proven")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let total_obligations = contracts_proven + checked_invariants;
    if total_obligations == 0 {
        return Err(
            "certify_source requires at least one @verify contract or class invariant".into(),
        );
    }
    let digest = sha3_512(source.as_bytes());
    let digest_hex = bytes_to_hex(&digest);
    let canonical_statement = format!(
        "KOVREK-PCC-V1|scheme=ML-DSA-SIS+FORS-SHAKE256|sha3_512={}|functions={}|invariants={}|contracts={}",
        digest_hex, checked_functions, checked_invariants, total_obligations
    );
    let signature = pq_sign(armored_sec, canonical_statement.as_bytes())?;

    let cert_json = serde_json::json!({
        "format": "KOVREK-PCC-V1",
        "scheme": "ML-DSA-SIS+FORS-SHAKE256",
        "sha3_512": digest_hex,
        "functions_checked": checked_functions,
        "invariants_checked": checked_invariants,
        "contracts_proven": total_obligations,
        "statement": canonical_statement,
        "signature": signature,
    });
    serde_json::to_string_pretty(&cert_json).map_err(|e| e.to_string())
}

/// Verifies a Post-Quantum Proof-Carrying Code (PCC) JSON certificate against `source`
/// and `armored_pub` (`kvsign1pub:...`) without needing to re-run the SMT/bounded prover.
pub(crate) fn verify_code_certificate(
    source: &str,
    cert_json_str: &str,
    armored_pub: &str,
) -> Result<PccVerificationReport, String> {
    let parsed: serde_json::Value = serde_json::from_str(cert_json_str)
        .map_err(|e| format!("invalid PCC certificate JSON: {e}"))?;
    let format_str = parsed
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if format_str != "KOVREK-PCC-V1" {
        return Err(format!("unsupported PCC format '{format_str}'"));
    }
    let scheme = parsed
        .get("scheme")
        .and_then(|v| v.as_str())
        .unwrap_or("ML-DSA-SIS+FORS-SHAKE256")
        .to_string();
    let cert_sha3 = parsed
        .get("sha3_512")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "PCC missing sha3_512".to_string())?;
    let functions_checked = parsed
        .get("functions_checked")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let invariants_checked = parsed
        .get("invariants_checked")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let contracts_proven = parsed
        .get("contracts_proven")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let signature = parsed
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "PCC missing signature".to_string())?;

    let actual_digest_hex = bytes_to_hex(&sha3_512(source.as_bytes()));
    if actual_digest_hex != cert_sha3 || contracts_proven == 0 {
        return Ok(PccVerificationReport {
            valid: false,
            sha3_512_hex: actual_digest_hex,
            contracts_proven,
            functions_checked,
            invariants_checked,
            engine_scheme: scheme,
        });
    }

    let expected_statement = format!(
        "KOVREK-PCC-V1|scheme={}|sha3_512={}|functions={}|invariants={}|contracts={}",
        scheme, actual_digest_hex, functions_checked, invariants_checked, contracts_proven
    );
    let sig_ok = pq_verify(armored_pub, expected_statement.as_bytes(), signature)?;

    Ok(PccVerificationReport {
        valid: sig_ok,
        sha3_512_hex: actual_digest_hex,
        contracts_proven,
        functions_checked,
        invariants_checked,
        engine_scheme: scheme,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_crypto::pq_sign_keygen_deterministic;

    #[test]
    fn quantum_bell_ghz_entanglement_and_grover_search_exact() {
        // 1. Bell state |Phi+> = (|00> + |11>)/sqrt(2) has maximal entanglement entropy = 1.0 bit
        let mut bell = QuantumCircuit::new(2).expect("2-qubit circuit");
        bell.h(0).unwrap();
        bell.cnot(0, 1).unwrap();
        let probs = bell.probabilities();
        assert!((probs[0] - 0.5).abs() < 1e-12);
        assert!(probs[1].abs() < 1e-12);
        assert!(probs[2].abs() < 1e-12);
        assert!((probs[3] - 0.5).abs() < 1e-12);
        let entropy_bell = bell.entanglement_entropy(&[0]).unwrap();
        assert!(
            (entropy_bell - 1.0).abs() < 1e-9,
            "Bell state entanglement entropy must be 1.0 shannon, got {entropy_bell}"
        );

        // 2. Separable product state |+0> has entanglement entropy = 0.0 bit
        let mut sep = QuantumCircuit::new(2).unwrap();
        sep.h(0).unwrap();
        let entropy_sep = sep.entanglement_entropy(&[0]).unwrap();
        assert!(
            entropy_sep.abs() < 1e-9,
            "Product state entanglement entropy must be 0.0, got {entropy_sep}"
        );

        // 3. 4-qubit GHZ state (|0000> + |1111>)/sqrt(2) across bipartition {0,1} vs {2,3} = 1.0 bit
        let mut ghz = QuantumCircuit::new(4).unwrap();
        ghz.h(0).unwrap();
        ghz.cnot(0, 1).unwrap();
        ghz.cnot(1, 2).unwrap();
        ghz.cnot(2, 3).unwrap();
        let entropy_ghz = ghz.entanglement_entropy(&[0, 1]).unwrap();
        assert!(
            (entropy_ghz - 1.0).abs() < 1e-9,
            "GHZ bipartition entropy must be 1.0, got {entropy_ghz}"
        );

        // 4. Grover's Quantum Search on 6 qubits (64 states) for marked state 42
        let (iters, top_state, target_prob, _) = run_grover_search(6, 42).unwrap();
        assert_eq!(iters, 6);
        assert_eq!(top_state, 42);
        assert!(
            target_prob > 0.99,
            "Grover 6-qubit search probability for |42> should exceed 99%, got {target_prob}"
        );
    }

    #[test]
    fn secded_72_64_cosmic_ray_self_healing_and_double_bit_detection() {
        let msg = b"KOVREK SOVEREIGN COSMIC-RAY IMMUNE TELEMETRY FRAME // 22ND CENTURY";
        let token = secded_encode(msg);
        assert!(token.starts_with("kvecc1:"));

        // Clean decode
        let clean = secded_decode_and_heal(&token).expect("clean decode");
        assert_eq!(clean.payload, msg);
        assert!(!clean.healed);
        assert_eq!(clean.corrected_bits, 0);

        // Flip 1 bit in EVERY single word of the container (including length word 0,
        // SHA3-256 digest words 1..=4, and payload words 5..total_words)
        let mut irradiated = token.clone();
        for w in 0..clean.total_words {
            let bit_to_flip = (w * 13 + 7) % 72;
            irradiated = secded_flip_bit(&irradiated, w, bit_to_flip).unwrap();
        }
        let healed = secded_decode_and_heal(&irradiated).expect("self-heal 1 bit flip per word");
        assert_eq!(healed.payload, msg);
        assert!(healed.healed);
        assert_eq!(healed.corrected_bits, clean.total_words);

        // Flip 2 bits in the same word -> must be rejected as uncorrectable double-bit error
        let double_flipped =
            secded_flip_bit(&secded_flip_bit(&token, 5, 3).unwrap(), 5, 41).unwrap();
        assert!(
            secded_decode_and_heal(&double_flipped).is_err(),
            "Double-bit error in a single 72-bit word must be detected and rejected"
        );
    }

    #[test]
    fn post_quantum_proof_carrying_code_certification_and_tamper_rejection() {
        let (pub_key, sec_key) = pq_sign_keygen_deterministic(&[0x5A; 32]);
        let verified_kvr = r#"
@verify
fn clamp_altitude(alt: Int) -> Int {
    requires(alt >= 0, "alt >= 0");
    let clamped = alt;
    if clamped > 100000 {
        clamped = 100000;
    }
    ensures(clamped >= 0, "clamped >= 0");
    ensures(clamped <= 100000, "clamped <= 100000");
    return clamped;
}
"#;
        let cert = certify_verified_source(verified_kvr, &sec_key)
            .expect("formal verification + PQ signature certification");
        let check =
            verify_code_certificate(verified_kvr, &cert, &pub_key).expect("verify PCC certificate");
        assert!(check.valid);
        assert!(check.contracts_proven >= 2);

        // Tampering with a single character in source invalidates the PCC certificate
        let tampered_kvr = verified_kvr.replace("100000", "999999");
        let tampered_check = verify_code_certificate(&tampered_kvr, &cert, &pub_key).unwrap();
        assert!(!tampered_check.valid);
    }
}
