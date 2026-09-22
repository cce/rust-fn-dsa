//! Deterministic Falcon (round 3), as specified by
//! `algorand/FalconDeterministic`.
//!
//! Everything below the scheme level -- the emulated floating point, the FFT,
//! the Gram matrix, fast Fourier sampling and the encoder -- is this crate's
//! own code. Only three things differ from FN-DSA: the nonce is a fixed
//! versioned salt rather than random, the message is hashed with round-3
//! Falcon's plain rule (which this crate already reaches via the `0xFF` hash
//! identifier), and the sampler runs on ChaCha20 seeded from
//! `SHAKE256(logn || privkey || data)` rather than on SHAKE256.
//!
//! Build with the `fp_emu` feature so signing uses the emulated float backend,
//! matching `algorand/falcon`'s `FALCON_FPEMU = 1`.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use fn_dsa_comm::shake::SHAKE256;
use fn_dsa_comm::{signature_size, DomainContext, HashIdentifier, PRNG};
use fn_dsa_comm::{CryptoRng, RngCore, RngError};

use super::{decode_inner, flr, sign_inner, sign_key_size, vrfy_key_size};

/// The salt version this implementation signs with.
pub const CURRENT_SALT_VERSION: u8 = 0;

const SALT_DOMAIN: &[u8] = b"FALCON_DET";

/// Builds the 40-byte fixed salt for a salt version: the version byte, a byte
/// holding `logn`, the ASCII domain separator, and zero padding.
fn det_salt(logn: u32, version: u8) -> [u8; 40] {
    let mut s = [0u8; 40];
    s[0] = version;
    s[1] = logn as u8;
    s[2..2 + SALT_DOMAIN.len()].copy_from_slice(SALT_DOMAIN);
    s
}

/// ChaCha20 generator, as round-3 Falcon's `rng.c` specifies. Seeded from 56
/// bytes: 48 of key and nonce material, then the initial block counter.
#[derive(Copy, Clone)]
pub struct ChaCha20PRNG {
    buf: [u8; 512],
    ptr: usize,
    state: [u8; 56],
}

const CW: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

#[inline(always)]
fn qround(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

impl ChaCha20PRNG {
    fn refill(&mut self) {
        let mut cc = u64::from_le_bytes(self.state[48..56].try_into().unwrap());
        let mut d32 = [0u32; 12];
        for (i, w) in d32.iter_mut().enumerate() {
            *w = u32::from_le_bytes(self.state[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for u in 0..8usize {
            let mut st = [0u32; 16];
            st[0..4].copy_from_slice(&CW);
            st[4..16].copy_from_slice(&d32);
            st[14] ^= cc as u32;
            st[15] ^= (cc >> 32) as u32;
            for _ in 0..10 {
                qround(&mut st, 0, 4, 8, 12);
                qround(&mut st, 1, 5, 9, 13);
                qround(&mut st, 2, 6, 10, 14);
                qround(&mut st, 3, 7, 11, 15);
                qround(&mut st, 0, 5, 10, 15);
                qround(&mut st, 1, 6, 11, 12);
                qround(&mut st, 2, 7, 8, 13);
                qround(&mut st, 3, 4, 9, 14);
            }
            for v in 0..4 {
                st[v] = st[v].wrapping_add(CW[v]);
            }
            for v in 4..14 {
                st[v] = st[v].wrapping_add(d32[v - 4]);
            }
            st[14] = st[14].wrapping_add(d32[10] ^ (cc as u32));
            st[15] = st[15].wrapping_add(d32[11] ^ ((cc >> 32) as u32));
            cc = cc.wrapping_add(1);
            // Output words are interleaved the way the reference's AVX2 code
            // produces them; the scalar path reproduces that layout.
            for v in 0..16usize {
                let off = (u << 2) + (v << 5);
                self.buf[off..off + 4].copy_from_slice(&st[v].to_le_bytes());
            }
        }
        self.state[48..56].copy_from_slice(&cc.to_le_bytes());
        self.ptr = 0;
    }
}

impl PRNG for ChaCha20PRNG {
    fn new(seed: &[u8]) -> Self {
        let mut p = ChaCha20PRNG { buf: [0u8; 512], ptr: 0, state: [0u8; 56] };
        let n = core::cmp::min(seed.len(), 56);
        p.state[..n].copy_from_slice(&seed[..n]);
        p.refill();
        p
    }

    fn next_u8(&mut self) -> u8 {
        let v = self.buf[self.ptr];
        self.ptr += 1;
        if self.ptr == self.buf.len() {
            self.refill();
        }
        v
    }

    fn next_u16(&mut self) -> u16 {
        let lo = self.next_u8() as u16;
        let hi = self.next_u8() as u16;
        lo | (hi << 8)
    }

    fn next_u64(&mut self) -> u64 {
        // Fewer than nine bytes left triggers a refill, dropping the tail of
        // the buffer; the reference does the same, so the streams agree.
        let mut u = self.ptr;
        if u >= self.buf.len() - 9 {
            self.refill();
            u = 0;
        }
        self.ptr = u + 8;
        u64::from_le_bytes(self.buf[u..u + 8].try_into().unwrap())
    }
}

/// Feeds sign_inner the deterministic mode's randomness: the fixed salt where
/// it asks for a nonce, then successive reads of
/// `SHAKE256(logn || privkey || data)` where it asks for a sampler seed.
struct DetRng {
    salt: [u8; 40],
    salt_used: bool,
    stream: SHAKE256,
}

impl RngCore for DetRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if !self.salt_used && dest.len() == 40 {
            dest.copy_from_slice(&self.salt);
            self.salt_used = true;
            return;
        }
        self.stream.extract(dest);
    }

    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DetRng {}

/// Produces a deterministic Falcon signature in the unsalted compressed
/// format, as `falcon_det512_sign_compressed` does.
///
/// The returned buffer is the fixed-size encoding: the variable-length form
/// that `algorand/falcon` emits is the same bytes with the trailing zeros
/// removed.
pub fn det_sign_compressed(privkey: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    if privkey.is_empty() || (privkey[0] & 0xF0) != 0x50 {
        return None;
    }
    let logn = (privkey[0] & 0x0F) as u32;
    if !(9..=10).contains(&logn) || privkey.len() != sign_key_size(logn) {
        return None;
    }
    let n = 1usize << logn;

    let mut f = vec![0i8; n];
    let mut g = vec![0i8; n];
    let mut ff = vec![0i8; n];
    let mut gg = vec![0i8; n];
    let mut vk = vec![0u8; vrfy_key_size(logn)];
    let mut hvk = [0u8; 64];
    let mut tmp_u16 = vec![0u16; 2 * n];
    decode_inner(logn, logn, &mut f, &mut g, &mut ff, &mut gg,
        &mut vk, &mut hvk, &mut tmp_u16, privkey)?;

    // The sampler's randomness: SHAKE256(logn || privkey || data).
    let mut stream = SHAKE256::new();
    stream.inject(&[logn as u8]);
    stream.inject(privkey);
    stream.inject(msg);
    stream.flip();

    let mut rng = DetRng {
        salt: det_salt(logn, CURRENT_SALT_VERSION),
        salt_used: false,
        stream,
    };

    // The 0xFF hash identifier selects round-3 Falcon's plain hash-to-point,
    // SHAKE256(nonce || message), with no domain separation.
    let id = HashIdentifier(&[0xFFu8]);
    let ctx = DomainContext(b"");

    let mut sig = vec![0u8; signature_size(logn)];
    let mut tmp_i16 = vec![0i16; 2 * n];
    let mut tmp_u16b = vec![0u16; 2 * n];
    let mut tmp_flr = vec![flr::FLR::ZERO; 10 * n];

    #[cfg(not(feature = "small_context"))]
    {
        let mut basis = vec![flr::FLR::ZERO; 4 * n];
        super::compute_basis_inner(logn, &f, &g, &ff, &gg, &mut basis);
        sign_inner::<DetRng, ChaCha20PRNG>(logn, &mut rng,
            &f, &g, &ff, &gg, &hvk, &ctx, &id, msg, &mut sig,
            &basis, &mut tmp_i16, &mut tmp_u16b, &mut tmp_flr);
    }
    #[cfg(feature = "small_context")]
    sign_inner::<DetRng, ChaCha20PRNG>(logn, &mut rng,
        &f, &g, &ff, &gg, &hvk, &ctx, &id, msg, &mut sig,
        &mut tmp_i16, &mut tmp_u16b, &mut tmp_flr);

    // sign_inner emits the salted form: header || nonce || s2. The unsalted
    // form replaces the 40-byte salt with just its version byte and sets the
    // top bit of the header.
    let mut out = vec![0u8; sig.len() - 40 + 1];
    out[0] = sig[0] | 0x80;
    out[1] = CURRENT_SALT_VERSION;
    out[2..].copy_from_slice(&sig[41..]);
    Some(out)
}
