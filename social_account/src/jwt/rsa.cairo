//! RSA-2048 / SHA-256 (RS256) check without `core::circuit`.
//!
//! Replacement of `garaga::signatures::rsa::is_valid_rsa2048_sha256_signature`. Garaga checks the
//! same thing through circuits, which compile to the `RangeCheck96`, `AddMod` and `MulMod`
//! builtins. The SNIP-36 prover cannot prove those, so this file does the arithmetic with plain
//! felt252 operations instead. The hint format, the key format and the chain of reductions are
//! garaga's, so the client and the registry are untouched.
//!
//! Numbers are 24 limbs of 96 bits, low to high, the flattened `RSA2048Chunks`. The hint carries
//! quotient and remainder for the 17 modular reductions of `sig^65537 mod n`
//! (16 squarings, then one multiply by `sig`), and every one is checked exactly:
//! `a * b == q * n + r` over the integers.

use core::sha256::compute_sha256_byte_array;
use garaga::definitions::{RSA2048Chunks, RSA2048ReductionWitness};
use garaga::signatures::rsa::{
    RSA2048PublicKey, RSA2048ReductionWitnessSerde, RSA2048SignatureWithHint,
};

const LIMBS: usize = 24;
const POW32: felt252 = 0x100000000;
const POW96_U128: NonZero<u128> = 0x1000000000000000000000000;
const U96_MAX: felt252 = 0xffffffffffffffffffffffff;

/// Same signature as garaga's. False on any failed check, like garaga.
pub fn is_valid_rsa2048_sha256_signature(
    signature: @RSA2048SignatureWithHint, public_key: @RSA2048PublicKey, message: @ByteArray,
) -> bool {
    let m = pkcs1_sha256_limbs(compute_sha256_byte_array(message));
    let n = limbs(public_key.modulus);
    let s = limbs(signature.signature.signature);

    if !top_chunk_well_formed(n) || !top_chunk_well_formed(s) {
        return false;
    }
    if !gt_one(n) || is_even(n) || !lt(s, n) || !lt(m, n) {
        return false;
    }

    // The outer `RSA2048SignatureWithHint` deserializer already sliced exactly 17 witnesses.
    let mut hint = *signature.reductions_hint;
    let mut x = s;
    let mut ok = true;
    let mut i: usize = 0;
    while ok && i != 17 {
        let w: RSA2048ReductionWitness = Serde::deserialize(ref hint).unwrap();
        let q = limbs(@w.quotient);
        let r = limbs(@w.remainder);
        let b = if i == 16 {
            s
        } else {
            x
        };
        ok = top_chunk_well_formed(q)
            && top_chunk_well_formed(r)
            && lt(r, n)
            && reduction_holds(x, b, q, n, r);
        x = r;
        i += 1;
    }
    ok && x == m
}

/// a * b == q * n + r over the integers.
///
/// Both sides are built as 47 base-2^96 coefficients (each < 24 * 2^192 + 2^96, so no felt252
/// wrap), then carried into canonical limbs. Equal canonical forms, including the final carry,
/// mean equal integers.
fn reduction_holds(
    a: Span<felt252>, b: Span<felt252>, q: Span<felt252>, n: Span<felt252>, r: Span<felt252>,
) -> bool {
    normalize(product(a, b).span(), [].span()) == normalize(product(q, n).span(), r)
}

/// The 47 base-2^96 coefficients of a * b, low to high: `coeff[k] = sum of a[i] * b[j]` over all
/// `i + j == k`, not yet carried.
///
/// The same sum as nested loops over spans costs a bounds check and a span
/// pop per term and nearly tripled the gas of the whole token check (140M vs 58M). Straight-line
/// code lets each of the 576 terms be one mul and one add in the trace, which also matters for
/// the prover's memory.
fn product(mut a: Span<felt252>, mut b: Span<felt252>) -> Array<felt252> {
    let [
        a0,
        a1,
        a2,
        a3,
        a4,
        a5,
        a6,
        a7,
        a8,
        a9,
        a10,
        a11,
        a12,
        a13,
        a14,
        a15,
        a16,
        a17,
        a18,
        a19,
        a20,
        a21,
        a22,
        a23,
    ] =
        (*a
        .multi_pop_front::<24>()
        .unwrap())
        .unbox();
    let [
        b0,
        b1,
        b2,
        b3,
        b4,
        b5,
        b6,
        b7,
        b8,
        b9,
        b10,
        b11,
        b12,
        b13,
        b14,
        b15,
        b16,
        b17,
        b18,
        b19,
        b20,
        b21,
        b22,
        b23,
    ] =
        (*b
        .multi_pop_front::<24>()
        .unwrap())
        .unbox();
    array![
        a0 * b0, a0 * b1 + a1 * b0, a0 * b2 + a1 * b1 + a2 * b0,
        a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0, a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0,
        a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0,
        a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0,
        a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0,
        a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0,
        a0 * b9
            + a1 * b8
            + a2 * b7
            + a3 * b6
            + a4 * b5
            + a5 * b4
            + a6 * b3
            + a7 * b2
            + a8 * b1
            + a9 * b0,
        a0 * b10
            + a1 * b9
            + a2 * b8
            + a3 * b7
            + a4 * b6
            + a5 * b5
            + a6 * b4
            + a7 * b3
            + a8 * b2
            + a9 * b1
            + a10 * b0,
        a0 * b11
            + a1 * b10
            + a2 * b9
            + a3 * b8
            + a4 * b7
            + a5 * b6
            + a6 * b5
            + a7 * b4
            + a8 * b3
            + a9 * b2
            + a10 * b1
            + a11 * b0,
        a0 * b12
            + a1 * b11
            + a2 * b10
            + a3 * b9
            + a4 * b8
            + a5 * b7
            + a6 * b6
            + a7 * b5
            + a8 * b4
            + a9 * b3
            + a10 * b2
            + a11 * b1
            + a12 * b0,
        a0 * b13
            + a1 * b12
            + a2 * b11
            + a3 * b10
            + a4 * b9
            + a5 * b8
            + a6 * b7
            + a7 * b6
            + a8 * b5
            + a9 * b4
            + a10 * b3
            + a11 * b2
            + a12 * b1
            + a13 * b0,
        a0 * b14
            + a1 * b13
            + a2 * b12
            + a3 * b11
            + a4 * b10
            + a5 * b9
            + a6 * b8
            + a7 * b7
            + a8 * b6
            + a9 * b5
            + a10 * b4
            + a11 * b3
            + a12 * b2
            + a13 * b1
            + a14 * b0,
        a0 * b15
            + a1 * b14
            + a2 * b13
            + a3 * b12
            + a4 * b11
            + a5 * b10
            + a6 * b9
            + a7 * b8
            + a8 * b7
            + a9 * b6
            + a10 * b5
            + a11 * b4
            + a12 * b3
            + a13 * b2
            + a14 * b1
            + a15 * b0,
        a0 * b16
            + a1 * b15
            + a2 * b14
            + a3 * b13
            + a4 * b12
            + a5 * b11
            + a6 * b10
            + a7 * b9
            + a8 * b8
            + a9 * b7
            + a10 * b6
            + a11 * b5
            + a12 * b4
            + a13 * b3
            + a14 * b2
            + a15 * b1
            + a16 * b0,
        a0 * b17
            + a1 * b16
            + a2 * b15
            + a3 * b14
            + a4 * b13
            + a5 * b12
            + a6 * b11
            + a7 * b10
            + a8 * b9
            + a9 * b8
            + a10 * b7
            + a11 * b6
            + a12 * b5
            + a13 * b4
            + a14 * b3
            + a15 * b2
            + a16 * b1
            + a17 * b0,
        a0 * b18
            + a1 * b17
            + a2 * b16
            + a3 * b15
            + a4 * b14
            + a5 * b13
            + a6 * b12
            + a7 * b11
            + a8 * b10
            + a9 * b9
            + a10 * b8
            + a11 * b7
            + a12 * b6
            + a13 * b5
            + a14 * b4
            + a15 * b3
            + a16 * b2
            + a17 * b1
            + a18 * b0,
        a0 * b19
            + a1 * b18
            + a2 * b17
            + a3 * b16
            + a4 * b15
            + a5 * b14
            + a6 * b13
            + a7 * b12
            + a8 * b11
            + a9 * b10
            + a10 * b9
            + a11 * b8
            + a12 * b7
            + a13 * b6
            + a14 * b5
            + a15 * b4
            + a16 * b3
            + a17 * b2
            + a18 * b1
            + a19 * b0,
        a0 * b20
            + a1 * b19
            + a2 * b18
            + a3 * b17
            + a4 * b16
            + a5 * b15
            + a6 * b14
            + a7 * b13
            + a8 * b12
            + a9 * b11
            + a10 * b10
            + a11 * b9
            + a12 * b8
            + a13 * b7
            + a14 * b6
            + a15 * b5
            + a16 * b4
            + a17 * b3
            + a18 * b2
            + a19 * b1
            + a20 * b0,
        a0 * b21
            + a1 * b20
            + a2 * b19
            + a3 * b18
            + a4 * b17
            + a5 * b16
            + a6 * b15
            + a7 * b14
            + a8 * b13
            + a9 * b12
            + a10 * b11
            + a11 * b10
            + a12 * b9
            + a13 * b8
            + a14 * b7
            + a15 * b6
            + a16 * b5
            + a17 * b4
            + a18 * b3
            + a19 * b2
            + a20 * b1
            + a21 * b0,
        a0 * b22
            + a1 * b21
            + a2 * b20
            + a3 * b19
            + a4 * b18
            + a5 * b17
            + a6 * b16
            + a7 * b15
            + a8 * b14
            + a9 * b13
            + a10 * b12
            + a11 * b11
            + a12 * b10
            + a13 * b9
            + a14 * b8
            + a15 * b7
            + a16 * b6
            + a17 * b5
            + a18 * b4
            + a19 * b3
            + a20 * b2
            + a21 * b1
            + a22 * b0,
        a0 * b23
            + a1 * b22
            + a2 * b21
            + a3 * b20
            + a4 * b19
            + a5 * b18
            + a6 * b17
            + a7 * b16
            + a8 * b15
            + a9 * b14
            + a10 * b13
            + a11 * b12
            + a12 * b11
            + a13 * b10
            + a14 * b9
            + a15 * b8
            + a16 * b7
            + a17 * b6
            + a18 * b5
            + a19 * b4
            + a20 * b3
            + a21 * b2
            + a22 * b1
            + a23 * b0,
        a1 * b23
            + a2 * b22
            + a3 * b21
            + a4 * b20
            + a5 * b19
            + a6 * b18
            + a7 * b17
            + a8 * b16
            + a9 * b15
            + a10 * b14
            + a11 * b13
            + a12 * b12
            + a13 * b11
            + a14 * b10
            + a15 * b9
            + a16 * b8
            + a17 * b7
            + a18 * b6
            + a19 * b5
            + a20 * b4
            + a21 * b3
            + a22 * b2
            + a23 * b1,
        a2 * b23
            + a3 * b22
            + a4 * b21
            + a5 * b20
            + a6 * b19
            + a7 * b18
            + a8 * b17
            + a9 * b16
            + a10 * b15
            + a11 * b14
            + a12 * b13
            + a13 * b12
            + a14 * b11
            + a15 * b10
            + a16 * b9
            + a17 * b8
            + a18 * b7
            + a19 * b6
            + a20 * b5
            + a21 * b4
            + a22 * b3
            + a23 * b2,
        a3 * b23
            + a4 * b22
            + a5 * b21
            + a6 * b20
            + a7 * b19
            + a8 * b18
            + a9 * b17
            + a10 * b16
            + a11 * b15
            + a12 * b14
            + a13 * b13
            + a14 * b12
            + a15 * b11
            + a16 * b10
            + a17 * b9
            + a18 * b8
            + a19 * b7
            + a20 * b6
            + a21 * b5
            + a22 * b4
            + a23 * b3,
        a4 * b23
            + a5 * b22
            + a6 * b21
            + a7 * b20
            + a8 * b19
            + a9 * b18
            + a10 * b17
            + a11 * b16
            + a12 * b15
            + a13 * b14
            + a14 * b13
            + a15 * b12
            + a16 * b11
            + a17 * b10
            + a18 * b9
            + a19 * b8
            + a20 * b7
            + a21 * b6
            + a22 * b5
            + a23 * b4,
        a5 * b23
            + a6 * b22
            + a7 * b21
            + a8 * b20
            + a9 * b19
            + a10 * b18
            + a11 * b17
            + a12 * b16
            + a13 * b15
            + a14 * b14
            + a15 * b13
            + a16 * b12
            + a17 * b11
            + a18 * b10
            + a19 * b9
            + a20 * b8
            + a21 * b7
            + a22 * b6
            + a23 * b5,
        a6 * b23
            + a7 * b22
            + a8 * b21
            + a9 * b20
            + a10 * b19
            + a11 * b18
            + a12 * b17
            + a13 * b16
            + a14 * b15
            + a15 * b14
            + a16 * b13
            + a17 * b12
            + a18 * b11
            + a19 * b10
            + a20 * b9
            + a21 * b8
            + a22 * b7
            + a23 * b6,
        a7 * b23
            + a8 * b22
            + a9 * b21
            + a10 * b20
            + a11 * b19
            + a12 * b18
            + a13 * b17
            + a14 * b16
            + a15 * b15
            + a16 * b14
            + a17 * b13
            + a18 * b12
            + a19 * b11
            + a20 * b10
            + a21 * b9
            + a22 * b8
            + a23 * b7,
        a8 * b23
            + a9 * b22
            + a10 * b21
            + a11 * b20
            + a12 * b19
            + a13 * b18
            + a14 * b17
            + a15 * b16
            + a16 * b15
            + a17 * b14
            + a18 * b13
            + a19 * b12
            + a20 * b11
            + a21 * b10
            + a22 * b9
            + a23 * b8,
        a9 * b23
            + a10 * b22
            + a11 * b21
            + a12 * b20
            + a13 * b19
            + a14 * b18
            + a15 * b17
            + a16 * b16
            + a17 * b15
            + a18 * b14
            + a19 * b13
            + a20 * b12
            + a21 * b11
            + a22 * b10
            + a23 * b9,
        a10 * b23
            + a11 * b22
            + a12 * b21
            + a13 * b20
            + a14 * b19
            + a15 * b18
            + a16 * b17
            + a17 * b16
            + a18 * b15
            + a19 * b14
            + a20 * b13
            + a21 * b12
            + a22 * b11
            + a23 * b10,
        a11 * b23
            + a12 * b22
            + a13 * b21
            + a14 * b20
            + a15 * b19
            + a16 * b18
            + a17 * b17
            + a18 * b16
            + a19 * b15
            + a20 * b14
            + a21 * b13
            + a22 * b12
            + a23 * b11,
        a12 * b23
            + a13 * b22
            + a14 * b21
            + a15 * b20
            + a16 * b19
            + a17 * b18
            + a18 * b17
            + a19 * b16
            + a20 * b15
            + a21 * b14
            + a22 * b13
            + a23 * b12,
        a13 * b23
            + a14 * b22
            + a15 * b21
            + a16 * b20
            + a17 * b19
            + a18 * b18
            + a19 * b17
            + a20 * b16
            + a21 * b15
            + a22 * b14
            + a23 * b13,
        a14 * b23
            + a15 * b22
            + a16 * b21
            + a17 * b20
            + a18 * b19
            + a19 * b18
            + a20 * b17
            + a21 * b16
            + a22 * b15
            + a23 * b14,
        a15 * b23
            + a16 * b22
            + a17 * b21
            + a18 * b20
            + a19 * b19
            + a20 * b18
            + a21 * b17
            + a22 * b16
            + a23 * b15,
        a16 * b23
            + a17 * b22
            + a18 * b21
            + a19 * b20
            + a20 * b19
            + a21 * b18
            + a22 * b17
            + a23 * b16,
        a17 * b23 + a18 * b22 + a19 * b21 + a20 * b20 + a21 * b19 + a22 * b18 + a23 * b17,
        a18 * b23 + a19 * b22 + a20 * b21 + a21 * b20 + a22 * b19 + a23 * b18,
        a19 * b23 + a20 * b22 + a21 * b21 + a22 * b20 + a23 * b19,
        a20 * b23 + a21 * b22 + a22 * b21 + a23 * b20, a21 * b23 + a22 * b22 + a23 * b21,
        a22 * b23 + a23 * b22, a23 * b23,
    ]
}

/// Carries each coefficient (plus the matching limb of `add`, while it has any) into a 96-bit
/// limb; the final carry is appended as the last element.
fn normalize(coeffs: Span<felt252>, mut add: Span<felt252>) -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut carry: felt252 = 0;
    for c in coeffs {
        let extra = match add.pop_front() {
            Some(x) => *x,
            None => 0,
        };
        let v: u256 = (*c + carry + extra).into();
        let (hi, limb) = DivRem::div_rem(v.low, POW96_U128);
        out.append(limb.into());
        carry = v.high.into() * POW32 + hi.into();
    }
    out.append(carry);
    out
}

/// The 24 limbs of a chunked number, low to high, as felts.
fn limbs(c: @RSA2048Chunks) -> Span<felt252> {
    let mut out: Array<felt252> = array![];
    c.serialize(ref out);
    out.span()
}

fn to_u128(x: felt252) -> u128 {
    x.try_into().unwrap()
}

/// a < b
fn lt(a: Span<felt252>, b: Span<felt252>) -> bool {
    let mut i = LIMBS;
    loop {
        if i == 0 {
            break false;
        }
        i -= 1;
        if *a[i] != *b[i] {
            break to_u128(*a[i]) < to_u128(*b[i]);
        }
    }
}

fn gt_one(a: Span<felt252>) -> bool {
    let mut i = 1;
    while i != LIMBS {
        if *a[i] != 0 {
            return true;
        }
        i += 1;
    }
    to_u128(*a[0]) > 1
}

fn is_even(a: Span<felt252>) -> bool {
    to_u128(*a[0]) % 2 == 0
}

/// The top chunk (limbs 20..23) holds only 128 bits: limb 21 <= 0xFFFFFFFF, limbs 22 and 23 zero.
fn top_chunk_well_formed(a: Span<felt252>) -> bool {
    *a[22] == 0 && *a[23] == 0 && to_u128(*a[21]) <= 0xFFFFFFFF
}

/// PKCS#1 v1.5 SHA-256 encoding, 256 bytes big endian:
/// `0x00 || 0x01 || 0xFF * 202 || 0x00 || DigestInfo(19) || SHA-256(32)`, as 24 limbs.
/// Same constants as garaga's `pkcs1_v1_5_sha256_encode`.
fn pkcs1_sha256_limbs(hash: [u32; 8]) -> Span<felt252> {
    let [h0, h1, h2, h3, h4, h5, h6, h7] = hash;
    let (h0, h1, h2, h3): (felt252, felt252, felt252, felt252) = (
        h0.into(), h1.into(), h2.into(), h3.into(),
    );
    let (h4, h5, h6, h7): (felt252, felt252, felt252, felt252) = (
        h4.into(), h5.into(), h6.into(), h7.into(),
    );
    array![
        // w0: hash tail and DigestInfo
        h5 * 0x10000000000000000 + h6 * POW32 + h7, h2 * 0x10000000000000000 + h3 * POW32 + h4,
        0x05000420 * 0x10000000000000000 + h0 * POW32 + h1, 0x0d0609608648016503040201,
        // w1
        0xffffffffffffffff00303130, U96_MAX, U96_MAX, U96_MAX, // w2..w4: padding
        U96_MAX, U96_MAX,
        U96_MAX, U96_MAX, U96_MAX, U96_MAX, U96_MAX, U96_MAX, U96_MAX, U96_MAX, U96_MAX,
        U96_MAX, // w5: padding start, 0x00 0x01
        U96_MAX, 0x0001ffff, 0, 0,
    ]
        .span()
}

#[cfg(test)]
mod tests {
    use garaga::signatures::rsa::{RSA2048PublicKey, RSA2048SignatureWithHint};
    use snforge_std::fs::{FileTrait, read_txt};
    use super::is_valid_rsa2048_sha256_signature;

    const SIG_WITH_HINT_LEN: usize = 48 + 17 * 48;

    /// Output of `backend/src/scripts/gen-rsa-fixture.ts`: a fresh key, an RS256 signature and
    /// the garaga hint, laid out as modulus, signature with hint, then the signed message.
    fn vector() -> (RSA2048PublicKey, Span<felt252>, ByteArray) {
        let mut felts = read_txt(@FileTrait::new("tests/data/rsa_sha256_vector.txt")).span();
        let key = Serde::<RSA2048PublicKey>::deserialize(ref felts).unwrap();
        let sig = felts.slice(0, SIG_WITH_HINT_LEN);
        let mut rest = felts.slice(SIG_WITH_HINT_LEN, felts.len() - SIG_WITH_HINT_LEN);
        let message = Serde::<ByteArray>::deserialize(ref rest).unwrap();
        (key, sig, message)
    }

    fn check(mut sig: Span<felt252>, key: @RSA2048PublicKey, message: @ByteArray) -> bool {
        let sig = Serde::<RSA2048SignatureWithHint>::deserialize(ref sig).unwrap();
        is_valid_rsa2048_sha256_signature(@sig, key, message)
    }

    /// `felts` with the element at `index` bumped by `delta`.
    fn bumped(felts: Span<felt252>, index: usize, delta: felt252) -> Span<felt252> {
        let mut out: Array<felt252> = array![];
        let mut i = 0;
        for f in felts {
            out.append(if i == index {
                *f + delta
            } else {
                *f
            });
            i += 1;
        }
        out.span()
    }

    #[test]
    fn accepts_a_valid_signature() {
        let (key, sig, message) = vector();
        assert!(check(sig, @key, @message));
    }

    #[test]
    fn rejects_another_message() {
        let (key, sig, message) = vector();
        assert!(!check(sig, @key, @(message + "!")));
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let (key, sig, message) = vector();
        assert!(!check(bumped(sig, 0, 1), @key, @message));
    }

    #[test]
    fn rejects_a_tampered_quotient() {
        let (key, sig, message) = vector();
        assert!(!check(bumped(sig, 48 + 48 * 7 + 3, 1), @key, @message));
    }

    #[test]
    fn rejects_a_tampered_remainder() {
        let (key, sig, message) = vector();
        assert!(!check(bumped(sig, 48 + 48 * 7 + 24 + 3, 1), @key, @message));
    }

    #[test]
    fn rejects_another_key() {
        let (key, sig, message) = vector();
        let mut felts: Array<felt252> = array![];
        key.serialize(ref felts);
        let mut other = bumped(felts.span(), 0, 2);
        let other = Serde::<RSA2048PublicKey>::deserialize(ref other).unwrap();
        assert!(!check(sig, @other, @message));
    }
}
