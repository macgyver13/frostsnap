//! Silent payment sending (BIP352) and the BIP374 DLEQ proofs that let every party check a share
//! of the ECDH before anything is signed with it.
//!
//! Everything here is a pure function over points and scalars. Frostsnap's threshold ECDH works
//! on account key shares `x_j`: each party publishes `x_j * B_scan` with a DLEQ proof against its
//! share image, and [`combine_ecdh_shares`] turns any threshold of those into the same point the
//! sender would compute from the summed input secret.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use bitcoin::{hashes::Hash, OutPoint};
use schnorr_fun::{
    frost::ShareIndex,
    fun::{g, hash::Tag, marker::*, poly, s, Point, Scalar, G},
};
use sha2::{Digest, Sha256};

use crate::tweak::TweakContext;

fn tagged(tag: &str) -> Sha256 {
    Sha256::default().tag(tag.as_bytes())
}

fn xor_32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (out, (a, b)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
        *out = a ^ b;
    }
    out
}

/// BIP374 challenge `e`. `m` is the optional message, empty when absent.
fn dleq_challenge(
    a: Point,
    b: Point,
    c: Point,
    g_point: Point,
    r1: Point,
    r2: Point,
    m: Option<&[u8; 32]>,
) -> Scalar<Public, Zero> {
    let mut hash = tagged("BIP0374/challenge")
        .chain_update(a.to_bytes())
        .chain_update(b.to_bytes())
        .chain_update(c.to_bytes())
        .chain_update(g_point.to_bytes())
        .chain_update(r1.to_bytes())
        .chain_update(r2.to_bytes());
    if let Some(m) = m {
        hash = hash.chain_update(m);
    }
    Scalar::from_bytes_mod_order(hash.finalize().into())
}

/// BIP374 `GenerateProof`: a 64-byte proof `e || s` that `a * g_point` and `a * b` share the
/// secret `a`. `r` is fresh auxiliary randomness and `m` an optional 32-byte message.
pub fn dleq_prove(
    a: Scalar,
    b: Point,
    r: &[u8; 32],
    g_point: Point,
    m: Option<&[u8; 32]>,
) -> Option<[u8; 64]> {
    let a_point = g!(a * g_point).normalize().non_zero()?;
    let c = g!(a * b).normalize().non_zero()?;

    let t = xor_32(
        a.to_bytes(),
        tagged("BIP0374/aux").chain_update(r).finalize().into(),
    );
    let mut rand = tagged("BIP0374/nonce")
        .chain_update(t)
        .chain_update(a_point.to_bytes())
        .chain_update(c.to_bytes());
    if let Some(m) = m {
        rand = rand.chain_update(m);
    }
    let k = Scalar::<Secret, Zero>::from_bytes_mod_order(rand.finalize().into()).non_zero()?;

    let r1 = g!(k * g_point).normalize().non_zero()?;
    let r2 = g!(k * b).normalize().non_zero()?;
    let e = dleq_challenge(a_point, b, c, g_point, r1, r2, m);
    let s = s!(k + e * a);

    let mut proof = [0u8; 64];
    proof[..32].copy_from_slice(&e.to_bytes());
    proof[32..].copy_from_slice(&s.to_bytes());

    // The spec has the prover check its own proof before returning it.
    dleq_verify(a_point, b, c, g_point, &proof, m).then_some(proof)
}

/// BIP374 `VerifyProof`: checks that `a` and `c` are `x * g_point` and `x * b` for one `x`.
pub fn dleq_verify(
    a: Point,
    b: Point,
    c: Point,
    g_point: Point,
    proof: &[u8; 64],
    m: Option<&[u8; 32]>,
) -> bool {
    let (Some(e), Some(s)) = (
        Scalar::<Public, Zero>::from_slice(&proof[..32]),
        Scalar::<Public, Zero>::from_slice(&proof[32..]),
    ) else {
        return false;
    };
    let Some(r1) = g!(s * g_point - e * a).normalize().non_zero() else {
        return false;
    };
    let Some(r2) = g!(s * b - e * c).normalize().non_zero() else {
        return false;
    };
    e == dleq_challenge(a, b, c, g_point, r1, r2, m)
}

/// BIP352 `input_hash`, binding the lexicographically smallest outpoint of the transaction to the
/// sum of the input public keys.
pub fn input_hash(smallest_outpoint: &OutPoint, a_sum_public: Point) -> Option<Scalar<Public>> {
    let hash = tagged("BIP0352/Inputs")
        .chain_update(smallest_outpoint.txid.as_byte_array())
        .chain_update(smallest_outpoint.vout.to_le_bytes())
        .chain_update(a_sum_public.to_bytes())
        .finalize();
    Scalar::from_bytes(hash.into())?.non_zero()
}

/// BIP352 `t_k`, the tweak of the `k`th output to a scan key given that key's shared secret
/// `ecdh = input_hash * a_sum * B_scan`.
fn shared_secret_tweak(ecdh: Point, k: u32) -> Option<Scalar<Public>> {
    let hash = tagged("BIP0352/SharedSecret")
        .chain_update(ecdh.to_bytes())
        .chain_update(k.to_be_bytes())
        .finalize();
    Scalar::from_bytes(hash.into())?.non_zero()
}

/// Combines the ECDH shares of a threshold of account key shares into the BIP352 shared secret
/// `input_hash * a_sum * B_scan`, where `a_sum` is the sum of the input secrets that `inputs`
/// describe.
///
/// Each entry of `shares` is a share index and `x_j * B_scan` for that share's account key share
/// `x_j`. The account secret is the Lagrange combination of the shares, so the result does not
/// depend on which threshold subset was used.
pub fn combine_ecdh_shares(
    input_hash: Scalar<Public>,
    b_scan: Point,
    inputs: &[TweakContext],
    shares: &[(ShareIndex, Point)],
) -> Option<Point> {
    let indices = shares.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    let distinct = indices.iter().collect::<BTreeSet<_>>();
    if indices.is_empty() || distinct.len() != indices.len() {
        return None;
    }

    // a_sum = Gx * x + T, with Gx and T summed over the inputs.
    let gx = inputs
        .iter()
        .fold(Scalar::<Public, Zero>::zero(), |acc, input| {
            s!(acc + input.gv * input.gacc).public()
        });
    let t = inputs
        .iter()
        .fold(Scalar::<Public, Zero>::zero(), |acc, input| {
            s!(acc + input.gv * input.tacc).public()
        });

    // x * B_scan = sum of lambda_j * (x_j * B_scan)
    let x_b_scan = shares.iter().fold(
        Point::<Normal, Public, Zero>::zero(),
        |acc, &(index, share)| {
            let lambda = poly::eval_basis_poly_at_0(index, indices.iter().copied());
            g!(acc + lambda * share).normalize()
        },
    );

    let a_sum_b_scan = g!(gx * x_b_scan + t * b_scan).normalize();
    g!(input_hash * a_sum_b_scan).normalize().non_zero()
}

/// A silent payment recipient, identified by the scan and spend keys in its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SilentPaymentRecipient {
    pub scan_key: Point,
    pub spend_key: Point,
}

/// Limit on silent payment outputs to one scan key within a transaction (BIP352 `K_max`).
const K_MAX: u32 = 2323;

/// BIP352 output keys for `recipients`, in the order given, as x-only public keys.
///
/// `shared_secrets` maps each scan key to its shared secret, see [`combine_ecdh_shares`]. Outputs
/// to one scan key are numbered by `k` in recipient order, so the order of recipients to a scan
/// key matters. Returns `None` if a scan key has no shared secret, a group exceeds `K_MAX`, or a
/// tweak is invalid.
pub fn output_keys(
    recipients: &[SilentPaymentRecipient],
    shared_secrets: &BTreeMap<Point, Point>,
) -> Option<Vec<[u8; 32]>> {
    let mut next_k = BTreeMap::<Point, u32>::new();
    recipients
        .iter()
        .map(|recipient| {
            let k = next_k.entry(recipient.scan_key).or_default();
            if *k >= K_MAX {
                return None;
            }
            let t = shared_secret_tweak(*shared_secrets.get(&recipient.scan_key)?, *k)?;
            *k += 1;
            let output = g!(recipient.spend_key + t * G).normalize().non_zero()?;
            Some(output.to_xonly_bytes())
        })
        .collect()
}
