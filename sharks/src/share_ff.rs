use alloc::vec::*;
use core::convert::TryInto;

#[cfg(feature = "fuzzing")]
use arbitrary::Arbitrary;

use crate::ff::*;

pub const FIELD_ELEMENT_LEN: usize = 32;

#[cfg_attr(feature = "fuzzing", derive(Arbitrary))]
#[derive(PrimeField)]
#[PrimeFieldModulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Fp([u64; 4]);

impl From<Fp> for Vec<u8> {
    fn from(s: Fp) -> Vec<u8> {
        s.to_repr().as_ref().to_vec()
    }
}

impl From<Fp> for Vec<u64> {
    fn from(s: Fp) -> Vec<u64> {
        s.0.to_vec()
    }
}

// Finds the [root of the Lagrange polynomial](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach).
// The expected `shares` argument format is the same as the output by the `get_evaluator´ function.
// Where each (key, value) pair corresponds to one share, where the key is the `x` and the value is a vector of `y`,
// where each element corresponds to one of the secret's byte chunks.
pub fn interpolate(shares: &[Share]) -> Vec<u8> {
    let res: Vec<Vec<u8>> = (0..shares[0].y.len())
        .map(|s| {
            let e: Fp = shares
                .iter()
                .map(|s_i| {
                    let f: Fp = shares
                        .iter()
                        .filter(|s_j| s_j.x != s_i.x)
                        .map(|s_j| {
                            s_j.x.clone() * (s_j.x.clone() - s_i.x.clone()).invert().unwrap()
                        })
                        .fold(Fp::one(), |acc, x| acc * x); // take product of all fractions
                    f * s_i.y[s].clone()
                })
                .fold(Fp::zero(), |acc, x| acc + x); // take sum of all field elements
            Vec::from(e) // turn into byte vector
        })
        .collect();
    res.iter()
        .fold(Vec::new(), |acc, r| [acc, r.to_vec()].concat())
}

// Generates `k` polynomial coefficients, being the last one `s` and the
// others randomly generated in the field.
// Coefficient degrees go from higher to lower in the returned vector
// order.
pub fn random_polynomial<R: rand::Rng>(s: Fp, k: u32, rng: &mut R) -> Vec<Fp> {
    let k = k as usize;
    let mut poly = Vec::with_capacity(k);
    for _ in 1..k {
        poly.push(Fp::random(&mut *rng));
    }
    poly.push(s);

    poly
}

// Returns an iterator over the points of the `polys` polynomials passed as argument.
// Each item of the iterator is a tuple `(x, [f_1(x), f_2(x)..])` where eaxh `f_i` is the result for the ith polynomial.
// Each polynomial corresponds to one byte chunk of the original secret.
pub fn get_evaluator(polys: Vec<Vec<Fp>>) -> Evaluator {
    Evaluator {
        polys,
        x: Fp::zero(),
    }
}

#[derive(Debug)]
pub struct Evaluator {
    polys: Vec<Vec<Fp>>,
    x: Fp,
}

impl Evaluator {
    fn evaluate(&self, x: Fp) -> Share {
        Share {
            x: x.clone(),
            y: self
                .polys
                .iter()
                .map(|p| {
                    p.iter()
                        .fold(Fp::zero(), |acc, c| acc * x.clone() + c.clone())
                })
                .collect(),
        }
    }

    pub fn gen<R: rand::Rng>(&self, rng: &mut R) -> Share {
        let rand = Fp::random(rng);
        self.evaluate(rand)
    }
}

// Implement `Iterator` for `Evaluator`.
// The `Iterator` trait only requires a method to be defined for the `next` element.
impl Iterator for Evaluator {
    type Item = Share;

    fn next(&mut self) -> Option<Share> {
        self.x = self.x + Fp::one();
        Some(self.evaluate(self.x))
    }
}

/// A share used to reconstruct the secret. Can be serialized to and from a byte array.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(Arbitrary))]
pub struct Share {
    pub x: Fp,
    pub y: Vec<Fp>,
}

/// Obtains a byte vector from a `Share` instance
impl From<&Share> for Vec<u8> {
    fn from(s: &Share) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(s.y.len() + FIELD_ELEMENT_LEN);
        let repr = s.x.to_repr();
        let x_coord = repr.as_ref().to_vec();
        let y_coords: Vec<u8> =
            s.y.iter()
                .map(|p| p.to_repr().as_ref().to_vec())
                .fold(Vec::new(), |acc, r| [acc, r.to_vec()].concat());
        bytes.extend(x_coord);
        bytes.extend(y_coords);
        bytes
    }
}

/// Obtains a `Share` instance from a byte slice
impl core::convert::TryFrom<&[u8]> for Share {
    type Error = &'static str;

    fn try_from(s: &[u8]) -> Result<Share, Self::Error> {
        if s.len() < 2 {
            Err("A Share must be at least 2 bytes long")
        } else {
            let x = Fp::from_repr(FpRepr(
                s[..FIELD_ELEMENT_LEN]
                    .try_into()
                    .expect("Failed to parse bytes for x coordinate"),
            ))
            .unwrap();
            let y_coords_bytes = s[FIELD_ELEMENT_LEN..].to_vec();
            let total_y_coords_len = y_coords_bytes.len();
            let mut y = Vec::with_capacity(total_y_coords_len / FIELD_ELEMENT_LEN);
            for i in 0..total_y_coords_len / FIELD_ELEMENT_LEN {
                y.push(
                    Fp::from_repr(FpRepr(
                        y_coords_bytes[i * FIELD_ELEMENT_LEN..(i + 1) * FIELD_ELEMENT_LEN]
                            .try_into()
                            .expect("Failed to parse bytes for y coordinates"),
                    ))
                    .unwrap(),
                )
            }
            Ok(Share { x, y })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{get_evaluator, interpolate, random_polynomial};
    use super::{Fp, Share};
    use crate::ff::Field;
    use alloc::{vec, vec::Vec};
    use core::convert::TryFrom;
    use rand_chacha::rand_core::SeedableRng;

    fn fp_one() -> Fp {
        Fp::one()
    }

    fn fp_two() -> Fp {
        fp_one().double()
    }

    fn fp_three() -> Fp {
        fp_two() + fp_one()
    }

    #[test]
    fn field_addition() {
        let x = fp_one();
        let y = fp_two();
        let z = fp_three();
        assert_eq!(x + y, z);
    }

    #[test]
    fn field_mult() {
        let x = fp_three();
        let y = fp_one();
        let z = fp_three();
        assert_eq!(Vec::from(x * y) as Vec<u8>, Vec::from(z) as Vec<u8>);
    }

    #[test]
    fn random_polynomial_works() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
        let poly = random_polynomial(fp_one(), 3, &mut rng);
        assert_eq!(poly.len(), 3);
        assert_eq!(poly[2], fp_one());
    }

    #[test]
    fn evaluator_works() {
        let iter = get_evaluator(vec![vec![fp_three(), fp_two(), fp_three() + fp_two()]]);
        let values: Vec<(Fp, Vec<Fp>)> = iter.take(2).map(|s| (s.x.clone(), s.y.clone())).collect();
        assert_eq!(
            values,
            vec![
                (
                    fp_one(),
                    vec![Fp([
                        94489280490u64,
                        14822445601838602262,
                        11026904598472781706,
                        690069828877630411
                    ])]
                ),
                (
                    fp_two(),
                    vec![Fp([
                        197568495570u64,
                        17576572386601039918,
                        14671371399666020106,
                        3119850012535913734
                    ])]
                )
            ]
        );
    }

    #[test]
    fn interpolate_works() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
        let poly = random_polynomial(fp_one(), 5, &mut rng);
        let iter = get_evaluator(vec![poly]);
        let shares: Vec<Share> = iter.take(5).collect();
        let root = interpolate(&shares);
        let mut chk = vec![0u8; 32];
        chk[0] = 1u8;
        assert_eq!(root, chk);
    }

    #[test]
    fn vec_from_share_works() {
        let share = Share {
            x: fp_one(),
            y: vec![fp_two(), fp_three()],
        };
        let bytes = Vec::from(&share);
        let chk_bytes = get_test_bytes();
        assert_eq!(bytes, chk_bytes);
    }

    #[test]
    fn share_from_u8_slice_works() {
        let share = Share::try_from(&get_test_bytes()[..]).unwrap();
        assert_eq!(share.x, fp_one());
        assert_eq!(share.y, vec![fp_two(), fp_three()]);
    }

    fn get_test_bytes() -> Vec<u8> {
        let suffix = vec![0u8; 31];
        let mut bytes = vec![1u8; 1];
        bytes.extend(suffix.clone()); // x coord
        bytes.extend(vec![2u8; 1]);
        bytes.extend(suffix.clone()); // y coord #1
        bytes.extend(vec![3u8; 1]);
        bytes.extend(suffix.clone()); // y coord #2
        bytes
    }
}
