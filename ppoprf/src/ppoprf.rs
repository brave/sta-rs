//! This module defines the `Client` and `Server` functionality for a
//! puncturable partially oblivious pseudorandom function (PPOPRF).
//!
//! The POPRF that is used is very similar to the design of [Tyagi et
//! al.](https://eprint.iacr.org/2021/864.pdf), but where H_3 is
//! replaced with a puncturable PRF evaluation (over a small input
//! domain). This allows puncturing metadata tags from PPOPRF server
//! secret keys, which in turn gives forward-security guarantees related
//! to the pseudorandomness of evaluations received by clients.
//!
//! This construction is primarily used in the STAR protocol for
//! providing secure randomness to clients.

extern crate rand;

extern crate rand_core;
use rand_core::RngCore;
use rand_core_ristretto::OsRng;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as RistrettoScalar;

use serde::{de, ser, Deserialize, Serialize};

use std::collections::BTreeMap;
use std::convert::TryInto;

use strobe_rng::StrobeRng;
use strobe_rs::{SecParam, Strobe};

use zeroize::{Zeroize, ZeroizeOnDrop};

pub use crate::PPRFError;
use crate::{ggm::GGM, PPRF};

use std::str;

pub const COMPRESSED_POINT_LEN: usize = 32;
pub const DIGEST_LEN: usize = 64;
pub const MAX_SERIALIZED_PK_SIZE: usize = 16384;
pub const MAX_SERIALIZED_PROOF_SIZE: usize = 64;

#[derive(Serialize, Deserialize)]
pub struct ProofDLEQ {
  c: RistrettoScalar,
  s: RistrettoScalar,
}
impl ProofDLEQ {
  fn new(
    key: &RistrettoScalar,
    public_value: &RistrettoPoint,
    p: &RistrettoPoint,
    q: &RistrettoPoint,
  ) -> Self {
    let mut csprng = OsRng;
    let t = RistrettoScalar::random(&mut csprng);

    let tg = t * RISTRETTO_BASEPOINT_POINT;
    let tp = t * p;
    let chl = ProofDLEQ::hash(&[
      &RISTRETTO_BASEPOINT_POINT,
      public_value,
      p,
      q,
      &tg,
      &tp,
    ]);
    let s = t - (chl * key);
    Self { c: chl, s }
  }

  fn new_batch(
    key: &RistrettoScalar,          //k
    public_value: &RistrettoPoint,  //Y -> B
    p: &[RistrettoPoint],           //C
    q: &[RistrettoPoint],           //D
  ) -> Self {
    //(M, Z) = ComputeCompositesFast(k, B, C, D)
    let (M, Z) = ProofDLEQ::computeComposites(
      Some(*key),
      public_value,
      p, 
      q,
    );
    //r = G.RandomScalar()
    let mut csprng = OsRng;
    let r = RistrettoScalar::random(&mut csprng);
    //t2 = r * A
    let t2 = r * RISTRETTO_BASEPOINT_POINT;
    //t3 = r * M
    let t3 = r * M;

    //Bm = G.SerializeElement(B)
    let bm_string = ProofDLEQ::serialize_element(*public_value);

    /*a0 = G.SerializeElement(M)
    a1 = G.SerializeElement(Z)
    a2 = G.SerializeElement(t2)
    a3 = G.SerializeElement(t3) */
    let a0_string = ProofDLEQ::serialize_element(M);
    let a1_string = ProofDLEQ::serialize_element(Z);
    let a2_string = ProofDLEQ::serialize_element(t2);
    let a3_string = ProofDLEQ::serialize_element(t3);

    /*challengeTranscript =
    I2OSP(len(Bm), 2) || Bm ||
    I2OSP(len(a0), 2) || a0 ||
    I2OSP(len(a1), 2) || a1 ||
    I2OSP(len(a2), 2) || a2 ||
    I2OSP(len(a3), 2) || a3 ||
    "Challenge"*/
    let challenge_transcript = format!("{}{}{}{}{}{}{}{}{}{}{}",
                                             bm_string.len(), 
                                             bm_string, 
                                             a0_string.len(),
                                             a0_string,
                                             a1_string.len(),
                                             a1_string,
                                             a2_string.len(),
                                             a2_string,
                                             a3_string.len(),
                                             a3_string,
                                             "Challenge"); 

  //c = G.HashToScalar(challengeTranscript)
  let mut out = [0u8; 64];
  // TODO label?
  strobe_hash(&challenge_transcript.as_bytes(), "Challenge", &mut out);
  let c = RistrettoScalar::from_bytes_mod_order_wide(&out);
  //s = r - c * k
  let s = r - c * key;

  //return [c, s]
  Self { c: c, s }
  }

  fn verify(
    &self,
    public_value: &RistrettoPoint,
    p: &RistrettoPoint,
    q: &RistrettoPoint,
  ) -> bool {
    let a = (self.s * RISTRETTO_BASEPOINT_POINT) + (self.c * public_value);
    let b = (self.s * p) + (self.c * q);
    let c_prime = ProofDLEQ::hash(&[
      &RISTRETTO_BASEPOINT_POINT,
      public_value,
      p,
      q,
      &a,
      &b,
    ]);
    c_prime == self.c
  }

  fn verifyBatch(
    &self, 
    public_value: &RistrettoPoint,
    p: &[RistrettoPoint],           //P
    q: &[RistrettoPoint],           //Q
  ) -> bool {
    //(M, Z) = ComputeComposites(B, C, D)
    let (M, Z) = ProofDLEQ::computeComposites(
      None,
      public_value, 
      p, 
      q,
    );

    //t2 = ((s * A) + (c * B))
    let t2 = (self.s * RISTRETTO_BASEPOINT_POINT) + (self.c * public_value);
    //t3 = ((s * M) + (c * Z))
    let t3 = (self.s * M) + (self.c * Z);

    //Bm = G.SerializeElement(B)
    let bm_string = ProofDLEQ::serialize_element(*public_value);

    /*a0 = G.SerializeElement(M)
    a1 = G.SerializeElement(Z)
    a2 = G.SerializeElement(t2)
    a3 = G.SerializeElement(t3) */
    let a0_string = ProofDLEQ::serialize_element(M);
    let a1_string = ProofDLEQ::serialize_element(Z);
    let a2_string = ProofDLEQ::serialize_element(t2);
    let a3_string = ProofDLEQ::serialize_element(t3);

    /*challengeTranscript =
      I2OSP(len(Bm), 2) || Bm ||
      I2OSP(len(a0), 2) || a0 ||
      I2OSP(len(a1), 2) || a1 ||
      I2OSP(len(a2), 2) || a2 ||
      I2OSP(len(a3), 2) || a3 ||
      "Challenge"*/
      let challenge_transcript = format!("{}{}{}{}{}{}{}{}{}{}{}",
                                               bm_string.len(), 
                                               bm_string, 
                                               a0_string.len(),
                                               a0_string,
                                               a1_string.len(),
                                               a1_string,
                                               a2_string.len(),
                                               a2_string,
                                               a3_string.len(),
                                               a3_string,
                                               "Challenge"); 

    //c = G.HashToScalar(challengeTranscript)
    let mut out = [0u8; 64];
    // TODO label?
    strobe_hash(&challenge_transcript.as_bytes(), "Challenge", &mut out);
    let expected_c = RistrettoScalar::from_bytes_mod_order_wide(&out);
  
    //verified = (expectedC == c)
    return expected_c == self.c
  }

  fn computeComposites(
    key: Option<RistrettoScalar>,
    b: &RistrettoPoint,
    c: &[RistrettoPoint],
    d: &[RistrettoPoint],
  ) -> (RistrettoPoint, RistrettoPoint){
    //Bm = G.SerializeElement(B)
    let bm_string = ProofDLEQ::serialize_element(*b);

    // We use the Partially-punctureable Oblivious Pseudo-Random Function
    let context_string = format!("{}{}{}{}", 
                                        "PPOPRFv1-", 
                                        0x03.to_string(), 
                                        "-", 
                                        "ristretto255-strobe");
    //seedDST = "Seed-" || contextString
    let seed_dst = format!("{}{}", "Seed-", context_string);

    // seedTranscript = I2OSP(len(Bm), 2) || Bm || I2OSP(len(seedDST), 2) || seedDST
    let seed_transcript = format!("{}{}{}{}", 
                                         bm_string.len(), 
                                         bm_string, 
                                         seed_dst.len(), 
                                         seed_dst);

    // TODO what is the correct label? what's the digest length?
    let mut seed = [0u8; 64];
    strobe_hash(&seed_transcript.as_bytes(), "Seed", &mut seed);

    //M = G.Identity()
    let mut M = RISTRETTO_BASEPOINT_POINT;
    //Z = G.Identity()
    let mut Z = RISTRETTO_BASEPOINT_POINT;

    let seed_string = match str::from_utf8(&seed) {
      Ok(v) => v,
      Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    // for i in range(m):
    for i in 0..5 {
      //Ci = G.SerializeElement(C[i])
      let ci_string = ProofDLEQ::serialize_element(c[i]);
      //Di = G.SerializeElement(D[i])
      let di_string = ProofDLEQ::serialize_element(d[i]);

      //compositeTranscript = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) || 
      //                      I2OSP(len(Ci), 2) || Ci || I2OSP(len(Di), 2) || Di || "Composite"
      let composite_transcript = format!("{}{}{}{}{}{}{}{}",
                                                seed.len().to_string(), 
                                                seed_string, 
                                                i.to_string(),
                                                ci_string.len(),
                                                ci_string,
                                                di_string.len(),
                                                di_string,
                                                "Composite"); 

      //di = G.HashToScalar(compositeTranscript)
      let mut out = [0u8; 64];
      // TODO label?
      strobe_hash(&composite_transcript.as_bytes(), "Composite", &mut out);
      let di = RistrettoScalar::from_bytes_mod_order_wide(&out);

      //M = di * C[i] + M
      M = di * c[i] + M;

      // If we know the key (server), we don't need to calculate Z here
      if key.is_none() {
        //Z = di * D[i] + Z
        Z = di * d[i] + Z;
      }
    }

    // If we know the key (server), we can calulate Z from key and M
    if let Some(k) = key { 
      Z = k * M;
    }
  
    // return (M, Z)
    (M, Z)
  }

  // H3
  fn hash(elements: &[&RistrettoPoint]) -> RistrettoScalar {
    if elements.len() != 6 {
      panic!("Incorrect number of points sent: {}", elements.len());
    }
    let mut input = Vec::with_capacity(elements.len() * COMPRESSED_POINT_LEN);
    for ele in elements {
      input.extend(ele.compress().to_bytes());
    }
    let mut out = [0u8; 64];
    strobe_hash(&input, "ppoprf_dleq_hash", &mut out);
    RistrettoScalar::from_bytes_mod_order_wide(&out)
  }

  fn serialize_element(element: RistrettoPoint) -> String {
    let byte_array = element.compress().to_bytes();
    let string = match str::from_utf8(&byte_array) {
      Ok(v) => v.to_string(),
      Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    return string;
  }

  pub fn serialize_to_bincode(&self) -> Result<Vec<u8>, PPRFError> {
    bincode::serialize(self).map_err(PPRFError::Bincode)
  }

  pub fn load_from_bincode(data: &[u8]) -> Result<Self, PPRFError> {
    if data.len() > MAX_SERIALIZED_PROOF_SIZE {
      return Err(PPRFError::SerializedDataTooBig);
    }
    bincode::deserialize(data).map_err(PPRFError::Bincode)
  }
}

// Server public key structure for PPOPRF, contains all elements of the
// form g^{sk_0},g^{t_i} for metadata tags t_i.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ServerPublicKey {
  base_pk: Point,
  md_pks: BTreeMap<u8, Point>,
}
impl ServerPublicKey {
  fn get(&self, md: u8) -> Option<&Point> {
    self.md_pks.get(&md)
  }

  fn get_combined_pk_value(&self, md: u8) -> Result<Point, PPRFError> {
    let res = self.get(md);
    let md_pk = res.ok_or(PPRFError::BadTag { md })?;
    let b = self.base_pk.decompress().unwrap();
    let md = md_pk.decompress().unwrap();
    Ok(Point::from(b + md))
  }

  pub fn serialize_to_bincode(&self) -> Result<Vec<u8>, PPRFError> {
    bincode::serialize(self).map_err(PPRFError::Bincode)
  }

  pub fn load_from_bincode(data: &[u8]) -> Result<Self, PPRFError> {
    if data.len() > MAX_SERIALIZED_PK_SIZE {
      return Err(PPRFError::SerializedDataTooBig);
    }
    bincode::deserialize(data).map_err(PPRFError::Bincode)
  }
}

// The wrapper for PPOPRF evaluations (similar to standard OPRFs)
#[derive(Deserialize, Serialize)]
pub struct Evaluation {
  #[serde(deserialize_with = "point_deserialize")]
  #[serde(serialize_with = "point_serialize")]
  pub output: Point,
  pub proof: Option<ProofDLEQ>,
}

// Public wrapper for points associated with the elliptic curve that
// is used
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Point(CompressedRistretto);
impl Point {
  fn decompress(&self) -> Option<RistrettoPoint> {
    self.0.decompress()
  }

  pub fn as_bytes(&self) -> &[u8; 32] {
    self.0.as_bytes()
  }
}
impl From<RistrettoPoint> for Point {
  fn from(rp: RistrettoPoint) -> Self {
    Self(rp.compress())
  }
}
impl From<&[u8]> for Point {
  fn from(bytes: &[u8]) -> Self {
    Self(CompressedRistretto::from_slice(bytes))
  }
}
impl From<Point> for RistrettoPoint {
  fn from(p: Point) -> RistrettoPoint {
    p.decompress().unwrap()
  }
}

// Public wrapper for scalar values associated with the elliptic curve
// that is used. Currently only supports ristretto. Will need to be
// rewritten to include generic types if we want to support more curves
pub struct CurveScalar(RistrettoScalar);
impl From<[u8; 32]> for CurveScalar {
  fn from(bytes: [u8; 32]) -> Self {
    CurveScalar(RistrettoScalar::from_bytes_mod_order(bytes))
  }
}
impl From<RistrettoScalar> for CurveScalar {
  fn from(rs: RistrettoScalar) -> Self {
    CurveScalar(rs)
  }
}
impl From<CurveScalar> for RistrettoScalar {
  fn from(cs: CurveScalar) -> RistrettoScalar {
    cs.0
  }
}

fn point_serialize<S>(p: &Point, s: S) -> Result<S::Ok, S::Error>
where
  S: ser::Serializer,
{
  s.serialize_str(&base64::encode(p.0 .0))
}

fn point_deserialize<'de, D>(d: D) -> Result<Point, D::Error>
where
  D: de::Deserializer<'de>,
{
  let s: &str = de::Deserialize::deserialize(d)?;
  let data = base64::decode(s).map_err(de::Error::custom)?;
  let fixed_data: [u8; 32] = data
    .try_into()
    .map_err(|_| de::Error::custom("Ristretto must be 32 bytes"))?;
  Ok(Point(CompressedRistretto(fixed_data)))
}

// The `Server` runs the server-side component of the PPOPRF protocol.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Server {
  oprf_key: RistrettoScalar,
  #[zeroize(skip)]
  public_key: ServerPublicKey,
  pprf: GGM,
}
impl Server {
  pub fn new(mds: Vec<u8>) -> Result<Self, PPRFError> {
    let mut csprng = OsRng;
    let oprf_key = RistrettoScalar::random(&mut csprng);
    let mut md_pks = BTreeMap::new();
    let pprf = GGM::setup();
    for &md in mds.iter() {
      let mut tag = [0u8; 32];
      pprf.eval(&[md], &mut tag)?;
      let ts = RistrettoScalar::from_bytes_mod_order(tag);
      md_pks.insert(md, Point::from(ts * RISTRETTO_BASEPOINT_POINT));
    }
    Ok(Self {
      oprf_key,
      public_key: ServerPublicKey {
        base_pk: Point::from(oprf_key * RISTRETTO_BASEPOINT_POINT),
        md_pks,
      },
      pprf,
    })
  }

  pub fn eval(
    &self,
    p: &Point,
    md: u8,
    verifiable: bool,
  ) -> Result<Evaluation, PPRFError> {
    let p = p.0;
    let point = p.decompress().unwrap();
    if self.public_key.get(md).is_none() {
      return Err(PPRFError::BadTag { md });
    }
    let mut tag = [0u8; 32];
    self.pprf.eval(&[md], &mut tag)?;
    let ts = RistrettoScalar::from_bytes_mod_order(tag);
    let tagged_key = self.oprf_key + ts;
    let exponent = tagged_key.invert();
    let eval_point = exponent * point;
    let mut proof = None;
    if verifiable {
      let public_value = self.public_key.get_combined_pk_value(md)?;
      proof = Some(ProofDLEQ::new(
        &tagged_key,
        &public_value.into(),
        &eval_point,
        &point,
      ));
    }
    Ok(Evaluation {
      output: Point(eval_point.compress()),
      proof,
    })
  }

  pub fn puncture(&mut self, md: u8) -> Result<(), PPRFError> {
    self.pprf.puncture(&[md])
  }

  pub fn get_public_key(&self) -> ServerPublicKey {
    self.public_key.clone()
  }
}

// The `Client` struct is essentially a collection of static functions
// for computing client-side operations in the PPOPRF protocol.
pub struct Client {}
impl Client {
  pub fn blind(input: &[u8]) -> (Point, CurveScalar) {
    let mut hashed_input = [0u8; 64];
    strobe_hash(input, "ppoprf_derive_client_input", &mut hashed_input);
    let point = RistrettoPoint::from_uniform_bytes(&hashed_input);
    let mut csprng = OsRng;
    let r = RistrettoScalar::random(&mut csprng);
    (Point((r * point).compress()), CurveScalar::from(r))
  }

  pub fn verify(
    public_key: &ServerPublicKey,
    input: &Point,
    eval: &Evaluation,
    md: u8,
  ) -> bool {
    let Evaluation { output, proof } = eval;
    if let Ok(public_value) = public_key.get_combined_pk_value(md) {
      return proof.as_ref().unwrap().verify(
        &public_value.into(),
        &output.decompress().unwrap(),
        &input.decompress().unwrap(),
      );
    }
    false
  }

  pub fn unblind(p: &Point, r: &CurveScalar) -> Point {
    let point = p.decompress().unwrap();
    let r_inv = r.0.invert();
    Point((r_inv * point).compress())
  }

  pub fn finalize(input: &[u8], md: u8, unblinded: &Point, out: &mut [u8]) {
    if out.len() != 32 {
      panic!("Wrong output length!!: {:?}", out.len());
    }
    let point_bytes = unblinded.as_bytes();
    let mut hash_input =
      Vec::with_capacity(input.len() + 1 + point_bytes.len());
    hash_input.extend(input);
    hash_input.push(md);
    hash_input.extend(point_bytes);
    let mut untruncated = vec![0u8; 64];
    strobe_hash(&hash_input, "ppoprf_finalize", &mut untruncated);
    out.copy_from_slice(&untruncated[..32]);
  }
}

fn strobe_hash(input: &[u8], label: &str, out: &mut [u8]) {
  if out.len() != DIGEST_LEN {
    panic!(
      "Output buffer length ({}) does not match intended output length ({})",
      out.len(),
      DIGEST_LEN
    );
  }
  let mut t = Strobe::new(label.as_bytes(), SecParam::B128);
  t.key(input, false);
  let mut rng: StrobeRng = t.into();
  rng.fill_bytes(out);
}

#[cfg(test)]
mod tests {
  use super::*;

  use insta::assert_snapshot;

  fn end_to_end_eval_check_no_proof(
    server: &Server,
    c_input: &[u8],
    md: u8,
  ) -> (Point, Point) {
    let (blinded_point, r) = Client::blind(c_input);
    let evaluated = server.eval(&blinded_point, md, false).unwrap();
    let unblinded = Client::unblind(&evaluated.output, &r);

    let mut chk_inp = [0u8; 64];
    strobe_hash(c_input, "ppoprf_derive_client_input", &mut chk_inp);
    let p = Point(RistrettoPoint::from_uniform_bytes(&chk_inp).compress());
    let chk_eval = server.eval(&p, md, false).unwrap();
    (unblinded, chk_eval.output)
  }

  fn end_to_end_eval_check(
    server: &Server,
    c_input: &[u8],
    md: u8,
  ) -> (Point, Point) {
    let (blinded_point, r) = Client::blind(c_input);
    let evaluated = server.eval(&blinded_point, md, true).unwrap();
    if !Client::verify(&server.public_key, &blinded_point, &evaluated, md) {
      panic!("Failed to verify proof");
    }
    let unblinded = Client::unblind(&evaluated.output, &r);

    let mut chk_inp = [0u8; 64];
    strobe_hash(c_input, "ppoprf_derive_client_input", &mut chk_inp);
    let p = Point(RistrettoPoint::from_uniform_bytes(&chk_inp).compress());
    let chk_eval = server.eval(&p, md, false).unwrap();
    (unblinded, chk_eval.output)
  }

  fn end_to_end_no_verify(mds: &[u8], md: u8) {
    let server = Server::new(mds.to_vec()).unwrap();
    let input = b"some_test_input";
    let (unblinded, chk_eval) =
      end_to_end_eval_check_no_proof(&server, input, md);
    assert_eq!(chk_eval, unblinded);
    let mut eval_final = vec![0u8; 32];
    Client::finalize(input, md, &unblinded, &mut eval_final);
    let mut chk_final = vec![0u8; 32];
    Client::finalize(input, md, &chk_eval, &mut chk_final);
    assert_eq!(chk_final, eval_final);
  }

  fn end_to_end_verify(mds: &[u8], md: u8) {
    let server = Server::new(mds.to_vec()).unwrap();
    let input = b"some_test_input";
    let (unblinded, chk_eval) = end_to_end_eval_check(&server, input, md);
    assert_eq!(chk_eval, unblinded);
    let mut eval_final = vec![0u8; 32];
    Client::finalize(input, md, &unblinded, &mut eval_final);
    let mut chk_final = vec![0u8; 32];
    Client::finalize(input, md, &chk_eval, &mut chk_final);
    assert_eq!(chk_final, eval_final);
  }

  #[test]
  fn end_to_end_no_verify_single_tag() {
    end_to_end_no_verify(&[0u8], 0);
  }

  #[test]
  fn end_to_end_verify_single_tag() {
    end_to_end_verify(&[0u8], 0);
  }

  #[test]
  #[should_panic]
  fn bad_index() {
    end_to_end_verify(&[0u8], 1);
  }

  #[test]
  fn end_to_end_no_verify_multi_tag() {
    let mds = vec![0u8, 1, 2, 3, 4];
    end_to_end_no_verify(&mds, 0);
    end_to_end_no_verify(&mds, 1);
    end_to_end_no_verify(&mds, 2);
    end_to_end_no_verify(&mds, 3);
    end_to_end_no_verify(&mds, 4);
  }

  #[test]
  fn end_to_end_verify_multi_tag() {
    let mds = vec![0u8, 1, 2, 3, 4];
    end_to_end_verify(&mds, 0);
    end_to_end_verify(&mds, 1);
    end_to_end_verify(&mds, 2);
    end_to_end_verify(&mds, 3);
    end_to_end_verify(&mds, 4);
  }

  #[test]
  #[should_panic(expected = "NoPrefixFound")]
  fn end_to_end_puncture() {
    let mds = vec![0u8, 1];
    let mut server = Server::new(mds).unwrap();
    let (unblinded, chk_eval) =
      end_to_end_eval_check_no_proof(&server, b"some_test_input", 1);
    assert_eq!(chk_eval, unblinded);
    server.puncture(1).unwrap();
    let (unblinded1, chk_eval1) =
      end_to_end_eval_check_no_proof(&server, b"another_input", 0);
    assert_eq!(chk_eval1, unblinded1);
    end_to_end_eval_check_no_proof(&server, b"some_test_input", 1);
  }

  #[test]
  fn pk_serialization() {
    let oprf_key = RistrettoScalar::from_bytes_mod_order([7u8; 32]);
    let mut md_pks = BTreeMap::new();

    for i in 0..8u8 {
      let ts = RistrettoScalar::from_bytes_mod_order([i * 2; 32]);
      md_pks.insert(i, Point::from(ts * RISTRETTO_BASEPOINT_POINT));
    }

    let pk = ServerPublicKey {
      base_pk: Point::from(oprf_key * RISTRETTO_BASEPOINT_POINT),
      md_pks,
    };

    let pk_bincode = pk
      .serialize_to_bincode()
      .expect("Should serialize to bincode");

    assert_snapshot!(base64::encode(&pk_bincode));

    ServerPublicKey::load_from_bincode(&pk_bincode)
      .expect("Should load bincode");
  }

  #[test]
  fn pk_bad_data_load() {
    assert!(ServerPublicKey::load_from_bincode(&[8u8; 40]).is_err());
    assert!(
      ProofDLEQ::load_from_bincode(&[98u8; MAX_SERIALIZED_PK_SIZE + 1])
        .is_err()
    );
    assert!(ServerPublicKey::load_from_bincode(&[98u8; 10000]).is_err());
  }

  #[test]
  fn proof_serialization() {
    let proof = ProofDLEQ {
      c: RistrettoScalar::from_bytes_mod_order([7u8; 32]),
      s: RistrettoScalar::from_bytes_mod_order([15u8; 32]),
    };

    let proof_bincode = proof
      .serialize_to_bincode()
      .expect("Should serialize to bincode");

    assert_snapshot!(base64::encode(&proof_bincode));

    ProofDLEQ::load_from_bincode(&proof_bincode).expect("Should load bincode");
  }

  #[test]
  fn proof_bad_data_load() {
    assert!(ProofDLEQ::load_from_bincode(&[8u8; 40]).is_err());
    assert!(ProofDLEQ::load_from_bincode(
      &[98u8; MAX_SERIALIZED_PROOF_SIZE + 1]
    )
    .is_err());
    assert!(ProofDLEQ::load_from_bincode(&[98u8; 10000]).is_err());
  }
}
