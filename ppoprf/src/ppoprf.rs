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
use curve25519_dalek::scalar::Scalar;

use strobe_rng::StrobeRng;
use strobe_rs::{SecParam, Strobe};

use crate::{ggm::GGM, PPRF};

pub const COMPRESSED_POINT_LEN: usize = 32;
pub const DIGEST_LEN: usize = 64;

pub struct ProofDLEQ {
    c: Scalar,
    s: Scalar,
}
impl ProofDLEQ {
    pub fn new(
        key: &Scalar,
        public_value: &RistrettoPoint,
        p: &RistrettoPoint,
        q: &RistrettoPoint,
    ) -> Self {
        let mut csprng = OsRng;
        let t = Scalar::random(&mut csprng);

        let tg = t * RISTRETTO_BASEPOINT_POINT;
        let tp = t * p;
        let chl = ProofDLEQ::hash(&[&RISTRETTO_BASEPOINT_POINT, public_value, p, q, &tg, &tp]);
        let s = t - (chl * key);
        Self { c: chl, s }
    }

    pub fn verify(
        &self,
        public_value: &RistrettoPoint,
        p: &RistrettoPoint,
        q: &RistrettoPoint,
    ) -> bool {
        let a = (self.s * RISTRETTO_BASEPOINT_POINT) + (self.c * public_value);
        let b = (self.s * p) + (self.c * q);
        let c_prime = ProofDLEQ::hash(&[&RISTRETTO_BASEPOINT_POINT, public_value, p, q, &a, &b]);
        c_prime == self.c
    }

    fn hash(elements: &[&RistrettoPoint]) -> Scalar {
        if elements.len() != 6 {
            panic!("Incorrect number of points sent: {}", elements.len());
        }
        let mut input = Vec::with_capacity(elements.len() * COMPRESSED_POINT_LEN);
        for ele in elements {
            input.extend(ele.compress().to_bytes());
        }
        let mut out = [0u8; 64];
        strobe_hash(&input, "ppoprf_dleq_hash", &mut out);
        Scalar::from_bytes_mod_order_wide(&out)
    }
}

// Server public key structure for PPOPRF, contains all elements of the
// form g^{sk_0},g^{t_i} for metadata tags t_i.
pub type ServerPublicKey = Vec<RistrettoPoint>;

// The wrapper for PPOPRF evaluations (similar to standard OPRFs)
pub struct Evaluation {
    output: CompressedRistretto,
    proof: Option<ProofDLEQ>,
}

// The `Server` runs the server-side component of the PPOPRF protocol.
#[derive(Clone)]
pub struct Server {
    oprf_key: Scalar,
    public_key: ServerPublicKey,
    mds: Vec<Vec<u8>>,
    pprf: GGM,
}
impl Server {
    pub fn new(mds: &[Vec<u8>]) -> Self {
        let mut csprng = OsRng;
        let oprf_key = Scalar::random(&mut csprng);
        let mut public_key = Vec::with_capacity(mds.len() + 1);
        public_key.push(oprf_key * RISTRETTO_BASEPOINT_POINT);
        let pprf = GGM::setup();
        for md in mds {
            let mut tag = [0u8; 32];
            pprf.eval(md, &mut tag);
            let ts = Scalar::from_bytes_mod_order(tag);
            public_key.push(ts * RISTRETTO_BASEPOINT_POINT);
        }
        Self {
            oprf_key,
            public_key,
            mds: mds.to_vec(),
            pprf,
        }
    }

    pub fn eval(&self, p: &CompressedRistretto, md_idx: usize, verifiable: bool) -> Evaluation {
        let point = p.decompress().unwrap();
        if md_idx >= self.mds.len() {
            panic!("Specified tag index is out of bounds for stored tags, indicated index {} is not in [0..{})", md_idx, self.mds.len());
        }
        let mut tag = [0u8; 32];
        self.pprf.eval(&self.mds[md_idx], &mut tag);
        let ts = Scalar::from_bytes_mod_order(tag);
        let tagged_key = self.oprf_key + ts;
        let exponent = tagged_key.invert();
        let eval_point = exponent * point;
        let mut proof = None;
        if verifiable {
            let public_value = self.public_key[0] + self.public_key[md_idx + 1];
            proof = Some(ProofDLEQ::new(
                &tagged_key,
                &public_value,
                &eval_point,
                &point,
            ));
        }
        Evaluation {
            output: eval_point.compress(),
            proof,
        }
    }

    pub fn puncture(&mut self, md: &[u8]) {
        self.pprf.puncture(md);
    }

    pub fn get_public_key(&self) -> ServerPublicKey {
        self.public_key.clone()
    }

    pub fn get_valid_metadata_tags(&self) -> Vec<Vec<u8>> {
        self.mds.clone()
    }
}

// The `Client` struct is essentially a collection of static functions
// for computing client-side operations in the PPOPRF protocol.
pub struct Client {}
impl Client {
    pub fn blind(input: &[u8]) -> (CompressedRistretto, Scalar) {
        let mut hashed_input = [0u8; 64];
        strobe_hash(input, "ppoprf_derive_client_input", &mut hashed_input);
        let point = RistrettoPoint::from_uniform_bytes(&hashed_input);
        let mut csprng = OsRng;
        let r = Scalar::random(&mut csprng);
        ((r * point).compress(), r)
    }

    pub fn verify(
        public_key: &[RistrettoPoint],
        input: &RistrettoPoint,
        eval: &Evaluation,
        md_idx: usize,
    ) -> bool {
        let Evaluation { output, proof } = eval;
        let public_value = public_key[0] + public_key[md_idx + 1];
        proof
            .as_ref()
            .unwrap()
            .verify(&public_value, &output.decompress().unwrap(), input)
    }

    pub fn unblind(p: &CompressedRistretto, r: &Scalar) -> CompressedRistretto {
        let point = p.decompress().unwrap();
        let r_inv = r.invert();
        (r_inv * point).compress()
    }

    pub fn finalize(input: &[u8], md: &[u8], unblinded: &CompressedRistretto, out: &mut [u8]) {
        if out.len() != 32 {
            panic!("Wrong output length!!: {:?}", out.len());
        }
        let point_bytes = unblinded.to_bytes();
        let mut hash_input = Vec::with_capacity(input.len() + md.len() + point_bytes.len());
        hash_input.extend(input);
        hash_input.extend(md);
        hash_input.extend(&point_bytes);
        let mut untruncated = vec![0u8; 64];
        strobe_hash(&hash_input, "ppoprf_finalize", &mut untruncated);
        out.copy_from_slice(&untruncated[..32]);
    }
}

// The `ènd_to_end_evaluation` helper function for performs a full
// protocol evaluation for a given `Server`.
pub fn end_to_end_evaluation(
    server: &Server,
    input: &[u8],
    md_idx: usize,
    verify: bool,
    out: &mut [u8],
) {
    let (blinded_point, r) = Client::blind(input);
    let evaluated = server.eval(&blinded_point, md_idx, verify);
    if verify
        && !Client::verify(
            &server.public_key,
            &blinded_point.decompress().unwrap(),
            &evaluated,
            md_idx,
        )
    {
        panic!("Verification failed")
    }
    let unblinded = Client::unblind(&evaluated.output, &r);
    Client::finalize(input, &server.mds[md_idx], &unblinded, out);
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

    fn end_to_end_eval_check_no_proof(
        server: &Server,
        c_input: &[u8],
        md_idx: usize,
    ) -> (CompressedRistretto, CompressedRistretto) {
        let (blinded_point, r) = Client::blind(&c_input);
        let evaluated = server.eval(&blinded_point, md_idx, false);
        let unblinded = Client::unblind(&evaluated.output, &r);

        let mut chk_inp = [0u8; 64];
        strobe_hash(c_input, "ppoprf_derive_client_input", &mut chk_inp);
        let chk_eval = server.eval(
            &RistrettoPoint::from_uniform_bytes(&chk_inp).compress(),
            md_idx,
            false,
        );
        (unblinded, chk_eval.output)
    }

    fn end_to_end_eval_check(
        server: &Server,
        c_input: &[u8],
        md_idx: usize,
    ) -> (CompressedRistretto, CompressedRistretto) {
        let (blinded_point, r) = Client::blind(c_input);
        let evaluated = server.eval(&blinded_point, md_idx, true);
        if !Client::verify(
            &server.public_key,
            &blinded_point.decompress().unwrap(),
            &evaluated,
            md_idx,
        ) {
            panic!("Failed to verify proof");
        }
        let unblinded = Client::unblind(&evaluated.output, &r);

        let mut chk_inp = [0u8; 64];
        strobe_hash(c_input, "ppoprf_derive_client_input", &mut chk_inp);
        let chk_eval = server.eval(
            &RistrettoPoint::from_uniform_bytes(&chk_inp).compress(),
            md_idx,
            false,
        );
        (unblinded, chk_eval.output)
    }

    fn end_to_end_no_verify(mds: &[Vec<u8>], md_idx: usize) {
        let server = Server::new(mds);
        let input = b"some_test_input";
        let (unblinded, chk_eval) = end_to_end_eval_check_no_proof(&server, input, md_idx);
        assert_eq!(chk_eval, unblinded);
        let mut eval_final = vec![0u8; 32];
        Client::finalize(input, &mds[md_idx], &unblinded, &mut eval_final);
        let mut chk_final = vec![0u8; 32];
        Client::finalize(input, &mds[md_idx], &chk_eval, &mut chk_final);
        assert_eq!(chk_final, eval_final);
    }

    fn end_to_end_verify(mds: &[Vec<u8>], md_idx: usize) {
        let server = Server::new(mds);
        let input = b"some_test_input";
        let (unblinded, chk_eval) = end_to_end_eval_check(&server, input, md_idx);
        assert_eq!(chk_eval, unblinded);
        let mut eval_final = vec![0u8; 32];
        Client::finalize(input, &mds[md_idx], &unblinded, &mut eval_final);
        let mut chk_final = vec![0u8; 32];
        Client::finalize(input, &mds[md_idx], &chk_eval, &mut chk_final);
        assert_eq!(chk_final, eval_final);
    }

    #[test]
    fn end_to_end_no_verify_single_tag() {
        let mds = vec![b"t".to_vec()];
        end_to_end_no_verify(&mds, 0);
    }

    #[test]
    fn end_to_end_verify_single_tag() {
        let mds = vec![b"t".to_vec()];
        end_to_end_verify(&mds, 0);
    }

    #[test]
    #[should_panic]
    fn bad_index() {
        let mds = vec![b"t".to_vec()];
        end_to_end_verify(&mds, 1);
    }

    #[test]
    fn end_to_end_no_verify_multi_tag() {
        let epochs = vec!["a", "e", "i", "o", "u"];
        let mds: Vec<Vec<u8>> = epochs.iter().map(|t| t.as_bytes().to_vec()).collect();
        end_to_end_no_verify(&mds, 0);
        end_to_end_no_verify(&mds, 1);
        end_to_end_no_verify(&mds, 2);
        end_to_end_no_verify(&mds, 3);
        end_to_end_no_verify(&mds, 4);
    }

    #[test]
    fn end_to_end_verify_multi_tag() {
        let epochs = vec!["a", "e", "i", "o", "u"];
        let mds: Vec<Vec<u8>> = epochs.iter().map(|t| t.as_bytes().to_vec()).collect();
        end_to_end_verify(&mds, 0);
        end_to_end_verify(&mds, 1);
        end_to_end_verify(&mds, 2);
        end_to_end_verify(&mds, 3);
        end_to_end_verify(&mds, 4);
    }

    #[test]
    #[should_panic(expected = "NoPrefixFound")]
    fn end_to_end_puncture() {
        let mds = vec![b"a".to_vec(), b"t".to_vec()];
        let mut server = Server::new(&mds);
        let (unblinded, chk_eval) = end_to_end_eval_check_no_proof(&server, b"some_test_input", 1);
        assert_eq!(chk_eval, unblinded);
        server.puncture(b"t");
        let (unblinded1, chk_eval1) = end_to_end_eval_check_no_proof(&server, b"another_input", 0);
        assert_eq!(chk_eval1, unblinded1);
        end_to_end_eval_check_no_proof(&server, b"some_test_input", 1);
    }
}
