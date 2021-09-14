//! This module provides the implementation of the STAR (distributed
//! Secret-sharing for Threshold AggRegation of data) protocol. The
//! STAR protocol provides the ability for clients to report secret
//! measurements to servers, whilst maintaining k-anonymity-like
//! guarantees.
//!
//! In essence, such measurements are only revealed if a `threshold`
//! number of clients all send the same message. Clients are permitted
//! to also send relevant, arbitrary associated data that can also be
//! revealed.
//!
//! The STAR protocol is made up of two variants, STAR1 and STAR2. In
//! STAR1, clients derive randomness used for hiding their measurements
//! locally from the measurement itself. In STAR2, clients derive
//! randomness from a separate server that implements a puncturable
//! partially oblivious pseudorandom function (PPOPRF) protocol. The
//! PPOPRF protocol takes in the client measurement, a server secret
//! key, and the current epoch metadata tag as input, and outputs a
//! random (deterministic) value.
//!
//! In the case of STAR1, the design is simpler than in STAR2, but
//! security is only maintained in the case where client measurements
//! are sampled from a high-entropy domain. In the case of STAR2, client
//! security guarantees hold even for low-entropy inputs, as long as the
//! randomness is only revealed after the epoch metadata tag has been
//! punctured from the randomness server's secret key.

use std::error::Error;
use std::str;

extern crate ring;
use ring::aead;
use ring::digest::{self, Context, SHA256};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};

use adss_rs::{recover, store_bytes, Commune};
use ppoprf::ppoprf::{end_to_end_evaluation, Server as PPOPRFServer};
pub use {adss_rs::load_bytes, adss_rs::Share};

pub const AES_BLOCK_LEN: usize = 24;
// FIXME
pub const MEASUREMENT_MAX_LEN: usize = 32;
pub const DEBUG: bool = false;

// A `Measurement` provides the wrapper for a client-generated value in
// the STAR protocol that is later aggregated and processed at the
// server-side. Measurements are only revealed on the server-side if the
// `threshold` is met, in terms of clients that send the same
// `Measurement` value.
//
// Such data is essentially arbitrary subject to the maximum length
// requirement specified by `MEASUREMENT_MAX_LEN`
#[derive(Debug)]
pub struct Measurement(Vec<u8>);
impl Measurement {
    pub fn new(x: &[u8]) -> Self {
        let m = x.to_vec();
        if m.len() > MEASUREMENT_MAX_LEN {
            panic!("Length of string ({:?}) is too long", m.len());
        }
        Self(m)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn as_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for Measurement {
    fn from(s: &str) -> Self {
        Measurement::new(s.as_bytes())
    }
}

// The `AssociatedData` struct wraps the arbitrary data that a client
// can encode in its message to the `Server`. Such data is also only
// revealed in the case that the `threshold` is met.
#[derive(Debug)]
pub struct AssociatedData(Vec<u8>);
impl AssociatedData {
    pub fn new(buf: &[u8]) -> Self {
        Self(buf.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn as_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}
impl From<&str> for AssociatedData {
    fn from(s: &str) -> Self {
        AssociatedData::from(s.as_bytes())
    }
}
impl From<&[u8]> for AssociatedData {
    fn from(buf: &[u8]) -> Self {
        AssociatedData::new(buf)
    }
}

// The `Ciphertext` struct holds the symmetrically encrypted data that
// corresponds to the concatenation of `Measurement` and any optional
// `AssociatedData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    bytes: Vec<u8>,
    nonce: [u8; 12],
    aad: Option<Vec<u8>>,
}
impl Ciphertext {
    fn new(enc_key_buf: &[u8], data: &[u8]) -> Self {
        let mut nonce_buf = [0; 12];
        let prng = SystemRandom::new();
        prng.fill(&mut nonce_buf).unwrap();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_buf);

        let mut in_out = data.to_vec();
        in_out.extend(vec![0u8; aead::AES_128_GCM.tag_len()]);

        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, enc_key_buf).unwrap();
        let ls_key = aead::LessSafeKey::new(unbound);
        ls_key
            .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
            .unwrap();

        Self {
            bytes: in_out,
            nonce: nonce_buf,
            aad: None,
        }
    }

    pub fn decrypt(&self, enc_key_buf: &[u8]) -> Vec<u8> {
        let ls_key =
            aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, enc_key_buf).unwrap());
        let mut in_out = self.bytes.clone();
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce);
        ls_key
            .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
            .unwrap();
        in_out[..in_out.len() - aead::AES_128_GCM.tag_len()].to_vec() // plaintext
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();

        // bytes: Vec<u8>
        store_bytes(&self.bytes, &mut out);

        // aad: Option<Vec<u8>>
        store_bytes(if let Some(aad) = &self.aad { aad } else { &[] }, &mut out);

        // nonce: [u8; 12]
        out.extend(&self.nonce);

        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Ciphertext> {
        let mut slice = bytes;

        // bytes: Vec<u8>
        let bytes = load_bytes(slice)?;
        slice = &slice[4 + bytes.len() as usize..];

        // aad: Option<Vec<u8>>
        let aad = load_bytes(slice)?;
        slice = &slice[4 + aad.len() as usize..];

        // nonce: [u8; 12]
        let mut nonce: [u8; 12] = [0u8; 12];
        nonce.copy_from_slice(slice);

        Some(Ciphertext {
            bytes: bytes.to_vec(),
            nonce,
            aad: if aad.is_empty() {
                None
            } else {
                Some(aad.to_vec())
            },
        })
    }
}

// A `Triple` is the message that a client sends to the server during
// the STAR protocol. Consisting of a `Ciphertext`, a `Share`, and a
// `tag`. The `Ciphertext`can only be decrypted if a `threshold` number
// of clients possess the same measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Triple {
    pub ciphertext: Ciphertext,
    pub share: Share,
    pub tag: Vec<u8>,
}

impl Triple {
    fn new(c: Ciphertext, share: Share, tag: &[u8]) -> Self {
        Self {
            ciphertext: c,
            share,
            tag: tag.to_vec(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();

        // ciphertext: Ciphertext
        store_bytes(&self.ciphertext.to_bytes(), &mut out);

        // share: Share
        store_bytes(&self.share.to_bytes(), &mut out);

        // tag: Vec<u8>
        store_bytes(&self.tag, &mut out);

        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Triple> {
        let mut slice = bytes;

        // ciphertext: Ciphertext
        let cb = load_bytes(slice)?;
        let ciphertext = Ciphertext::from_bytes(cb)?;
        slice = &slice[4 + cb.len() as usize..];

        // share: Share
        let sb = load_bytes(slice)?;
        let share = Share::from_bytes(sb)?;
        slice = &slice[4 + sb.len() as usize..];

        // tag: Vec<u8>
        let tag = load_bytes(slice)?;

        Some(Triple {
            ciphertext,
            share,
            tag: tag.to_vec(),
        })
    }
}

// In the STAR protocol, the `Client` is the entity which samples and
// sends `Measurement` to the `AggregationServer`. The measurements will
// only be revealed if a `threshold` number of clients send the same
// encoded `Measurement` value.
//
// Note that the `Client` struct holds all of the public protocol
// parameters, the secret `Measurement` and `AssociatedData` objects,
// and where randomness should be sampled from.
//
// In the STAR1 protocol, the `Client` samples randomness locally: derived
// straight from the `Measurement` itself. In the STAR2 protocol, the
// `Client` derives its randomness from an exchange with a
// specifically-defined server that runs a POPRF.
pub struct Client {
    x: Measurement,
    threshold: u32,
    epoch: String,
    use_local_rand: bool,
    aux: Option<AssociatedData>,
}
impl Client {
    pub fn new(
        x: &[u8],
        threshold: u32,
        epoch: &str,
        use_local_rand: bool,
        aux: Option<Vec<u8>>,
    ) -> Self {
        let x = Measurement::new(x);
        Self {
            x,
            threshold,
            epoch: epoch.to_string(),
            use_local_rand,
            aux: aux.and_then(|x| Some(AssociatedData::new(&x))),
        }
    }

    // Generates a triple that is used in the aggregation phase
    pub fn generate_triple(&self, oprf_server: Option<&PPOPRFServer>) -> Triple {
        let mut rnd = vec![0u8; 32];
        if self.use_local_rand {
            self.sample_local_randomness(&mut rnd);
        } else {
            if oprf_server.is_none() {
                panic!("No OPRF server specified");
            }
            self.sample_oprf_randomness(oprf_server.unwrap(), &mut rnd);
        }
        let r = self.derive_random_values(&rnd);

        let ciphertext = self.derive_ciphertext(&r[0]);
        let share = self.share(&r[0], &r[1]);
        let tag = &r[2];
        Triple::new(ciphertext, share, tag)
    }

    pub fn derive_random_values(&self, randomness: &[u8]) -> Vec<Vec<u8>> {
        let mut output = Vec::new();
        for i in 0..3 {
            let mut hash = Context::new(&SHA256);
            hash.update(randomness);
            hash.update(&[i as u8]);
            output.push(hash.finish().as_ref().to_vec());
        }
        output
    }

    pub fn derive_key(&self, r1: &[u8]) -> Vec<u8> {
        let mut enc_key = vec![0u8; 16];
        derive_ske_key(r1, self.epoch.as_bytes(), &mut enc_key);
        enc_key
    }

    fn derive_ciphertext(&self, r1: &[u8]) -> Ciphertext {
        let enc_key = self.derive_key(r1);

        let mut data: Vec<u8> = Vec::new();
        store_bytes(&self.x.0, &mut data);
        if let Some(aux) = &self.aux {
            store_bytes(&aux.0, &mut data);
        }
        Ciphertext::new(&enc_key, &data)
    }

    pub fn share(&self, r1: &[u8], r2: &[u8]) -> Share {
        let c = Commune::new(self.threshold, r1.to_vec(), r2.to_vec(), None);
        c.share()
    }

    pub fn sample_local_randomness(&self, out: &mut [u8]) {
        if out.len() != digest::SHA256_OUTPUT_LEN {
            panic!(
                "Output buffer length ({}) does not match randomness length ({})",
                out.len(),
                digest::SHA256_OUTPUT_LEN
            );
        }
        let mut hash = Context::new(&digest::SHA256);
        hash.update(self.x.as_slice());
        hash.update(self.epoch.as_bytes());
        hash.update(&self.threshold.to_le_bytes());
        let digest = hash.finish();
        out.copy_from_slice(digest.as_ref());
    }

    pub fn sample_oprf_randomness(&self, oprf_server: &PPOPRFServer, out: &mut [u8]) {
        end_to_end_evaluation(oprf_server, self.x.as_slice(), self.epoch.as_bytes(), out);
    }
}

// FIXME can we implement collect trait?
pub fn share_recover(shares: &[Share]) -> Result<Commune, Box<dyn Error>> {
    recover(shares)
}

// The `derive_ske_key` helper function derives symmetric encryption
// keys that are used for encrypting/decrypting `Ciphertext` objects
// during the STAR protocol.
pub fn derive_ske_key(r1: &[u8], epoch: &[u8], key_out: &mut [u8]) {
    if key_out.len() != digest::SHA256_OUTPUT_LEN / 2 {
        panic!(
            "Output buffer length ({}) does not match randomness length ({})",
            key_out.len(),
            digest::SHA256_OUTPUT_LEN / 2
        );
    }
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, epoch);
    let prk = salt.extract(r1);
    let expand_info = &["star_threshold_agg".as_bytes()];
    let okm = prk.expand(expand_info, hkdf::HKDF_SHA256).unwrap();
    let mut to_fill = vec![0u8; 32];
    okm.fill(&mut to_fill).unwrap();
    key_out.copy_from_slice(&to_fill[..16]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_ciphertext() {
        let client = Client::new(b"foobar", 0, "epoch", true, None);
        let triple = client.generate_triple(None);
        let bytes = triple.ciphertext.to_bytes();
        assert_eq!(Ciphertext::from_bytes(&bytes), Some(triple.ciphertext));
    }

    #[test]
    fn serialize_triple() {
        let client = Client::new(b"foobar", 0, "epoch", true, None);
        let triple = client.generate_triple(None);
        let bytes = triple.to_bytes();
        assert_eq!(Triple::from_bytes(&bytes), Some(triple));
    }

    #[test]
    fn roundtrip() {
        let client = Client::new(b"foobar", 1, "epoch", true, None);
        let triple = client.generate_triple(None);

        let commune = share_recover(&vec![triple.share]).unwrap();
        let message = commune.get_message();

        let mut enc_key_buf = vec![0u8; 16];
        derive_ske_key(&message, "epoch".as_bytes(), &mut enc_key_buf);
        let plaintext = triple.ciphertext.decrypt(&enc_key_buf);

        let mut slice = &plaintext[..];

        let measurement_bytes = load_bytes(&slice).unwrap();
        slice = &slice[4 + measurement_bytes.len() as usize..];

        if slice.len() > 0 {
            let aux_bytes = load_bytes(&slice).unwrap();
            assert_eq!(aux_bytes.len(), 0);
        }

        assert_eq!(measurement_bytes, b"foobar");
    }
}
