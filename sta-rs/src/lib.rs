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
//! 
//! # Example (client)
//! 
//! The following example shows how to generate a triple of 
//! `(key, share, tag)` for each client in the STAR1 protocol. The STAR2
//! protocol is not yet supported. Note
//! that `key` MUST then used to encrypt the measurement and associated
//! data into a `ciphertext`. The triple `(ciphertext, share, tag)` is
//! then sent to the server.
//! 
//! ```
//! # use sta_rs::*;
//! # let threshold = 2;
//! # let epoch = "t";
//! # let measurement = "hello world".as_bytes();
//! let client = Client::new(measurement, threshold, epoch, None);
//! let ClientSharingMaterial {
//!   key: key,
//!   share: share,
//!   tag: tag,
//! } = client.share_with_local_randomness();
//! ```
//! 
//! # Example (server)
//! 
//! Once over `threshold` shares are recovered from clients, it is
//! possible to recover the randomness encoded in each of the shares
//! 
//! ```
//! # use sta_rs::*;
//! # use sta_rs_test_utils::*;
//! # let mut clients = Vec::new();
//! # let threshold = 2;
//! # let epoch = "t";
//! # let measurement = "hello world";
//! # for i in 0..3 {
//! #     clients.push(Client::new(measurement.as_bytes(), threshold, epoch, None));
//! # }
//! # let triples: Vec<Triple> = clients.into_iter().map(|c| Triple::generate(&c, None)).collect();
//! # let shares: Vec<Share> = triples.iter().map(|triple| triple.share.clone()).collect();
//! let message = share_recover(&shares).unwrap().get_message();
//! 
//! // derive key for decrypting payload data in client message
//! let mut enc_key = vec![0u8; 16];
//! derive_ske_key(&message, epoch.as_bytes(), &mut enc_key);
//! ```

use std::error::Error;
use std::str;

extern crate ring;
use ring::digest::{self, Context, SHA256};
use ring::hkdf;

use adss_rs::{recover, Commune};
pub use {adss_rs::load_bytes, adss_rs::store_bytes, adss_rs::Share};

#[cfg(feature = "star2")]
use ppoprf::ppoprf::{end_to_end_evaluation, Server as PPOPRFServer};

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

// The `ClientSharingMaterial` consists of all data that is passed to the
// higher-level application for encrypting and sending the client
// measurements int he STAR protocol.
pub struct ClientSharingMaterial {
    pub key: Vec<u8>,
    pub share: Share,
    pub tag: Vec<u8>,
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
    pub x: Measurement,
    threshold: u32,
    epoch: String,
    pub aux: Option<AssociatedData>,
}
impl Client {
    pub fn new(x: &[u8], threshold: u32, epoch: &str, aux: Option<Vec<u8>>) -> Self {
        let x = Measurement::new(x);
        Self {
            x,
            threshold,
            epoch: epoch.to_string(),
            aux: aux.and_then(|x| Some(AssociatedData::new(&x))),
        }
    }

    // Share with OPRF randomness (STAR1)
    pub fn share_with_local_randomness(&self) -> ClientSharingMaterial {
        let mut rnd = vec![0u8; 32];
        self.sample_local_randomness(&mut rnd);
        let r = self.derive_random_values(&rnd);
        
        // key is then used for encrypting measurement and associated
        // data
        let key = self.derive_key(&r[0]);
        let share = self.share(&r[0], &r[1]);
        let tag = r[2].clone();
        ClientSharingMaterial {
            key,
            share,
            tag,
        }
    }

    #[cfg(feature = "star2")]
    // Share with OPRF randomness (STAR2)
    pub fn share_with_oprf_randomness(&self, oprf_server: &PPOPRFServer) -> ClientSharingMaterial {
        let mut rnd = vec![0u8; 32];
        self.sample_oprf_randomness(oprf_server, &mut rnd);
        let r = self.derive_random_values(&rnd);
        
        // key is then used for encrypting measurement and associated
        // data
        let key = self.derive_key(&r[0]);
        let share = self.share(&r[0], &r[1]);
        let tag = r[2].clone();
        ClientSharingMaterial {
            key,
            share,
            tag,
        }
    }

    fn derive_random_values(&self, randomness: &[u8]) -> Vec<Vec<u8>> {
        let mut output = Vec::new();
        for i in 0..3 {
            let mut hash = Context::new(&SHA256);
            hash.update(randomness);
            hash.update(&[i as u8]);
            output.push(hash.finish().as_ref().to_vec());
        }
        output
    }

    fn derive_key(&self, r1: &[u8]) -> Vec<u8> {
        let mut enc_key = vec![0u8; 16];
        derive_ske_key(r1, self.epoch.as_bytes(), &mut enc_key);
        enc_key
    }

    fn share(&self, r1: &[u8], r2: &[u8]) -> Share {
        let c = Commune::new(self.threshold, r1.to_vec(), r2.to_vec(), None);
        c.share()
    }

    fn sample_local_randomness(&self, out: &mut [u8]) {
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

    #[cfg(feature = "star2")]
    fn sample_oprf_randomness(&self, oprf_server: &PPOPRFServer, out: &mut [u8]) {
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
