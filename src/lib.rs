use std::error::Error;

extern crate ring;
use ring::aead;
use ring::digest;
use ring::digest::{Context, SHA256};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};

use rand::distributions::Distribution;

use adss_rs::{Commune, Share, recover};

use zipf::ZipfDistribution;

pub const ZIPF_NUM_SITES: usize = 1000;
pub const ZIPF_EXPONENT: f64 = 1.03;

pub struct Measurement(Vec<u8>);
impl Measurement {
    fn new(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    fn zipf() -> Self {
        let mut rng = rand::thread_rng();
        let zipf = ZipfDistribution::new(ZIPF_NUM_SITES, ZIPF_EXPONENT).unwrap();
        let sample = zipf.sample(&mut rng).to_le_bytes();
        Self(sample.to_vec())
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn as_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct AssociatedData(Vec<u8>);
impl AssociatedData {
    fn new(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

pub struct Triple {
    ciphertext: Vec<u8>,
    share: Share,
    tag: Vec<u8>,
}
impl Triple {
    fn new(c: &[u8], share: Share, tag: &[u8]) -> Self {
        Self { ciphertext: c.to_vec(), share: share, tag: tag.to_vec() }
    }
}

pub struct Client {
    x: Measurement,
    threshold: u8,
    epoch: String,
    aux: Option<AssociatedData>,
}
impl Client {
    pub fn new(threshold: u8, epoch: &str, aux: Option<&str>) -> Self {
        let x = Measurement::zipf();
        if let Some(s) = aux {
            return Self{ x: x, threshold: threshold, epoch: epoch.to_string(), aux: Some(AssociatedData::new(s)) };
        }
        Self{ x: x, threshold: threshold, epoch: epoch.to_string(), aux: None }
    }

    // Generates a triple that is used in the aggregation phase
    pub fn generate_triple(&self) -> Triple {
        let mut rnd = vec![0u8; 32];
        self.sample_core_randomness(&mut rnd);
        let r = self.derive_random_values(&rnd);

        let ciphertext = self.derive_ciphertext(&r[0]);
        let share = self.share(&r[0], &r[1]);
        let tag = r[2];
        Triple::new(&ciphertext, share, &tag)
    }

    fn derive_random_values(&self, randomness: &[u8]) -> Vec<Vec<u8>> {
        let output = Vec::new();
        for i in 0..3 {
            let hash = Context::new(&SHA256);
            hash.update(randomness);
            hash.update(&[i as u8]);
            output.push(hash.finish().as_ref().to_vec());
        }
        output
    }

    fn derive_ciphertext(&self, r1: &[u8]) -> Vec<u8> {
        let mut enc_key = vec![0u8; 32];
        self.derive_enc_key(r1, &mut enc_key);
        
        // derive nonce
        let mut nonce = [0; 12];
        let prng = SystemRandom::new();
        prng.fill(&mut nonce).unwrap();
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        
        let mut in_out = r1.to_vec().clone();
        in_out.extend(vec![0u8; aead::AES_128_GCM.tag_len()]);
        
        let ls_key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &enc_key).unwrap());
        ls_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out);

        in_out
    }

    fn derive_enc_key(&self, r1: &[u8], key_out: &mut [u8]) -> Vec<u8> {
        if key_out.len() != digest::SHA256_OUTPUT_LEN {
            panic!("Output buffer length ({}) does not match randomness length ({})", key_out.len(), digest::SHA256_OUTPUT_LEN);
        }
        let salt_input = self.epoch;
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_input.as_bytes());
        let prk = salt.extract(r1);
        let okm = prk.expand(&[vec!["star_threshold_agg"; 1]], hkdf::HKDF_SHA256);
        if let Ok(derived) = okm {
            derived.fill(&mut key_out);
        }
        panic!("Failed to derive key");
    }

    fn share(&self, r1: &[u8], r2: &[u8]) -> Share {
        let c = Commune::new(self.threshold, r1.to_vec(), r2.to_vec(), None);
        c.share()
    }

    fn sample_core_randomness(&self, out: &mut [u8]) {
        if out.len() != digest::SHA256_OUTPUT_LEN {
            panic!("Output buffer length ({}) does not match randomness length ({})", out.len(), digest::SHA256_OUTPUT_LEN);
        }
        let digest = digest::digest(&digest::SHA256, &self.x.as_slice());
        out.copy_from_slice(digest.as_ref());
    }
}

pub struct Server {
    threshold: u8,
}
impl Server {
    pub fn new(threshold: u8) -> Self {
        Server { threshold }
    }

    fn share_recover(&self, shares: Vec<Share>) -> Result<Commune, Box<dyn Error>> {
        recover(&shares)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
