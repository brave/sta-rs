use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;

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
pub const MEASUREMENT_MAX_LEN: usize = 8;

pub struct Measurement(Vec<u8>);
impl Measurement {
    fn new(x: &[u8]) -> Self {
        let mut m = x.to_vec();
        if m.len() > MEASUREMENT_MAX_LEN {
            panic!("Length of string ({:?}) is too long");
        }
        m.extend(vec![0u8; MEASUREMENT_MAX_LEN-x.len()]);
        Self(m)
    }

    fn from_str(s: &str) -> Self {
        let s_bytes = s.as_bytes();
        Measurement::new(s_bytes)
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

    fn as_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[derive(Debug, Clone)]
struct Ciphertext {
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
        
        let ls_key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &enc_key_buf).unwrap());
        ls_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out);
        
        Self { bytes: in_out, nonce: nonce_buf, aad: None }
    }

    fn decrypt(&self, enc_key_buf: &[u8]) -> Vec<u8> {
        let ls_key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &enc_key_buf).unwrap());
        let mut in_out = self.bytes.clone();
        in_out.extend(vec![0u8; aead::AES_128_GCM.tag_len()]);
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce);
        ls_key.open_in_place(nonce, aead::Aad::empty(), &mut in_out);
        in_out[..in_out.len()-aead::AES_128_GCM.tag_len()].to_vec()
    }
}

#[derive(Clone)]
pub struct Triple {
    ciphertext: Ciphertext,
    share: Share,
    tag: Vec<u8>,
}
impl Triple {
    fn new(c: Ciphertext, share: Share, tag: &[u8]) -> Self {
        Self { ciphertext: c, share: share, tag: tag.to_vec() }
    }
}

// AggregationServer output from the protocol
pub struct Output {
    x: Measurement,
    aux: Vec<Vec<u8>>,
}
impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
         .field("tag", &self.x.0)
         .field("aux", &self.aux)
         .finish()
    }
}


pub struct Client {
    x: Measurement,
    threshold: u8,
    epoch: String,
    aux: Option<AssociatedData>,
}
impl Client {
    pub fn new(x: &[u8], threshold: u8, epoch: &str, aux: Option<&str>) -> Self {
        let x = Measurement::new(x);
        if let Some(s) = aux {
            return Self{ x: x, threshold: threshold, epoch: epoch.to_string(), aux: Some(AssociatedData::new(s)) };
        }
        Self{ x: x, threshold: threshold, epoch: epoch.to_string(), aux: None }
    }

    pub fn random(threshold: u8, epoch: &str, aux: Option<&str>) -> Self {
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
        let tag = &r[2];
        Triple::new(ciphertext, share, tag)
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

    fn derive_ciphertext(&self, r1: &[u8]) -> Ciphertext {
        let mut enc_key = vec![0u8; 32];
        derive_enc_key(r1, self.epoch.as_bytes(), &mut enc_key);
        let mut data = Vec::from(self.x.as_vec());
        if let Some(aux) = &self.aux {
            data.extend(aux.0.clone());
        }
        Ciphertext::new(&enc_key, &data)
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

pub struct AggregationServer {
    threshold: u8,
    epoch: String,
}
impl AggregationServer {
    pub fn new(threshold: u8, epoch: &str) -> Self {
        AggregationServer { threshold, epoch: epoch.to_string() }
    }

    pub fn retrieve_outputs(&self, all_triples: &[Triple]) -> Vec<Output> {
        let filtered = self.filter_triples(all_triples);
        filtered.into_iter().map(|triples| self.recover_measurements(&triples)).collect()
    }

    fn recover_measurements(&self, triples: &[Triple]) -> Output {
        let mut enc_key_buf = vec![0u8, 32];
        self.key_recover(triples, &mut enc_key_buf);
        
        let ciphertexts: Vec<Ciphertext> = triples.into_iter().map(|t| t.ciphertext.clone()).collect();
        let plaintexts: Vec<Vec<u8>> = ciphertexts.into_iter().map(|c| c.decrypt(&enc_key_buf)).collect();
        
        let splits: Vec<(Vec<u8>, Vec<u8>)> = plaintexts.into_iter().map(|p| {
            if p.len() > MEASUREMENT_MAX_LEN {
                return (p[..MEASUREMENT_MAX_LEN].to_vec(), p[MEASUREMENT_MAX_LEN..].to_vec());
            }
            (p, Vec::new())
        }).collect();
        let tag = &splits[0].0;
        for i in 1..splits.len() {
            let new_tag = &splits[i].0;
            if new_tag != tag {
                panic!("tag mismatch ({:?} != {:?})", tag, new_tag);
            }
        }
        Output { x: Measurement(tag.clone()), aux: splits.into_iter().map(|val| val.1).filter(|v| v.len() > 0).collect() }
    }

    fn key_recover(&self, triples: &[Triple], enc_key: &mut [u8]) {
        let shares: Vec<Share> = triples.into_iter().map(|triple| triple.share.clone()).collect();
        let commune = self.share_recover(&shares);
        let message = commune.get_message();
        derive_enc_key(&message, self.epoch.as_bytes(), enc_key);
    }

    fn share_recover(&self, shares: &[Share]) -> Commune {
        recover(shares).unwrap()
    }

    fn filter_triples(&self, triples: &[Triple]) -> Vec<Vec<Triple>> {
        let collected = self.collect_triples(triples);
        collected.into_iter().filter(|bucket| bucket.len() > (self.threshold as usize)).collect()
    }
    
    fn collect_triples(&self, triples: &[Triple]) -> Vec<Vec<Triple>> {
        let mut collected_triples: HashMap<String, Vec<Triple>> = HashMap::new();
        for triple in triples {
            let s = format!("{:x?}", triple.tag);
            match collected_triples.entry(s) {
                Entry::Vacant(e) => { e.insert(vec![triple.clone()]); },
                Entry::Occupied(mut e) => { e.get_mut().push(triple.clone()); }
            }
        }
        collected_triples.values().cloned().collect()
    }
}

fn derive_enc_key(r1: &[u8], epoch: &[u8], key_out: &mut [u8]) -> Vec<u8> {
    if key_out.len() != digest::SHA256_OUTPUT_LEN {
        panic!("Output buffer length ({}) does not match randomness length ({})", key_out.len(), digest::SHA256_OUTPUT_LEN);
    }
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, epoch);
    let prk = salt.extract(r1);
    let expand_info = &["star_threshold_agg".as_bytes()];
    let okm = prk.expand(expand_info, hkdf::HKDF_SHA256);
    if let Ok(derived) = okm {
        derived.fill(key_out).unwrap();
    }
    panic!("Failed to derive key");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end() {
        let mut clients = Vec::new();
        let threshold = 2;
        let epoch = "t";
        for i in 0..10 {
            if i % 3 == 0 {
                clients.push(Client::new(b"three", threshold, epoch, None));
            } else if i % 4 == 0 {
                clients.push(Client::new(b"four", threshold, epoch, None));
            } else {
                clients.push(Client::random(threshold, epoch, None));
            }
        }
        let agg_server = AggregationServer::new(threshold, epoch);

        let triples: Vec<Triple> = clients.into_iter().map(|c| c.generate_triple()).collect();
        let outputs = agg_server.retrieve_outputs(&triples);
        outputs.iter().for_each(|o| println!("{:?}", o));
    }
}
