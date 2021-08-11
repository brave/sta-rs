use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::str;

extern crate ring;
use ring::aead;
use ring::digest;
use ring::digest::{Context, SHA256};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};

use rand::distributions::Distribution;

use adss_rs::{Commune, Share, recover};
use ppoprf::ppoprf::{Server as OPRFServer, end_to_end_evaluation};

use zipf::ZipfDistribution;

pub const ZIPF_NUM_SITES: usize = 1000;
pub const ZIPF_EXPONENT: f64 = 1.03;

pub const AES_BLOCK_LEN: usize = 24;
pub const MEASUREMENT_MAX_LEN: usize = 32;

// A `Measurement` provides the wrapper for a client-generated value in
// the STAR protocol that is later aggregated and processed at the
// server-side. Measurements are only revealed on the server-side if the
// `threshold` is met, in terms of clients that send the same
// `Measurement` value.
// 
// Such data is essentially arbitrary subject to the maximum length
// requirement specified by `MEASUREMENT_MAX_LEN`
pub struct Measurement(Vec<u8>);
impl Measurement {
    pub fn new(x: &[u8]) -> Self {
        let mut m = x.to_vec();
        if m.len() > MEASUREMENT_MAX_LEN {
            panic!("Length of string ({:?}) is too long", m.len());
        }
        m.extend(vec![0u8; MEASUREMENT_MAX_LEN-x.len()]);
        Self(m)
    }

    pub fn zipf() -> Self {
        let mut rng = rand::thread_rng();
        let zipf = ZipfDistribution::new(ZIPF_NUM_SITES, ZIPF_EXPONENT).unwrap();
        let sample = zipf.sample(&mut rng).to_le_bytes();
        let mut extended = sample.to_vec();
        extended.extend(vec![0u8; MEASUREMENT_MAX_LEN-sample.len()]);
        Self(extended.to_vec())
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn as_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn len(&self) -> usize {
        self.0.len()
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
// `ÀssociatedData`.
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
        
        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &enc_key_buf).unwrap();
        let ls_key = aead::LessSafeKey::new(unbound);
        ls_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out).unwrap();
        
        Self { bytes: in_out, nonce: nonce_buf, aad: None }
    }

    fn decrypt(&self, enc_key_buf: &[u8]) -> Vec<u8> {
        let ls_key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &enc_key_buf).unwrap());
        let mut in_out = self.bytes.clone();
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce);
        ls_key.open_in_place(nonce, aead::Aad::empty(), &mut in_out).unwrap();
        let plaintext = in_out[..in_out.len()-aead::AES_128_GCM.tag_len()].to_vec();
        plaintext
    }
}

// A `Triple` is the message that a client sends to the server during
// the STAR protocol. Consisting of a `Ciphertext`, a `Share`, and a
// `tag`. The `Ciphertext`can only be decrypted if a `threshold` number
// of clients possess the same measurement.
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

// An `Òutput` corresponds to a single client `Measurement` sent to the
// `AggregationServer` that satisfied the `threshold` check. Such
// structs contain the `Measurement` value itself, along with a vector
// of all the optional `ÀssociatedData` values sent by clients.
pub struct Output {
    x: Measurement,
    aux: Vec<Option<AssociatedData>>,
}
impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
         .field("tag", &self.x.0)
         .field("aux", &self.aux)
         .finish()
    }
}

// In the STAR protocol, the `Client`is the entity which samples and
// sends `Measurement` to the `ÀggregationServer`. The measurements will
// only be revealed if a `threshold` number of clients send the same
// encoded `Measurement` value.
// 
// Note that the `Client` struct holds all of the public protocol
// parameters, the secret `Measurement` and `ÀssociatedData` objects,
// and where randomness should be sampled from.
// 
// In the STAR1 protocol, the `Client` samples randomness locally: derived
// straight from the `Measurement` itself. In the STAR2 protocol, the
// `Client` derives its randomness from an exchange with a
// specifically-defined server that runs a POPRF.
pub struct Client {
    x: Measurement,
    threshold: u8,
    epoch: String,
    use_local_rand: bool,
    aux: Option<AssociatedData>,
}
impl Client {
    pub fn new(x: &[u8], threshold: u8, epoch: &str, use_local_rand: bool, aux: Option<Vec<u8>>) -> Self {
        let x = Measurement::new(x);
        if let Some(v) = aux {
            return Self{ x, threshold, epoch: epoch.to_string(), use_local_rand, aux: Some(AssociatedData::new(&v)) };
        }
        Self{ x, threshold, epoch: epoch.to_string(), use_local_rand, aux: None }
    }

    pub fn random(threshold: u8, epoch: &str, use_local_rand: bool, aux: Option<Vec<u8>>) -> Self {
        let x = Measurement::zipf();
        if let Some(v) = aux {
            return Self{ x: x, threshold: threshold, epoch: epoch.to_string(), use_local_rand, aux: Some(AssociatedData::new(&v)) };
        }
        Self{ x, threshold, epoch: epoch.to_string(), use_local_rand, aux: None }
    }

    // Generates a triple that is used in the aggregation phase
    pub fn generate_triple(&self, oprf_server: Option<&OPRFServer>) -> Triple {
        let mut rnd = vec![0u8; 32];
        if self.use_local_rand {
            self.sample_local_randomness(&mut rnd);
        } else {
            if let None = oprf_server {
                panic!("No OPRF server specified");
            }
            self.sample_oprf_randomness(&oprf_server.unwrap(), &mut rnd);
        }
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
        let mut enc_key = vec![0u8; 16];
        derive_ske_key(r1, self.epoch.as_bytes(), &mut enc_key);
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

    fn sample_local_randomness(&self, out: &mut [u8]) {
        if out.len() != digest::SHA256_OUTPUT_LEN {
            panic!("Output buffer length ({}) does not match randomness length ({})", out.len(), digest::SHA256_OUTPUT_LEN);
        }
        let mut hash = Context::new(&digest::SHA256);
        hash.update(&self.x.as_slice());
        hash.update(self.epoch.as_bytes());
        let digest = hash.finish();
        out.copy_from_slice(digest.as_ref());
    }

    fn sample_oprf_randomness(&self, oprf_server: &OPRFServer, out: &mut [u8]) {
        end_to_end_evaluation(oprf_server, self.x.as_slice(), self.epoch.as_bytes(), out);
    }
}

// The `AggregationServer` is the entity that processes `Client`
// messages and learns `Measurement` values and `ÀssociatedData` if the
// `threshold` is met. These servers possess no secret data.
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
        let mut enc_key_buf = vec![0u8; 16];
        self.key_recover(triples, &mut enc_key_buf);
        
        let ciphertexts: Vec<Ciphertext> = triples.into_iter().map(|t| t.ciphertext.clone()).collect();
        let plaintexts: Vec<Vec<u8>> = ciphertexts.into_iter().map(|c| c.decrypt(&enc_key_buf)).collect();
        
        let splits: Vec<(Vec<u8>, Option<AssociatedData>)> = plaintexts.into_iter().map(|p| {
            let max_aes_length = MEASUREMENT_MAX_LEN + AES_BLOCK_LEN - (MEASUREMENT_MAX_LEN % AES_BLOCK_LEN);
            if p.len() > max_aes_length {
                return (p[..MEASUREMENT_MAX_LEN].to_vec(), Some(AssociatedData(p[MEASUREMENT_MAX_LEN..].to_vec())));
            }
            (p, None)
        }).collect();
        let tag = &splits[0].0;
        for i in 1..splits.len() {
            let new_tag = &splits[i].0;
            if new_tag != tag {
                panic!("tag mismatch ({:?} != {:?})", tag, new_tag);
            }
        }
        Output { x: Measurement(tag.clone()), aux: splits.into_iter().map(|val| val.1).collect() }
    }

    fn key_recover(&self, triples: &[Triple], enc_key: &mut [u8]) {
        let shares: Vec<Share> = triples.into_iter().map(|triple| triple.share.clone()).collect();
        let commune = self.share_recover(&shares);
        let message = commune.get_message();
        derive_ske_key(&message, self.epoch.as_bytes(), enc_key);
    }

    fn share_recover(&self, shares: &[Share]) -> Commune {
        recover(shares).unwrap()
    }

    fn filter_triples(&self, triples: &[Triple]) -> Vec<Vec<Triple>> {
        let collected = self.collect_triples(triples);
        collected.into_iter().filter(|bucket| bucket.len() >= (self.threshold as usize)).collect()
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

// The `derive_ske_key` helper function derives symmetric encryption
// keys that are used for encrypting/decrypting `Ciphertext` objects
// during the STAR protocol.
fn derive_ske_key(r1: &[u8], epoch: &[u8], key_out: &mut [u8]) {
    if key_out.len() != digest::SHA256_OUTPUT_LEN/2 {
        panic!("Output buffer length ({}) does not match randomness length ({})", key_out.len(), digest::SHA256_OUTPUT_LEN/2);
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
    fn star1_no_aux_multiple_block() {
        star_no_aux_multiple_block(true, None);
    }
    
    #[test]
    fn star1_no_aux_single_block() {
        star_no_aux_single_block(true, None);
    }
    
    #[test]
    fn star1_with_aux_multiple_block() {
        star_with_aux_multiple_block(true, None);
    }
    
    #[test]
    fn star1_rand_with_aux_multiple_block() {
        star_rand_with_aux_multiple_block(true, None);
    }

    #[test]
    fn star2_no_aux_multiple_block() {
        star_no_aux_multiple_block(false, Some(OPRFServer::new()));
    }
    
    #[test]
    fn star2_no_aux_single_block() {
        star_no_aux_single_block(false, Some(OPRFServer::new()));
    }
    
    #[test]
    fn star2_with_aux_multiple_block() {
        star_with_aux_multiple_block(false, Some(OPRFServer::new()));
    }
    
    #[test]
    fn star2_rand_with_aux_multiple_block() {
        star_rand_with_aux_multiple_block(false, Some(OPRFServer::new()));
    }

    fn star_no_aux_multiple_block(use_local_rand: bool, oprf_server: Option<OPRFServer>) {
        let mut clients = Vec::new();
        let threshold = 2;
        let epoch = "t";
        let str1 = "hello world";
        let str2 = "goodbye sweet prince";
        for i in 0..10 {
            if i % 3 == 0 {
                clients.push(Client::new(str1.as_bytes(), threshold, epoch, use_local_rand, None));
            } else if i % 4 == 0 {
                clients.push(Client::new(str2.as_bytes(), threshold, epoch, use_local_rand, None));
            } else {
                clients.push(Client::new(&[i as u8], threshold, epoch, use_local_rand, None));
            }
        }
        let agg_server = AggregationServer::new(threshold, epoch);

        let triples: Vec<Triple> = clients.into_iter().map(|c| c.generate_triple(oprf_server.as_ref())).collect();
        let outputs = agg_server.retrieve_outputs(&triples);
        for o in outputs {
            let tag_str = str::from_utf8(&o.x.0).unwrap().trim_end_matches(char::from(0));
            if tag_str == str1 {
                assert_eq!(o.aux.len(), 4);
            } else if tag_str == str2 {
                assert_eq!(o.aux.len(), 2);
            } else {
                panic!("Unexpected tag: {}", tag_str);
            }

            for a in o.aux {
                if let Some(b) = a {
                    panic!("Unexpected auxiliary data: {:?}", b);
                }
            }
        }
    }

    fn star_no_aux_single_block(use_local_rand: bool, oprf_server: Option<OPRFServer>) {
        let mut clients = Vec::new();
        let threshold = 2;
        let epoch = "t";
        let str1 = "three";
        let str2 = "four";
        for i in 0..10 {
            if i % 3 == 0 {
                clients.push(Client::new(str1.as_bytes(), threshold, epoch, use_local_rand, None));
            } else if i % 4 == 0 {
                clients.push(Client::new(str2.as_bytes(), threshold, epoch, use_local_rand, None));
            } else {
                clients.push(Client::new(&[i as u8], threshold, epoch, use_local_rand, None));
            }
        }
        let agg_server = AggregationServer::new(threshold, epoch);

        let triples: Vec<Triple> = clients.into_iter().map(|c| c.generate_triple(oprf_server.as_ref())).collect();
        let outputs = agg_server.retrieve_outputs(&triples);
        for o in outputs {
            let tag_str = str::from_utf8(&o.x.0).unwrap().trim_end_matches(char::from(0));
            if tag_str == str1 {
                assert_eq!(o.aux.len(), 4);
            } else if tag_str == str2 {
                assert_eq!(o.aux.len(), 2);
            } else {
                panic!("Unexpected tag: {}", tag_str);
            }

            for a in o.aux {
                if let Some(b) = a {
                    panic!("Unexpected auxiliary data: {:?}", b);
                }
            }
        }
    }

    fn star_with_aux_multiple_block(use_local_rand: bool, oprf_server: Option<OPRFServer>) {
        let mut clients = Vec::new();
        let threshold = 2;
        let epoch = "t";
        let str1 = "hello world";
        let str2 = "goodbye sweet prince";
        for i in 0..10 {
            if i % 3 == 0 {
                clients.push(Client::new(str1.as_bytes(), threshold, epoch, use_local_rand, Some(vec![i+1 as u8; 1])));
            } else if i % 4 == 0 {
                clients.push(Client::new(str2.as_bytes(), threshold, epoch, use_local_rand, Some(vec![i+1 as u8; 1])));
            } else {
                clients.push(Client::new(&[i as u8], threshold, epoch, use_local_rand, Some(vec![i+1 as u8; 1])));
            }
        }
        let agg_server = AggregationServer::new(threshold, epoch);

        let triples: Vec<Triple> = clients.into_iter().map(|c| c.generate_triple(oprf_server.as_ref())).collect();
        let outputs = agg_server.retrieve_outputs(&triples);
        for o in outputs {
            let tag_str = str::from_utf8(&o.x.0).unwrap().trim_end_matches(char::from(0));
            if tag_str == str1 {
                assert_eq!(o.aux.len(), 4);
            } else if tag_str == str2 {
                assert_eq!(o.aux.len(), 2);
            } else {
                panic!("Unexpected tag: {}", tag_str);
            }

            for a in o.aux {
                match a {
                    None => panic!("Expected auxiliary data!"),
                    Some(b) => {
                        let v = b.as_vec();
                        for i in 0..10 {
                            let aux_str = str::from_utf8(&v).unwrap().trim_end_matches(char::from(0));
                            if aux_str.len() > 1 {
                                panic!("Auxiliary data has wrong length: {}", v.len());
                            } else if v[0] == i as u8 {
                                return;
                            }
                        }
                        panic!("Auxiliary data has unexpected value: {}", v[0]);
                    }
                }
            }
        }
    }

    fn star_rand_with_aux_multiple_block(use_local_rand: bool, oprf_server: Option<OPRFServer>) {
        let mut clients = Vec::new();
        let threshold = 5;
        let epoch = "t";
        for i in 0..128 {
            clients.push(Client::random(threshold, epoch, use_local_rand, Some(vec![i+1 as u8; 4])));
        }
        let agg_server = AggregationServer::new(threshold, epoch);

        let triples: Vec<Triple> = clients.into_iter().map(|c| c.generate_triple(oprf_server.as_ref())).collect();
        let outputs = agg_server.retrieve_outputs(&triples);
        for o in outputs {
            for aux in o.aux {
                if let None = aux {
                    panic!("Expected auxiliary data");
                } else if let Some(a) = aux {
                    let val = a.0[0];
                    assert!(val < 129);
                    for i in 1..3 {
                        assert_eq!(a.0[i], val);
                    }
                }
            }
        }
    }
}
