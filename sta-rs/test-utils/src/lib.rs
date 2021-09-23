use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;

use rand::distributions::Distribution;
use rayon::prelude::*;

use strobe_rs::{SecParam, Strobe};

use zipf::ZipfDistribution;

#[cfg(feature = "star2")]
pub use ppoprf::ppoprf::Server as PPOPRFServer;

#[cfg(not(feature = "star2"))]
pub struct PPOPRFServer;

use sta_rs::*;

// The `zipf_measurement` function returns a client `Measurement` sampled from
// Zipf power-law distribution with `n` corresponding to the number
// of potential elements, and `s` the exponent.
pub fn measurement_zipf(n: usize, s: f64) -> Measurement {
    let mut rng = rand::thread_rng();
    let zipf = ZipfDistribution::new(n, s).unwrap();
    let sample = zipf.sample(&mut rng).to_le_bytes();
    let extended = sample.to_vec();
    // essentially we compute a hash here so that we can simulate
    // having a full 32 bytes of data
    let mut to_fill = vec![0u8; 32];
    strobe_digest(&vec![0u8; 32], &[&extended], "star_zipf_sample", &mut to_fill);
    Measurement::new(&to_fill)
}

pub fn client_zipf(n: usize, s: f64, threshold: u32, epoch: &str, aux: Option<Vec<u8>>) -> Client {
    let x = measurement_zipf(n, s);
    Client::new(x.as_slice(), threshold, epoch, aux)
}

// The `Ciphertext` struct holds the symmetrically encrypted data that
// corresponds to the concatenation of `Measurement` and any optional
// `AssociatedData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    bytes: Vec<u8>,
}
impl Ciphertext {
    fn new(enc_key_buf: &[u8], data: &[u8]) -> Self {
        let mut s = Strobe::new(b"star_encrypt", SecParam::B128);
        s.key(enc_key_buf, false);
        let mut x = vec![0u8; data.len()];
        x.copy_from_slice(data);
        s.send_enc(&mut x, false);

        Self {
            bytes: x.to_vec(),
        }
    }

    pub fn decrypt(&self, enc_key_buf: &[u8]) -> Vec<u8> {
        let mut s = Strobe::new(b"star_encrypt", SecParam::B128);
        s.key(enc_key_buf, false);
        let mut m = vec![0u8; self.bytes.len()];
        m.copy_from_slice(&self.bytes);
        s.recv_enc(&mut m, false);
        m
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn from_bytes(bytes: &[u8]) -> Ciphertext {
        Self { bytes: bytes.to_vec() }
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

    // Generates a triple that is used in the aggregation phase
    pub fn generate(client: &Client, oprf_server: Option<&PPOPRFServer>) -> Self {
        // Adding '_' in as prefix of 'oprf' because when star2 is disabled then Clippy complains.
        let ClientSharingMaterial { key, share, tag } = if let Some(_oprf) = oprf_server {
            #[cfg(not(feature = "star2"))]
            unimplemented!();
            #[cfg(feature = "star2")]
            client.share_with_oprf_randomness(_oprf)
        } else {
            client.share_with_local_randomness()
        };

        let mut data: Vec<u8> = Vec::new();
        store_bytes(client.x.as_slice(), &mut data);
        if let Some(aux) = &client.aux {
            store_bytes(aux.as_slice(), &mut data);
        }
        let ciphertext = Ciphertext::new(&key, &data);

        Triple::new(ciphertext, share, &tag)
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
        let ciphertext = Ciphertext::from_bytes(cb);
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

// An `Output` corresponds to a single client `Measurement` sent to the
// `AggregationServer` that satisfied the `threshold` check. Such
// structs contain the `Measurement` value itself, along with a vector
// of all the optional `AssociatedData` values sent by clients.
pub struct Output {
    pub x: Measurement,
    pub aux: Vec<Option<AssociatedData>>,
}
impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
            .field("tag", &self.x)
            .field("aux", &self.aux)
            .finish()
    }
}

#[derive(Debug)]
enum AggServerError {
    PossibleShareCollision,
}

// The `AggregationServer` is the entity that processes `Client`
// messages and learns `Measurement` values and `AssociatedData` if the
// `threshold` is met. These servers possess no secret data.
pub struct AggregationServer {
    pub threshold: u32,
    pub epoch: String,
}
impl AggregationServer {
    pub fn new(threshold: u32, epoch: &str) -> Self {
        AggregationServer {
            threshold,
            epoch: epoch.to_string(),
        }
    }

    pub fn retrieve_outputs(&self, all_triples: &[Triple]) -> Vec<Output> {
        let filtered = self.filter_triples(all_triples);
        filtered
            .into_par_iter()
            .map(|triples| self.recover_measurements(&triples))
            .map(|output| output.unwrap())
            .collect()
    }

    fn recover_measurements(&self, triples: &[Triple]) -> Result<Output, AggServerError> {
        let mut enc_key_buf = vec![0u8; 16];
        let res = self.key_recover(triples, &mut enc_key_buf);
        if let Err(e) = res {
            return Err(e);
        }

        let ciphertexts = triples.iter().map(|t| t.ciphertext.clone());
        let plaintexts = ciphertexts.map(|c| c.decrypt(&enc_key_buf));

        let splits: Vec<(Vec<u8>, Option<AssociatedData>)> = plaintexts
            .map(|p| {
                let mut slice = &p[..];

                let measurement_bytes = load_bytes(slice).unwrap();
                slice = &slice[4 + measurement_bytes.len() as usize..];
                if !slice.is_empty() {
                    let aux_bytes = load_bytes(slice).unwrap();
                    if !aux_bytes.is_empty() {
                        return (
                            measurement_bytes.to_vec(),
                            Some(AssociatedData::new(aux_bytes)),
                        );
                    }
                }
                (measurement_bytes.to_vec(), None)
            })
            .collect();
        let tag = &splits[0].0;
        for new_tag in splits.iter().skip(1) {
            if &new_tag.0 != tag {
                panic!("tag mismatch ({:?} != {:?})", tag, new_tag.0);
            }
        }
        Ok(Output {
            x: Measurement::new(tag),
            aux: splits.into_iter().map(|val| val.1).collect(),
        })
    }

    fn key_recover(&self, triples: &[Triple], enc_key: &mut [u8]) -> Result<(), AggServerError> {
        let shares: Vec<Share> = triples.iter().map(|triple| triple.share.clone()).collect();
        let res = share_recover(&shares);
        if res.is_err() {
            return Err(AggServerError::PossibleShareCollision);
        }
        let message = res.unwrap().get_message();
        derive_ske_key(&message, self.epoch.as_bytes(), enc_key);
        Ok(())
    }

    fn filter_triples(&self, triples: &[Triple]) -> Vec<Vec<Triple>> {
        let collected = self.collect_triples(triples);
        collected
            .into_iter()
            .filter(|bucket| bucket.len() >= (self.threshold as usize))
            .collect()
    }

    fn collect_triples(&self, triples: &[Triple]) -> Vec<Vec<Triple>> {
        let mut collected_triples: HashMap<String, Vec<Triple>> = HashMap::new();
        for triple in triples {
            let s = format!("{:x?}", triple.tag);
            match collected_triples.entry(s) {
                Entry::Vacant(e) => {
                    e.insert(vec![triple.clone()]);
                }
                Entry::Occupied(mut e) => {
                    e.get_mut().push(triple.clone());
                }
            }
        }
        collected_triples.values().cloned().collect()
    }
}
