use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;

use rayon::prelude::*;

use sta_rs::*;

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

                let measurement_bytes = load_bytes(&slice).unwrap();
                slice = &slice[4 + measurement_bytes.len() as usize..];
                if slice.len() > 0 {
                    let aux_bytes = load_bytes(&slice).unwrap();
                    if aux_bytes.len() > 0 {
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
            x: Measurement::new(&tag),
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
