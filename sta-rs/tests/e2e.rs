use sta_rs::*;
use sta_rs_test_utils::*;

use base64::{decode, encode};

#[test]
fn serialize_ciphertext() {
    let client = Client::new(b"foobar", 0, "epoch", None);
    let triple = Triple::generate(&client, None);
    let bytes = triple.ciphertext.to_bytes();
    assert_eq!(Ciphertext::from_bytes(&bytes), triple.ciphertext);
}

#[test]
fn serialize_triple() {
    let client = Client::new(b"foobar", 0, "epoch", None);
    let triple = Triple::generate(&client, None);
    let bytes = triple.to_bytes();
    assert_eq!(Triple::from_bytes(&bytes), Some(triple));
}

#[test]
fn roundtrip() {
    let client = Client::new(b"foobar", 1, "epoch", None);
    let triple = Triple::generate(&client, None);

    let commune = share_recover(&[triple.share]).unwrap();
    let message = commune.get_message();

    let mut enc_key_buf = vec![0u8; 16];
    derive_ske_key(&message, "epoch".as_bytes(), &mut enc_key_buf);
    let plaintext = triple.ciphertext.decrypt(&enc_key_buf);
    let mut slice = &plaintext[..];

    let measurement_bytes = load_bytes(slice).unwrap();
    slice = &slice[4 + measurement_bytes.len() as usize..];

    if !slice.is_empty() {
        let aux_bytes = load_bytes(slice).unwrap();
        assert_eq!(aux_bytes.len(), 0);
    }

    assert_eq!(measurement_bytes, b"foobar");
}

#[test]
fn star1_no_aux_multiple_block() {
    star_no_aux_multiple_block(None);
}

#[test]
fn star1_no_aux_single_block() {
    star_no_aux_single_block(None);
}

#[test]
fn star1_with_aux_multiple_block() {
    star_with_aux_multiple_block(None);
}

#[test]
fn star1_rand_with_aux_multiple_block() {
    star_rand_with_aux_multiple_block(None);
}

#[cfg(feature = "star2")]
#[test]
fn star2_no_aux_multiple_block() {
    star_no_aux_multiple_block(Some(PPOPRFServer::new()));
}

#[cfg(feature = "star2")]
#[test]
fn star2_no_aux_single_block() {
    star_no_aux_single_block(Some(PPOPRFServer::new()));
}

#[cfg(feature = "star2")]
#[test]
fn star2_with_aux_multiple_block() {
    star_with_aux_multiple_block(Some(PPOPRFServer::new()));
}

#[cfg(feature = "star2")]
#[test]
fn star2_rand_with_aux_multiple_block() {
    star_rand_with_aux_multiple_block(Some(PPOPRFServer::new()));
}

fn star_no_aux_multiple_block(oprf_server: Option<PPOPRFServer>) {
    let mut clients = Vec::new();
    let threshold = 2;
    let epoch = "t";
    let str1 = "hello world";
    let str2 = "goodbye sweet prince";
    for i in 0..10 {
        if i % 3 == 0 {
            clients.push(Client::new(str1.as_bytes(), threshold, epoch, None));
        } else if i % 4 == 0 {
            clients.push(Client::new(str2.as_bytes(), threshold, epoch, None));
        } else {
            clients.push(Client::new(&[i as u8], threshold, epoch, None));
        }
    }
    let agg_server = AggregationServer::new(threshold, epoch);

    let triples: Vec<Triple> = clients
        .into_iter()
        .map(|c| Triple::generate(&c, oprf_server.as_ref()))
        .collect();
    let outputs = agg_server.retrieve_outputs(&triples[..]);
    for o in outputs {
        let tag_str = std::str::from_utf8(o.x.as_slice())
            .unwrap()
            .trim_end_matches(char::from(0));
        if tag_str == str1 {
            assert_eq!(o.aux.len(), 4);
        } else if tag_str == str2 {
            assert_eq!(o.aux.len(), 2);
        } else {
            panic!("Unexpected tag: {}", tag_str);
        }

        for b in o.aux.into_iter().flatten() {
            panic!("Unexpected auxiliary data: {:?}", b);
        }
    }
}

fn star_no_aux_single_block(oprf_server: Option<PPOPRFServer>) {
    let mut clients = Vec::new();
    let threshold = 2;
    let epoch = "t";
    let str1 = "three";
    let str2 = "four";
    for i in 0..10 {
        if i % 3 == 0 {
            clients.push(Client::new(str1.as_bytes(), threshold, epoch, None));
        } else if i % 4 == 0 {
            clients.push(Client::new(str2.as_bytes(), threshold, epoch, None));
        } else {
            clients.push(Client::new(&[i as u8], threshold, epoch, None));
        }
    }
    let agg_server = AggregationServer::new(threshold, epoch);

    let triples: Vec<Triple> = clients
        .into_iter()
        .map(|c| Triple::generate(&c, oprf_server.as_ref()))
        .collect();

    //  inspect lengths etc
    let t = &triples[0];
    println!("ciphertext: {:?}", encode(t.ciphertext.to_bytes()).len());
    println!("share: {:?}", encode(t.share.to_bytes()).len());
    println!("tag: {:?}", encode(&t.tag).len());

    let outputs = agg_server.retrieve_outputs(&triples);
    for o in outputs {
        let tag_str = std::str::from_utf8(o.x.as_slice())
            .unwrap()
            .trim_end_matches(char::from(0));
        if tag_str == str1 {
            assert_eq!(o.aux.len(), 4);
        } else if tag_str == str2 {
            assert_eq!(o.aux.len(), 2);
        } else {
            panic!("Unexpected tag: {}", tag_str);
        }

        for b in o.aux.into_iter().flatten() {
            panic!("Unexpected auxiliary data: {:?}", b);
        }
    }
}

fn star_with_aux_multiple_block(oprf_server: Option<PPOPRFServer>) {
    let mut clients = Vec::new();
    let threshold = 2;
    let epoch = "t";
    let str1 = "hello world";
    let str2 = "goodbye sweet prince";
    for i in 0..10 {
        if i % 3 == 0 {
            clients.push(Client::new(
                str1.as_bytes(),
                threshold,
                epoch,
                Some(vec![i + 1; 1]),
            ));
        } else if i % 4 == 0 {
            clients.push(Client::new(
                str2.as_bytes(),
                threshold,
                epoch,
                Some(vec![i + 1; 1]),
            ));
        } else {
            clients.push(Client::new(
                &[i as u8],
                threshold,
                epoch,
                Some(vec![i + 1; 1]),
            ));
        }
    }
    let agg_server = AggregationServer::new(threshold, epoch);

    let triples: Vec<Triple> = clients
        .into_iter()
        .map(|c| Triple::generate(&c, oprf_server.as_ref()))
        .collect();
    let outputs = agg_server.retrieve_outputs(&triples[..]);
    for o in outputs {
        let tag_str = std::str::from_utf8(o.x.as_slice())
            .unwrap()
            .trim_end_matches(char::from(0));
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
                        let aux_str = std::str::from_utf8(&v)
                            .unwrap()
                            .trim_end_matches(char::from(0));
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

fn star_rand_with_aux_multiple_block(oprf_server: Option<PPOPRFServer>) {
    let mut clients = Vec::new();
    let threshold = 5;
    let epoch = "t";
    for i in 0..254 {
        clients.push(client_zipf(
            1000,
            1.03,
            threshold,
            epoch,
            Some(vec![i + 1; 256]),
        ));
    }
    let agg_server = AggregationServer::new(threshold, epoch);

    let triples: Vec<Triple> = clients
        .into_iter()
        .map(|c| Triple::generate(&c, oprf_server.as_ref()))
        .collect();

    //  inspect lengths etc
    let t = &triples[0];
    println!("ciphertext: {:?}", encode(t.ciphertext.to_bytes()).len());
    println!("share: {:?}", encode(t.share.to_bytes()).len());
    println!("tag: {:?}", encode(&t.tag).len());
    
    let outputs = agg_server.retrieve_outputs(&triples[..]);
    for o in outputs {
        for aux in o.aux {
            if aux.is_none() {
                panic!("Expected auxiliary data");
            } else if let Some(a) = aux {
                let val = a.as_slice()[0];
                assert!(val < 255);
                for i in 1..3 {
                    assert_eq!(a.as_slice()[i], val);
                }
            }
        }
    }
}
