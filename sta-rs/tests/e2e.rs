use sta_rs::*;
use sta_rs_test_utils::AggregationServer;

use ppoprf::ppoprf::Server as PPOPRFServer;

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
    star_no_aux_multiple_block(false, Some(PPOPRFServer::new()));
}

#[test]
fn star2_no_aux_single_block() {
    star_no_aux_single_block(false, Some(PPOPRFServer::new()));
}

#[test]
fn star2_with_aux_multiple_block() {
    star_with_aux_multiple_block(false, Some(PPOPRFServer::new()));
}

#[test]
fn star2_rand_with_aux_multiple_block() {
    star_rand_with_aux_multiple_block(false, Some(PPOPRFServer::new()));
}

fn star_no_aux_multiple_block(use_local_rand: bool, oprf_server: Option<PPOPRFServer>) {
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
                use_local_rand,
                None,
            ));
        } else if i % 4 == 0 {
            clients.push(Client::new(
                str2.as_bytes(),
                threshold,
                epoch,
                use_local_rand,
                None,
            ));
        } else {
            clients.push(Client::new(
                &[i as u8],
                threshold,
                epoch,
                use_local_rand,
                None,
            ));
        }
    }
    let agg_server = AggregationServer::new(threshold, epoch);

    let triples: Vec<Triple> = clients
        .into_iter()
        .map(|c| c.generate_triple(oprf_server.as_ref()))
        .collect();
    let outputs = agg_server.retrieve_outputs(&triples[..]);
    for o in outputs {
        let tag_str = std::str::from_utf8(&o.x.as_slice())
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

fn star_no_aux_single_block(use_local_rand: bool, oprf_server: Option<PPOPRFServer>) {
    let mut clients = Vec::new();
    let threshold = 2;
    let epoch = "t";
    let str1 = "three";
    let str2 = "four";
    for i in 0..10 {
        if i % 3 == 0 {
            clients.push(Client::new(
                str1.as_bytes(),
                threshold,
                epoch,
                use_local_rand,
                None,
            ));
        } else if i % 4 == 0 {
            clients.push(Client::new(
                str2.as_bytes(),
                threshold,
                epoch,
                use_local_rand,
                None,
            ));
        } else {
            clients.push(Client::new(
                &[i as u8],
                threshold,
                epoch,
                use_local_rand,
                None,
            ));
        }
    }
    let agg_server = AggregationServer::new(threshold, epoch);

    let triples: Vec<Triple> = clients
        .into_iter()
        .map(|c| c.generate_triple(oprf_server.as_ref()))
        .collect();
    let outputs = agg_server.retrieve_outputs(&triples);
    for o in outputs {
        let tag_str = std::str::from_utf8(&o.x.as_slice())
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

fn star_with_aux_multiple_block(use_local_rand: bool, oprf_server: Option<PPOPRFServer>) {
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
                use_local_rand,
                Some(vec![i + 1; 1]),
            ));
        } else if i % 4 == 0 {
            clients.push(Client::new(
                str2.as_bytes(),
                threshold,
                epoch,
                use_local_rand,
                Some(vec![i + 1; 1]),
            ));
        } else {
            clients.push(Client::new(
                &[i as u8],
                threshold,
                epoch,
                use_local_rand,
                Some(vec![i + 1; 1]),
            ));
        }
    }
    let agg_server = AggregationServer::new(threshold, epoch);

    let triples: Vec<Triple> = clients
        .into_iter()
        .map(|c| c.generate_triple(oprf_server.as_ref()))
        .collect();
    let outputs = agg_server.retrieve_outputs(&triples[..]);
    for o in outputs {
        let tag_str = std::str::from_utf8(&o.x.as_slice())
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

fn star_rand_with_aux_multiple_block(use_local_rand: bool, oprf_server: Option<PPOPRFServer>) {
    let mut clients = Vec::new();
    let threshold = 5;
    let epoch = "t";
    for i in 0..254 {
        clients.push(Client::zipf(
            1000,
            1.03,
            threshold,
            epoch,
            use_local_rand,
            Some(vec![i + 1; 4]),
        ));
    }
    let agg_server = AggregationServer::new(threshold, epoch);

    let triples: Vec<Triple> = clients
        .into_iter()
        .map(|c| c.generate_triple(oprf_server.as_ref()))
        .collect();
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
