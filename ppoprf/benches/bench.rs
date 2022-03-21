use criterion::{criterion_group, criterion_main, Criterion};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core_ristretto::OsRng;
use ring::digest;

use ppoprf::ggm::GGM;
use ppoprf::ppoprf::end_to_end_evaluation;
use ppoprf::ppoprf::{Client, Point, Server};
use ppoprf::PPRF;

fn criterion_benchmark(c: &mut Criterion) {
    benchmark_ggm(c);
    benchmark_ppoprf(c);
    benchmark_server(c);
    benchmark_client(c);
}

fn benchmark_ggm(c: &mut Criterion) {
    c.bench_function("GGM setup", |b| {
        b.iter(GGM::setup);
    });

    c.bench_function("GGM eval 1 bit", |b| {
        let ggm = GGM::setup();
        let mut out = vec![0u8; 32];
        let input = b"x";
        b.iter(|| {
            ggm.eval(input, &mut out).unwrap();
        });
    });

    c.bench_function("GGM setup & puncture 1 input", |b| {
        let input = b"x";
        b.iter(|| {
            let mut ggm = GGM::setup();
            ggm.puncture(input).unwrap();
        });
    });

    c.bench_function("GGM setup & puncture all inputs", |b| {
        let mut inputs = Vec::new();
        for i in 0..255 {
            inputs.push(vec![i as u8]);
        }
        b.iter(|| {
            let mut ggm = GGM::setup();
            for x in &inputs {
                ggm.puncture(x).unwrap();
            }
        });
    });
}

fn benchmark_ppoprf(c: &mut Criterion) {
    let mds = [b"x".to_vec()];
    let server = Server::new(&mds).unwrap();
    let c_input = b"a_random_client_input";
    c.bench_function("PPOPRF end-to-end evaluation", |b| {
        b.iter(|| end_to_end_evaluation(&server, c_input, 0, false, &mut [0u8; 32]));
    });

    c.bench_function("PPOPRF end-to-end evaluation verifiable", |b| {
        b.iter(|| end_to_end_evaluation(&server, c_input, 0, true, &mut [0u8; 32]));
    });

    c.bench_function("PPOPRF setup & puncture 1 input", |b| {
        b.iter(|| {
            let mut server = Server::new(&mds).unwrap();
            server.puncture(b"x").unwrap();
        });
    });

    c.bench_function("PPOPRF setup & puncture all inputs", |b| {
        let mut inputs = Vec::new();
        for i in 0..255 {
            inputs.push(vec![i as u8]);
        }
        b.iter(|| {
            let mut server = Server::new(&inputs).unwrap();
            for md in &inputs {
                server.puncture(md).unwrap();
            }
        });
    });
}

fn benchmark_server(c: &mut Criterion) {
    let mut mds = Vec::new();
    for i in 0..7 {
        mds.push(vec![i as u8]);
    }

    c.bench_function("Server setup", |b| {
        b.iter(|| {
            Server::new(&mds).unwrap();
        })
    });

    c.bench_function("Server puncture 1 input", |b| {
        b.iter(|| {
            let mut server = Server::new(&mds).unwrap();
            server.puncture(&[0u8]).unwrap();
        })
    });

    c.bench_function("Server eval", |b| {
        b.iter(|| {
            let server = Server::new(&mds).unwrap();
            let point = Point(RistrettoPoint::random(&mut OsRng).compress());
            server.eval(&point, 0, false).unwrap();
        })
    });

    c.bench_function("Server verifiable eval", |b| {
        b.iter(|| {
            let server = Server::new(&mds).unwrap();
            let point = Point(RistrettoPoint::random(&mut OsRng).compress());
            server.eval(&point, 0, true).unwrap();
        })
    });
}

fn benchmark_client(c: &mut Criterion) {
    let mut mds = Vec::new();
    for i in 0..7 {
        mds.push(vec![i as u8]);
    }
    let input = digest::digest(&digest::SHA512, &Scalar::random(&mut OsRng).to_bytes());
    let server = Server::new(&mds).unwrap();

    c.bench_function("Client blind", |b| {
        b.iter(|| {
            Client::blind(input.as_ref());
        })
    });

    c.bench_function("Client verify", |b| {
        let (blinded_point, _) = Client::blind(input.as_ref());
        let eval = server.eval(&blinded_point, 0, true).unwrap();
        b.iter(|| {
            Client::verify(
                &server.get_public_key(),
                &blinded_point.0.decompress().unwrap(),
                &eval,
                0,
            );
        })
    });

    c.bench_function("Client unblind", |b| {
        let (blinded_point, r) = Client::blind(input.as_ref());
        b.iter(|| {
            Client::unblind(&blinded_point.0, &r);
        })
    });

    c.bench_function("Client finalize", |b| {
        let random_point = RistrettoPoint::random(&mut OsRng);
        b.iter(|| {
            Client::finalize(
                input.as_ref(),
                &mds[0],
                &random_point.compress(),
                &mut [0u8; 32],
            );
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
