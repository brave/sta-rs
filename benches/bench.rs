use criterion::{criterion_group, criterion_main, Criterion};

use sta_rs::*;

fn criterion_benchmark(c: &mut Criterion) {
    benchmark_ggm(c);
    benchmark_ppoprf(c);
}

fn benchmark_ggm(c: &mut Criterion) {
    c.bench_function(&format!("GGM setup"), |b| {
        b.iter(|| { 
            GGM::setup() 
        });
    });

    c.bench_function(&format!("GGM eval 1 bit"), |b| {
        let ggm = GGM::setup();
        let mut out = vec![0u8; 32];
        let input = b"x";
        b.iter(|| {
            ggm.eval(input, &mut out);
        });
    });

    c.bench_function(&format!("GGM setup & puncture 1 input"), |b| {
        let input = b"x";
        b.iter(|| {
            let mut ggm = GGM::setup();
            ggm.puncture(input);
        });
    });
    
    c.bench_function(&format!("GGM setup & puncture all inputs"), |b| {
        let mut inputs = Vec::new();
        for i in 0..255 {
            inputs.push(vec![i as u8]);
        }
        b.iter(|| {
            let mut ggm = GGM::setup();
            for x in &inputs {
                ggm.puncture(&x);
            }
        });
    });
}

fn benchmark_ppoprf(c: &mut Criterion) {
    c.bench_function(&format!("PPOPRF end-to-end evaluation"), |b| {
        b.iter(|| { 
            let server = Server::new();
            let c_input = b"a_random_client_input";
            let md = b"x";
            let input = digest::digest(&digest::SHA512, c_input);
            let (blinded_point, r) = Client::blind(&input.as_ref());
            let evaluated = server.eval(&blinded_point, md);
            let unblinded = Client::unblind(&evaluated, &r);
            let mut out = vec![0u8; 32];
            Client::finalize(c_input, md, &unblinded, &mut out);
        });
    });

    c.bench_function(&format!("PPOPRF setup & puncture 1 input"), |b| {
        let md = b"x";
        b.iter(|| { 
            let mut server = Server::new();
            server.puncture(md);
        });
    });
    
    c.bench_function(&format!("PPOPRF setup & puncture 1 input"), |b| {
        let mut inputs = Vec::new();
        for i in 0..255 {
            inputs.push(vec![i as u8]);
        }
        b.iter(|| { 
            let mut server = Server::new();
            for md in &inputs {
                server.puncture(md);
            }
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
