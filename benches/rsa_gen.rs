use criterion::{black_box, criterion_group, criterion_main, Criterion};

use sec_primitives::prime::gen;

fn prime_gen(c: &mut Criterion) {
    let sizes = [128, 256, 512, 1024];
    for size in sizes {
        let name = format!("prime::gen({})", size);
        c.bench_function(&name, |b| b.iter(|| gen::new_prime(black_box(size))));
    }
}

criterion_group!(benches, prime_gen);
criterion_main!(benches);
