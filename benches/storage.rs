//! Criterion baselines for authenticated record and stream formats.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use crypt_io::storage::{
    EncryptedStreamCodec, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyProviderError, KeyScope,
    PurposeId, RecordCodec, RecordContext, SecretKey32, SpaceId, StreamContext,
};

const KEY_ID: KeyId = KeyId::new(*b"bench-key-id-v01");
const GENERATION: KeyGeneration = KeyGeneration::new(1);
const MASTER_KEY: [u8; 32] = [0xA5; 32];
const SPACE: SpaceId = SpaceId::new([0x5A; 32]);
const RECORD_PURPOSE: PurposeId = PurposeId::new(*b"memory-record-v1");
const STREAM_PURPOSE: PurposeId = PurposeId::new(*b"snapshot-strm-v1");

fn require_benchmark_fixture<T, E>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(_error) => std::process::abort(),
    }
}

#[derive(Clone, Copy)]
struct BenchProvider;

impl BenchProvider {
    fn lease() -> KeyLease {
        KeyLease::new(KEY_ID, GENERATION, SecretKey32::new(MASTER_KEY))
    }
}

impl KeyProvider for BenchProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Ok(Self::lease())
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        key_id: KeyId,
        generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        if key_id != KEY_ID || generation != GENERATION {
            return Err(KeyProviderError::Unavailable);
        }
        Ok(Self::lease())
    }
}

fn record_benchmarks(criterion: &mut Criterion) {
    let codec = RecordCodec::new(BenchProvider);
    let scope = KeyScope::new(SPACE, RECORD_PURPOSE);
    let context = require_benchmark_fixture(RecordContext::new(1, b"criterion/record/v1"));
    let mut group = criterion.benchmark_group("sealed_record_v1");

    for plaintext_len in [1024_usize, 64 * 1024, 1024 * 1024] {
        let plaintext = vec![0x5C; plaintext_len];
        let sealed = require_benchmark_fixture(codec.seal(&scope, &context, &plaintext));
        let throughput_bytes = require_benchmark_fixture(u64::try_from(plaintext_len));
        group.throughput(Throughput::Bytes(throughput_bytes));
        group.bench_with_input(
            BenchmarkId::new("seal", plaintext_len),
            &plaintext,
            |bencher, input| {
                bencher.iter(|| {
                    require_benchmark_fixture(codec.seal(&scope, &context, black_box(input)))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("open", plaintext_len),
            sealed.as_bytes(),
            |bencher, input| {
                bencher.iter(|| {
                    require_benchmark_fixture(codec.open(&scope, &context, black_box(input)))
                });
            },
        );
    }
    group.finish();
}

fn stream_benchmarks(criterion: &mut Criterion) {
    let codec = EncryptedStreamCodec::new(BenchProvider);
    let scope = KeyScope::new(SPACE, STREAM_PURPOSE);
    let context = require_benchmark_fixture(StreamContext::new(1, b"criterion/stream/v1"));
    let mut group = criterion.benchmark_group("encrypted_stream_v1");
    group.sample_size(20);

    for plaintext_len in [1024 * 1024_usize, 16 * 1024 * 1024] {
        let plaintext = vec![0xC5; plaintext_len];
        let sealed = require_benchmark_fixture(codec.seal(&scope, &context, &plaintext));
        let throughput_bytes = require_benchmark_fixture(u64::try_from(plaintext_len));
        group.throughput(Throughput::Bytes(throughput_bytes));
        group.bench_with_input(
            BenchmarkId::new("seal", plaintext_len),
            &plaintext,
            |bencher, input| {
                bencher.iter(|| {
                    require_benchmark_fixture(codec.seal(&scope, &context, black_box(input)))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("open", plaintext_len),
            sealed.as_bytes(),
            |bencher, input| {
                bencher.iter(|| {
                    require_benchmark_fixture(codec.open(&scope, &context, black_box(input)))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, record_benchmarks, stream_benchmarks);
criterion_main!(benches);
