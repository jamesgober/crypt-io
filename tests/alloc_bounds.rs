//! Memory a peer can make crypt-io reserve before anything is
//! authenticated (1.6.0).
//!
//! A counting global allocator records the largest single allocation
//! and the number of allocations. One test function, so nothing else
//! allocates in parallel.

#![cfg(all(feature = "stream", any(feature = "std", feature = "getrandom")))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use crypt_io::stream::{StreamDecryptor, StreamEncryptor};
use crypt_io::{Algorithm, Crypt};

struct Largest;

static LARGEST: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System` with the same arguments; the
// only addition is a relaxed atomic update.
unsafe impl GlobalAlloc for Largest {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        let _ = COUNT.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Largest = Largest;

#[test]
fn decryptor_memory_follows_the_bytes_received() {
    let key = [7u8; 32];
    // A genuine header announcing 16 MiB chunks (the largest allowed).
    let (_enc, header) =
        StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, 24).unwrap();

    LARGEST.store(0, Ordering::Relaxed);
    let mut dec = StreamDecryptor::new(&key, &header).unwrap();
    assert_eq!(dec.chunk_size(), 16 * 1024 * 1024);
    // 1.5.0 reserved chunk_size + 16 bytes here, from an unauthenticated
    // header. Now nothing near that.
    let after_new = LARGEST.load(Ordering::Relaxed);
    assert!(after_new < 4096, "new() allocated {after_new} bytes");

    // A peer that sends 1 KiB makes the decryptor hold about 1 KiB.
    let _ = dec.update(&[0u8; 1024]).unwrap();
    let after_1k = LARGEST.load(Ordering::Relaxed);
    assert!(
        after_1k < 8 * 1024,
        "1 KiB of input allocated {after_1k} bytes"
    );

    // Allocations per call, as documented in PERFORMANCE.md.
    let allocs = |f: &mut dyn FnMut()| {
        f(); // warm up: buffers reach their size
        let before = COUNT.load(Ordering::Relaxed);
        f();
        COUNT.load(Ordering::Relaxed) - before
    };
    let pt = [0x11u8; 1000];
    for alg in [
        Algorithm::ChaCha20Poly1305,
        Algorithm::XChaCha20Poly1305,
        Algorithm::Aes256Gcm,
    ] {
        let crypt = Crypt::with_algorithm(alg);
        let keyed = crypt.keyed(&key).unwrap();
        let ct = crypt.encrypt(&key, &pt).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            allocs(&mut || drop(crypt.encrypt(&key, &pt).unwrap())),
            1,
            "{alg:?} encrypt"
        );
        assert_eq!(
            allocs(&mut || drop(crypt.decrypt(&key, &ct).unwrap())),
            1,
            "{alg:?} decrypt"
        );
        assert_eq!(
            allocs(&mut || crypt.encrypt_into(&key, &pt, &mut out).unwrap()),
            0,
            "{alg:?} encrypt_into"
        );
        assert_eq!(
            allocs(&mut || crypt.decrypt_into(&key, &ct, &mut out).unwrap()),
            0,
            "{alg:?} decrypt_into"
        );
        assert_eq!(
            allocs(&mut || keyed.encrypt_into(&pt, &mut out).unwrap()),
            0,
            "{alg:?} keyed encrypt_into"
        );
        assert_eq!(
            allocs(&mut || keyed.decrypt_into(&ct, &mut out).unwrap()),
            0,
            "{alg:?} keyed decrypt_into"
        );
        assert_eq!(
            allocs(&mut || drop(keyed.encrypt(&pt).unwrap())),
            1,
            "{alg:?} keyed encrypt"
        );
    }
}
