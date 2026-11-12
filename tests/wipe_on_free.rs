//! No plaintext or derived key left in freed heap memory (1.6.0).
//!
//! A global allocator scans every block it frees for a marker and
//! counts the hits. Each scenario arms it, runs, and checks the count.
//! One test function, so nothing else runs while it is armed.

#![cfg(all(feature = "std", feature = "zeroize"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

const MARKER_LEN: usize = 32;

static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static MARKER: [AtomicU8; MARKER_LEN] = [const { AtomicU8::new(0) }; MARKER_LEN];

struct Spy;

fn contains_marker(block: &[u8]) -> bool {
    let mut marker = [0u8; MARKER_LEN];
    for (m, a) in marker.iter_mut().zip(MARKER.iter()) {
        *m = a.load(Ordering::Relaxed);
    }
    block.windows(MARKER_LEN).any(|w| w == marker)
}

// SAFETY: allocation is forwarded to `System` unchanged. `dealloc` reads
// the block it is about to free (only compared, never interpreted) and
// zeroes it before forwarding.
unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) && layout.size() >= MARKER_LEN {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until
            // the `System.dealloc` below. Uninitialised bytes are only
            // compared as `u8`, which the scan tolerates for this test.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if contains_marker(block) {
                let _ = HITS.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Zero every freed block, armed or not, so a block handed out
        // again later cannot carry an old marker copy (from the test's
        // own buffers) into a scan.
        // SAFETY: `ptr` is valid for `layout.size()` bytes until freed.
        unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Spy = Spy;

fn set_marker(bytes: &[u8]) {
    for (a, b) in MARKER.iter().zip(bytes) {
        a.store(*b, Ordering::Relaxed);
    }
}

/// Run `f` with the scan armed and return how many freed blocks held the
/// marker.
fn freed_with_marker(f: impl FnOnce()) -> usize {
    HITS.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    f();
    ARMED.store(false, Ordering::Relaxed);
    HITS.load(Ordering::Relaxed)
}

#[test]
fn secrets_do_not_survive_in_freed_memory() {
    // The detector works: a plain Vec holding the marker is caught.
    set_marker(b"crypt-io wipe-on-free marker 001");
    assert!(freed_with_marker(|| drop(b"crypt-io wipe-on-free marker 001".to_vec())) > 0);

    #[cfg(feature = "kdf-hkdf")]
    {
        use crypt_io::kdf;
        let ikm = [0x42u8; 32];
        let mut key = [0u8; MARKER_LEN];
        kdf::hkdf_sha256_into(&ikm, Some(b"salt"), b"wipe test", &mut key).unwrap();
        set_marker(&key);
        // The zeroizing form leaves nothing behind...
        assert_eq!(
            freed_with_marker(|| {
                let k = kdf::hkdf_sha256_zeroizing(&ikm, Some(b"salt"), b"wipe test", 32).unwrap();
                drop(k);
            }),
            0
        );
        // ...where the plain form (documented) does.
        assert!(
            freed_with_marker(|| {
                drop(kdf::hkdf_sha256(&ikm, Some(b"salt"), b"wipe test", 32).unwrap());
            }) > 0
        );
    }

    #[cfg(all(feature = "stream", feature = "aead-chacha20"))]
    {
        use crypt_io::{Algorithm, stream};
        let dir = std::env::temp_dir().join(format!("crypt-io-wipe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (plain, enc, out) = (dir.join("p.bin"), dir.join("p.enc"), dir.join("p.out"));
        let marker = *b"crypt-io file plaintext marker!!";
        set_marker(&marker);
        let mut data = Vec::new();
        for _ in 0..(200 * 1024 / MARKER_LEN) {
            data.extend_from_slice(&marker);
        }
        std::fs::write(&plain, &data).unwrap();
        drop(data);
        let key = [9u8; 32];
        assert_eq!(
            freed_with_marker(|| {
                stream::encrypt_file(&plain, &enc, &key, Algorithm::ChaCha20Poly1305).unwrap();
            }),
            0,
            "encrypt_file freed plaintext unwiped"
        );
        assert_eq!(
            freed_with_marker(|| stream::decrypt_file(&enc, &out, &key).unwrap()),
            0,
            "decrypt_file freed plaintext unwiped"
        );
        assert_eq!(
            std::fs::read(&out).unwrap().len(),
            200 * 1024 / MARKER_LEN * MARKER_LEN
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
