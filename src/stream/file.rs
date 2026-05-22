//! File-level helpers built on top of [`super::StreamEncryptor`] /
//! [`super::StreamDecryptor`].
//!
//! These functions exist for the common "encrypt this file into that
//! file" workflow. For finer control (custom chunk size, hooking into
//! a different I/O type, processing bytes from a network socket),
//! drive the streaming types directly.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use crate::aead::Algorithm;
use crate::error::{Error, Result};

use super::frame::HEADER_LEN;
use super::{StreamDecryptor, StreamEncryptor};

/// I/O read buffer for `encrypt_file` / `decrypt_file`. Sized at 64 KiB
/// to match the default chunk size — minimises syscall overhead.
const IO_BUFFER_LEN: usize = 64 * 1024;

/// Encrypt the file at `input_path` into `output_path` using `key` and
/// the given AEAD `algorithm`. Uses the default chunk size (64 KiB).
///
/// The output file is overwritten if it already exists. On any failure
/// after the output file has been opened, callers should treat the
/// output file as junk and remove it.
///
/// # Errors
///
/// - [`Error::InvalidKey`] if `key` is not 32 bytes.
/// - [`Error::RandomFailure`] if the OS RNG cannot produce a nonce.
/// - [`Error::Mac`] for I/O failures (file open, read, write) — the
///   variant carries a `&'static str` reason; the underlying
///   `std::io::Error` is not surfaced (would risk leaking path
///   fragments through error rendering).
/// - [`Error::AuthenticationFailed`] for the (unreachable in
///   practice) AEAD failure path.
///
/// # Example
///
/// ```no_run
/// # #[cfg(all(feature = "stream", feature = "aead-chacha20"))] {
/// use crypt_io::Algorithm;
/// use crypt_io::stream;
///
/// let key = [0u8; 32];
/// stream::encrypt_file("input.bin", "output.enc", &key, Algorithm::ChaCha20Poly1305)?;
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn encrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    key: &[u8],
    algorithm: Algorithm,
) -> Result<()> {
    let input = File::open(input_path.as_ref()).map_err(|_| Error::Mac("stream: open input"))?;
    let output =
        File::create(output_path.as_ref()).map_err(|_| Error::Mac("stream: create output"))?;
    let mut reader = BufReader::with_capacity(IO_BUFFER_LEN, input);
    let mut writer = BufWriter::with_capacity(IO_BUFFER_LEN, output);

    let (mut enc, header) = StreamEncryptor::new(key, algorithm)?;
    writer
        .write_all(&header)
        .map_err(|_| Error::Mac("stream: write header"))?;

    let mut io_buf = alloc::vec![0u8; IO_BUFFER_LEN];
    loop {
        let n = reader
            .read(&mut io_buf)
            .map_err(|_| Error::Mac("stream: read input"))?;
        if n == 0 {
            break;
        }
        let encrypted = enc.update(&io_buf[..n])?;
        writer
            .write_all(&encrypted)
            .map_err(|_| Error::Mac("stream: write chunk"))?;
    }

    let tail = enc.finalize()?;
    writer
        .write_all(&tail)
        .map_err(|_| Error::Mac("stream: write final chunk"))?;
    writer
        .flush()
        .map_err(|_| Error::Mac("stream: flush output"))?;
    Ok(())
}

/// Decrypt the file at `input_path` into `output_path` using `key`. The
/// algorithm is read from the stream's header.
///
/// On authentication failure the output file may contain partially-
/// decrypted plaintext from earlier chunks. **Callers must delete the
/// output file when this function returns an error** — otherwise an
/// attacker who can flip later chunks could leak earlier plaintext to
/// disk.
///
/// # Errors
///
/// - [`Error::InvalidKey`] if `key` is not 32 bytes.
/// - [`Error::InvalidCiphertext`] if the header is malformed or the
///   stream is truncated below the minimum frame (header + tag).
/// - [`Error::Mac`] for I/O failures.
/// - [`Error::AuthenticationFailed`] for any cryptographic failure.
///
/// # Example
///
/// ```no_run
/// # #[cfg(all(feature = "stream", feature = "aead-chacha20"))] {
/// use crypt_io::stream;
///
/// let key = [0u8; 32];
/// stream::decrypt_file("input.enc", "output.bin", &key)?;
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    key: &[u8],
) -> Result<()> {
    let input = File::open(input_path.as_ref()).map_err(|_| Error::Mac("stream: open input"))?;
    let output =
        File::create(output_path.as_ref()).map_err(|_| Error::Mac("stream: create output"))?;
    let mut reader = BufReader::with_capacity(IO_BUFFER_LEN, input);
    let mut writer = BufWriter::with_capacity(IO_BUFFER_LEN, output);

    let mut header = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .map_err(|_| Error::Mac("stream: read header"))?;

    let mut dec = StreamDecryptor::new(key, &header)?;
    let mut io_buf = alloc::vec![0u8; IO_BUFFER_LEN];
    loop {
        let n = reader
            .read(&mut io_buf)
            .map_err(|_| Error::Mac("stream: read input"))?;
        if n == 0 {
            break;
        }
        let plaintext = dec.update(&io_buf[..n])?;
        writer
            .write_all(&plaintext)
            .map_err(|_| Error::Mac("stream: write plaintext"))?;
    }

    let tail = dec.finalize()?;
    writer
        .write_all(&tail)
        .map_err(|_| Error::Mac("stream: write final plaintext"))?;
    writer
        .flush()
        .map_err(|_| Error::Mac("stream: flush output"))?;
    Ok(())
}
