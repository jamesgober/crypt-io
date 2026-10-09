//! File-level helpers built on top of [`super::StreamEncryptor`] /
//! [`super::StreamDecryptor`].
//!
//! These functions exist for the common "encrypt this file into that
//! file" workflow. For finer control (custom chunk size, hooking into
//! a different I/O type, processing bytes from a network socket),
//! drive the streaming types directly.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

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
/// `input_path` and `output_path` must not name the same file (after
/// resolving symlinks and `..`): that would truncate the input before
/// it is read. The call is rejected with [`Error::InvalidInput`]
/// instead.
///
/// The file is written in stream format v2, so each file gets its own
/// subkey and one key can encrypt any number of files. Readers on
/// crypt-io 1.0.x cannot read v2; drive
/// [`StreamEncryptor::new_with_format`](super::StreamEncryptor::new_with_format)
/// with [`StreamFormat::V1`](super::StreamFormat::V1) if they must.
///
/// # Errors
///
/// - [`Error::InvalidKey`] if `key` is not 32 bytes.
/// - [`Error::RandomFailure`] if the OS RNG cannot produce a nonce.
/// - [`Error::Io`] for I/O failures (file open, read, write). The
///   variant carries a `&'static str` naming the step; the underlying
///   `std::io::Error` is not surfaced (it could leak path fragments
///   through error rendering). 1.0.x reported these as [`Error::Mac`].
/// - [`Error::InvalidInput`] when input and output are the same file.
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
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();
    let input = File::open(input_path).map_err(|_| Error::Io("stream: open input"))?;
    reject_same_file(input_path, output_path)?;
    // Validate the key (and draw the nonce prefix) before touching the
    // output path.
    let (mut enc, header) = StreamEncryptor::new(key, algorithm)?;
    let output = File::create(output_path).map_err(|_| Error::Io("stream: create output"))?;
    let mut reader = BufReader::with_capacity(IO_BUFFER_LEN, input);
    let mut writer = BufWriter::with_capacity(IO_BUFFER_LEN, output);

    writer
        .write_all(&header)
        .map_err(|_| Error::Io("stream: write header"))?;

    let mut io_buf = alloc::vec![0u8; IO_BUFFER_LEN];
    loop {
        let n = reader
            .read(&mut io_buf)
            .map_err(|_| Error::Io("stream: read input"))?;
        if n == 0 {
            break;
        }
        let encrypted = enc.update(&io_buf[..n])?;
        writer
            .write_all(&encrypted)
            .map_err(|_| Error::Io("stream: write chunk"))?;
    }

    let tail = enc.finalize()?;
    writer
        .write_all(&tail)
        .map_err(|_| Error::Io("stream: write final chunk"))?;
    writer
        .flush()
        .map_err(|_| Error::Io("stream: flush output"))?;
    Ok(())
}

/// Decrypt the file at `input_path` into `output_path` using `key`. The
/// algorithm is read from the stream's header.
///
/// Plaintext is never written to `output_path` until the whole stream,
/// including its final chunk, has been authenticated:
///
/// 1. Plaintext goes to a new temporary file in the same directory as
///    `output_path` (created exclusively, mode `0600` on Unix).
/// 2. After the final chunk verifies, the temporary file is flushed,
///    `fsync`ed and renamed over `output_path`.
/// 3. On any error the temporary file is overwritten with zeros
///    (best effort), deleted, and `output_path` is left untouched.
///
/// On Unix the resulting file therefore has mode `0600`; change it
/// afterwards if it should be readable by others.
///
/// `input_path` and `output_path` must not name the same file; that is
/// rejected with [`Error::InvalidInput`].
///
/// Files in either stream format (v1 from crypt-io 1.0.x, v2 from 1.1)
/// are accepted.
///
/// # Errors
///
/// - [`Error::InvalidKey`] if `key` is not 32 bytes.
/// - [`Error::InvalidCiphertext`] if the header is malformed or the
///   stream is truncated below the minimum frame (header + tag).
/// - [`Error::Io`] for I/O failures (1.0.x: [`Error::Mac`]).
/// - [`Error::InvalidInput`] when input and output are the same file.
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
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();
    let input = File::open(input_path).map_err(|_| Error::Io("stream: open input"))?;
    reject_same_file(input_path, output_path)?;
    let mut reader = BufReader::with_capacity(IO_BUFFER_LEN, input);

    // Parse the header and check the key before creating anything.
    let mut header = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .map_err(|_| Error::Io("stream: read header"))?;
    let dec = StreamDecryptor::new(key, &header)?;

    let (tmp_path, tmp_file) = create_temp_beside(output_path)?;
    match decrypt_body(dec, &mut reader, tmp_file) {
        Ok(()) => {
            if fs::rename(&tmp_path, output_path).is_err() {
                discard_temp(&tmp_path);
                return Err(Error::Io("stream: rename output"));
            }
            sync_parent_dir(output_path);
            Ok(())
        }
        Err(e) => {
            discard_temp(&tmp_path);
            Err(e)
        }
    }
}

/// Decrypt everything after the header from `reader` into `file`, then
/// flush and `fsync` it. The file is only complete when this returns
/// `Ok`.
fn decrypt_body(mut dec: StreamDecryptor, reader: &mut impl Read, file: File) -> Result<()> {
    let mut writer = BufWriter::with_capacity(IO_BUFFER_LEN, file);
    let mut io_buf = alloc::vec![0u8; IO_BUFFER_LEN];
    let mut plaintext = alloc::vec::Vec::with_capacity(IO_BUFFER_LEN + dec.chunk_size());
    let result = (|| {
        loop {
            let n = reader
                .read(&mut io_buf)
                .map_err(|_| Error::Io("stream: read input"))?;
            if n == 0 {
                break;
            }
            plaintext.clear();
            dec.update_into(&io_buf[..n], &mut plaintext)?;
            writer
                .write_all(&plaintext)
                .map_err(|_| Error::Io("stream: write plaintext"))?;
        }
        plaintext.clear();
        dec.finalize_into(&mut plaintext)?;
        writer
            .write_all(&plaintext)
            .map_err(|_| Error::Io("stream: write final plaintext"))?;
        let file = writer
            .into_inner()
            .map_err(|_| Error::Io("stream: flush output"))?;
        file.sync_all()
            .map_err(|_| Error::Io("stream: sync output"))
    })();
    crate::wipe::wipe_vec(&mut plaintext);
    result
}

/// Reject `input == output` (compared after canonicalisation, so
/// symlinks and `..` components are resolved). `input` must exist.
fn reject_same_file(input: &Path, output: &Path) -> Result<()> {
    let Ok(input_canon) = fs::canonicalize(input) else {
        // Caller already opened `input`; if it cannot be resolved now
        // there is nothing to compare against.
        return Ok(());
    };
    let output_canon = match fs::canonicalize(output) {
        Ok(p) => Some(p),
        // Output does not exist yet: resolve its directory instead.
        Err(_) => match (output.parent(), output.file_name()) {
            (Some(parent), Some(name)) => {
                let parent = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
                fs::canonicalize(parent).ok().map(|d| d.join(name))
            }
            _ => None,
        },
    };
    if output_canon.as_deref() == Some(input_canon.as_path()) {
        return Err(Error::InvalidInput(
            "stream: input and output are the same file",
        ));
    }
    Ok(())
}

/// Create a new, empty temporary file next to `output` (same
/// directory, so the final `rename` stays on one filesystem). Created
/// with `create_new` so an existing file is never reused, and with mode
/// `0600` on Unix.
fn create_temp_beside(output: &Path) -> Result<(PathBuf, File)> {
    let dir = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let base = output
        .file_name()
        .ok_or(Error::InvalidInput("stream: output path has no file name"))?
        .to_string_lossy();
    for _ in 0..8 {
        let mut rnd = [0u8; 8];
        crate::rng::fill(&mut rnd)?;
        let suffix = u64::from_le_bytes(rnd);
        let path = dir.join(alloc::format!(".{base}.{suffix:016x}.crypt-io-tmp"));

        let mut opts = OpenOptions::new();
        let _ = opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Error::Io("stream: create temporary output")),
        }
    }
    Err(Error::Io("stream: create temporary output"))
}

/// Best-effort removal of a temporary file that may hold verified
/// plaintext from earlier chunks: overwrite it with zeros, then delete
/// it.
fn discard_temp(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
            let zeros = alloc::vec![0u8; IO_BUFFER_LEN];
            let mut left = meta.len();
            while left > 0 {
                let n = usize::try_from(left).map_or(IO_BUFFER_LEN, |l| l.min(IO_BUFFER_LEN));
                if f.write_all(&zeros[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
            let _ = f.sync_all();
        }
    }
    let _ = fs::remove_file(path);
}

/// On Unix, `fsync` the directory holding `path` so the rename itself
/// is durable. Best effort; a no-op elsewhere.
fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
