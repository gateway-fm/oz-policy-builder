//! The delegate key `ozpb dry-run` signs offline-domain requests with.
//!
//! It is read only from a file: never a process argument, never an environment variable. The
//! file must be a regular file owned by the caller with mode exactly 0600, holding one Stellar
//! secret seed (`S…`), and the key must be the spec's delegate. Zeroization is best effort: the
//! file buffer, the decoded seed and the signing key are cleared when dropped, but a value moved
//! by the compiler can leave a stack copy behind. Nothing this module prints or returns contains
//! the secret. File mode and owner are the only access checks: an extended ACL that grants
//! someone else access to a 0600 file is not detected.

// The key file's path is a process argument, and the native worker runs as the caller: a hostile
// worker binary can read the file. The worker must be trusted (see `worker::Worker::new`).

use ed25519_dalek::SigningKey;
use std::fmt;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// A Stellar secret seed is 56 base32 characters; anything longer is refused unread.
const MAX_KEY_FILE_BYTES: u64 = 128;

/// Why a key file was refused. No variant carries any byte of the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyFileError {
    Unreadable,
    NotRegularFile,
    NotOwnedByCaller,
    Permissions { mode: u32 },
    Replaced,
    Malformed,
    NotSpecDelegate { expected: String, found: String },
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable => write!(f, "the delegate key file cannot be read"),
            Self::NotRegularFile => write!(
                f,
                "the delegate key file must be a regular file, not a symlink or other entry"
            ),
            Self::NotOwnedByCaller => {
                write!(f, "the delegate key file must be owned by the current user")
            }
            Self::Permissions { mode } => write!(
                f,
                "the delegate key file must have mode 0600, not {mode:04o}"
            ),
            Self::Replaced => write!(f, "the delegate key file changed while it was opened"),
            Self::Malformed => write!(
                f,
                "the delegate key file must hold exactly one Stellar secret seed (S…)"
            ),
            Self::NotSpecDelegate { expected, found } => write!(
                f,
                "the delegate key file holds the key of {found}, not the spec's delegate {expected}"
            ),
        }
    }
}

impl std::error::Error for KeyFileError {}

/// The spec delegate's signing key. Its `Debug` shows only the public address.
pub struct DelegateKey {
    key: SigningKey,
    address: String,
}

impl fmt::Debug for DelegateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegateKey")
            .field("address", &self.address)
            .field("secret", &format_args!("<withheld>"))
            .finish()
    }
}

impl DelegateKey {
    /// Read the key from `path` and require it to be `expected_delegate`'s.
    pub fn read(path: &Path, expected_delegate: &str) -> Result<Self, KeyFileError> {
        let before = std::fs::symlink_metadata(path).map_err(|_| KeyFileError::Unreadable)?;
        if !before.file_type().is_file() {
            return Err(KeyFileError::NotRegularFile);
        }
        let file = open_private(path)?;
        let opened = file.metadata().map_err(|_| KeyFileError::Unreadable)?;
        check_metadata(&before, &opened)?;
        let mut text = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE_BYTES as usize + 1));
        file.take(MAX_KEY_FILE_BYTES + 1)
            .read_to_end(&mut text)
            .map_err(|_| KeyFileError::Unreadable)?;
        let seed = decode_seed(&text)?;
        let key = SigningKey::from_bytes(&seed.0);
        drop(seed);
        let address = stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes())
            .to_string()
            .as_str()
            .to_owned();
        if address != expected_delegate {
            return Err(KeyFileError::NotSpecDelegate {
                expected: expected_delegate.to_owned(),
                found: address,
            });
        }
        Ok(Self { key, address })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Sign exactly these digest bytes. Callers check what the digest is of.
    pub(super) fn sign(&self, digest: &[u8; 32]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.key.sign(digest).to_bytes()
    }
}

/// Open the key file for reading without following a link and without blocking (a FIFO swapped
/// in after the path check would otherwise wait for a writer forever); the caller still checks
/// what was opened against the path check.
#[cfg(unix)]
fn open_private(path: &Path) -> Result<std::fs::File, KeyFileError> {
    use nix::fcntl::OFlag;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|_| KeyFileError::Unreadable)?;
    if !file
        .metadata()
        .map_err(|_| KeyFileError::Unreadable)?
        .file_type()
        .is_file()
    {
        return Err(KeyFileError::NotRegularFile);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_private(_: &Path) -> Result<std::fs::File, KeyFileError> {
    // Without file modes the file cannot be shown private (see `check_metadata`).
    Err(KeyFileError::Unreadable)
}

#[cfg(unix)]
fn check_metadata(
    before: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<(), KeyFileError> {
    use std::os::unix::fs::MetadataExt;
    if !opened.file_type().is_file() {
        return Err(KeyFileError::NotRegularFile);
    }
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(KeyFileError::Replaced);
    }
    if opened.uid() != nix::unistd::getuid().as_raw() {
        return Err(KeyFileError::NotOwnedByCaller);
    }
    let mode = opened.mode() & 0o7777;
    if mode != 0o600 {
        return Err(KeyFileError::Permissions { mode });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_metadata(_: &std::fs::Metadata, _: &std::fs::Metadata) -> Result<(), KeyFileError> {
    // File modes are a Unix control; without them the file cannot be shown private.
    Err(KeyFileError::Unreadable)
}

/// Decode one `S…` StrKey, with an optional single trailing newline. The StrKey crate zeroes
/// its decoding scratch buffers, and the key it returns zeroizes itself on drop.
fn decode_seed(text: &[u8]) -> Result<stellar_strkey::ed25519::PrivateKey, KeyFileError> {
    let text = text
        .strip_suffix(b"\r\n")
        .or_else(|| text.strip_suffix(b"\n"))
        .unwrap_or(text);
    stellar_strkey::ed25519::PrivateKey::from_slice(text).map_err(|_| KeyFileError::Malformed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A synthetic seed and its StrKey forms; test material only.
    pub(crate) fn seed_strkey(seed: [u8; 32]) -> String {
        stellar_strkey::Unredacted(&stellar_strkey::ed25519::PrivateKey(seed))
            .to_string()
            .as_str()
            .to_owned()
    }

    pub(crate) fn address(seed: [u8; 32]) -> String {
        stellar_strkey::ed25519::PublicKey(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
            .to_string()
            .as_str()
            .to_owned()
    }

    #[cfg(unix)]
    pub(crate) fn key_file(
        dir: &Path,
        name: &str,
        contents: &str,
        mode: u32,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn the_seed_reader_takes_one_seed_and_refuses_damage() {
        for seed in [[0u8; 32], [42; 32], [0xff; 32]] {
            let text = seed_strkey(seed);
            assert_eq!(decode_seed(text.as_bytes()).unwrap().0, seed);
            assert_eq!(decode_seed(format!("{text}\n").as_bytes()).unwrap().0, seed);
            let mut damaged = text.clone().into_bytes();
            damaged[20] = if damaged[20] == b'A' { b'B' } else { b'A' };
            assert_eq!(decode_seed(&damaged).unwrap_err(), KeyFileError::Malformed);
        }
        let public = address([42; 32]);
        for bad in [
            public.as_str(),
            "",
            "S",
            &format!("{}\n\n", seed_strkey([1; 32])),
            &format!(" {}", seed_strkey([1; 32])),
        ] {
            assert_eq!(
                decode_seed(bad.as_bytes()).unwrap_err(),
                KeyFileError::Malformed
            );
        }
    }

    /// The window between the path check and the open: whatever is at the path by then, the
    /// open neither blocks (a FIFO with no writer) nor follows a link.
    #[cfg(unix)]
    #[test]
    fn the_key_file_open_neither_blocks_on_a_fifo_nor_follows_a_link() {
        use nix::sys::stat::Mode;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("key.fifo");
        nix::unistd::mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(open_private(&fifo).map(|_| ()));
        });
        let opened = finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("opening a FIFO must not block");
        assert_eq!(opened.unwrap_err(), KeyFileError::NotRegularFile);
        let real = key_file(dir.path(), "real.key", &seed_strkey([42; 32]), 0o600);
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_private(&link).is_err(), "a link is not followed");
        assert!(open_private(&real).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_refuses_key_file_not_0600_or_not_spec_delegate() {
        let dir = tempfile::tempdir().unwrap();
        let secret = seed_strkey([42; 32]);
        let delegate = address([42; 32]);
        let good = key_file(dir.path(), "delegate.key", &format!("{secret}\n"), 0o600);
        let key =
            DelegateKey::read(&good, &delegate).expect("a private file with the delegate's key");
        assert_eq!(key.address(), delegate);

        for mode in [0o644, 0o640, 0o604, 0o700, 0o400, 0o4600] {
            let path = key_file(dir.path(), &format!("mode-{mode:o}.key"), &secret, mode);
            assert_eq!(
                DelegateKey::read(&path, &delegate).unwrap_err(),
                KeyFileError::Permissions { mode },
                "mode {mode:o}"
            );
        }
        let other = address([7; 32]);
        assert_eq!(
            DelegateKey::read(&good, &other).unwrap_err(),
            KeyFileError::NotSpecDelegate {
                expected: other,
                found: delegate.clone(),
            }
        );
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert_eq!(
            DelegateKey::read(&link, &delegate).unwrap_err(),
            KeyFileError::NotRegularFile
        );
        assert_eq!(
            DelegateKey::read(dir.path(), &delegate).unwrap_err(),
            KeyFileError::NotRegularFile
        );
        let two = key_file(
            dir.path(),
            "two.key",
            &format!("{secret}\n{}\n", seed_strkey([1; 32])),
            0o600,
        );
        assert_eq!(
            DelegateKey::read(&two, &delegate).unwrap_err(),
            KeyFileError::Malformed
        );
        let public = key_file(dir.path(), "public.key", &delegate, 0o600);
        assert_eq!(
            DelegateKey::read(&public, &delegate).unwrap_err(),
            KeyFileError::Malformed
        );
        assert_eq!(
            DelegateKey::read(&dir.path().join("absent.key"), &delegate).unwrap_err(),
            KeyFileError::Unreadable
        );
    }
}
