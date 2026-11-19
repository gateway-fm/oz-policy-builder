//! The delegate key `ozpb dry-run` signs offline-domain requests with: a private key file
//! ([`crate::key_file`]) whose key must be the spec's delegate.

// The key file's path is a process argument, and the native worker runs as the caller: a hostile
// worker binary can read the file. The worker must be trusted (see `worker::Worker::new`).

use crate::key_file::{read_signing_key, KeyFileError};
use ed25519_dalek::SigningKey;
use std::fmt;
use std::path::Path;

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
        let key = read_signing_key(path)?;
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::key_file::tests::{address, key_file, seed_strkey};

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
