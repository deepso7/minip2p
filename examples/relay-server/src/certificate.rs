use std::path::Path;
use std::time::{Duration, SystemTime};

use minip2p_tls::Validity;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;

use crate::cli::CertificatePaths;

/// How close to expiry the served leaf must be before the relay warns.
const EXPIRY_WARNING: Duration = Duration::from_secs(14 * 24 * 60 * 60);

/// A CA-signed WebTransport certificate read from the operator's files.
pub struct Certificate {
    pub chain_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// The leaf's validity window, for logging and the expiry warning.
    pub validity: Validity,
}

/// Reads both files and the leaf's validity; every error names its path.
/// The Endpoint builder checks the rest (key, chain) when it parses them.
pub fn load(paths: &CertificatePaths) -> Result<Certificate, String> {
    let read = |flag: &str, path: &Path| {
        std::fs::read(path)
            .map_err(|error| format!("cannot read {flag} {}: {error}", path.display()))
    };
    let chain_pem = read("--webtransport-cert", &paths.chain)?;
    let key_pem = read("--webtransport-key", &paths.key)?;
    let invalid =
        |problem: String| format!("--webtransport-cert {}: {problem}", paths.chain.display());
    let leaf = CertificateDer::pem_slice_iter(&chain_pem)
        .next()
        .ok_or_else(|| invalid("no `BEGIN CERTIFICATE` section".into()))?
        .map_err(|error| invalid(error.to_string()))?;
    let validity =
        minip2p_tls::certificate_validity(&leaf).map_err(|error| invalid(error.to_string()))?;
    Ok(Certificate {
        chain_pem,
        key_pem,
        validity,
    })
}

/// The certificate files' modification times, to notice a renewal.
///
/// The relay polls this and serves what [`Watched::poll`] loads; a failed
/// load is not retried until a file changes again, so a broken file logs once.
pub struct Watched {
    pub paths: CertificatePaths,
    mtimes: [Option<SystemTime>; 2],
}

impl Watched {
    /// Records the files' current modification times; create it before the
    /// first [`load`] so a change in between is noticed.
    pub fn new(paths: CertificatePaths) -> Self {
        let mtimes = modified(&paths);
        Self { paths, mtimes }
    }

    /// Reloads both files when either's modification time changed since the
    /// last attempt, or returns `None` while neither has.
    pub fn poll(&mut self) -> Option<Result<Certificate, String>> {
        let mtimes = modified(&self.paths);
        if mtimes == self.mtimes {
            return None;
        }
        self.mtimes = mtimes;
        Some(load(&self.paths))
    }
}

/// Both files' modification times; `None` for one that can't be read, so
/// its reappearance counts as a change.
fn modified(paths: &CertificatePaths) -> [Option<SystemTime>; 2] {
    [&paths.chain, &paths.key].map(|path| {
        std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
    })
}

/// The warning to log when fewer than 14 days are left at `now` (since the
/// Unix epoch), or `None` while the leaf has longer.
pub fn expiry_warning(validity: &Validity, now: Duration) -> Option<String> {
    let not_after = validity.not_after.to_unix_duration();
    let state = match not_after.checked_sub(now) {
        Some(left) if left >= EXPIRY_WARNING => return None,
        Some(left) => format!("expires in {} days", left.as_secs() / (24 * 60 * 60)),
        None => "has expired".into(),
    };
    Some(format!(
        "[relay] warning: the WebTransport certificate {state} (not_after={}); renew it",
        validity.not_after
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warns_only_inside_the_last_fourteen_days() {
        let paths = CertificatePaths {
            chain: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../transports/quic/tests/fixtures/ca/localhost.pem"
            )
            .into(),
            key: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../transports/quic/tests/fixtures/ca/localhost.key"
            )
            .into(),
        };
        let validity = load(&paths).unwrap().validity;
        let not_after = validity.not_after.to_unix_duration();
        let day = Duration::from_secs(24 * 60 * 60);

        assert_eq!(
            expiry_warning(&validity, not_after.checked_sub(14 * day).unwrap()),
            None
        );
        let warning = expiry_warning(&validity, not_after.checked_sub(13 * day).unwrap()).unwrap();
        assert!(warning.contains("expires in 13 days"), "{warning}");
        let warning = expiry_warning(&validity, not_after + day).unwrap();
        assert!(warning.contains("has expired"), "{warning}");
    }

    #[test]
    fn reloads_once_per_change_of_either_file() {
        let fixture = |name: &str| {
            std::fs::read(format!(
                "{}/../../transports/quic/tests/fixtures/ca/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap()
        };
        let dir = tempfile::tempdir().unwrap();
        let paths = CertificatePaths {
            chain: dir.path().join("fullchain.pem"),
            key: dir.path().join("privkey.pem"),
        };
        // Explicit times: a filesystem's mtime granularity can hide a rewrite.
        let write = |path: &Path, contents: &[u8], secs: u64| {
            std::fs::write(path, contents).unwrap();
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
                .unwrap();
        };
        write(&paths.chain, &fixture("chain.pem"), 1);
        write(&paths.key, &fixture("chain.key"), 1);
        let mut watched = Watched::new(paths);
        assert!(watched.poll().is_none());

        write(&watched.paths.chain, b"not a certificate", 2);
        assert!(watched.poll().unwrap().is_err());
        assert!(watched.poll().is_none(), "a failed load waits for a change");

        write(&watched.paths.chain, &fixture("localhost.pem"), 3);
        watched.poll().unwrap().unwrap();
        write(&watched.paths.key, &fixture("localhost.key"), 3);
        watched.poll().unwrap().unwrap();
        assert!(watched.poll().is_none());
    }

    #[test]
    fn errors_name_the_unreadable_path() {
        let paths = CertificatePaths {
            chain: "/nonexistent/fullchain.pem".into(),
            key: "/nonexistent/privkey.pem".into(),
        };
        let error = load(&paths).err().unwrap();
        assert!(
            error.contains("--webtransport-cert /nonexistent/fullchain.pem"),
            "{error}"
        );
    }
}
