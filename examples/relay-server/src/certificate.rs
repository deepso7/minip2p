use std::path::Path;
use std::time::Duration;

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
        "[relay] warning: the WebTransport certificate {state} (not_after={}); renew it and restart the relay",
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
