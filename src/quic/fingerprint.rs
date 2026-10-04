// PortRedirect - Certificate fingerprints
//
// A client can trust the server's certificate by its fingerprint instead of a copy of it, see
// --quic-cert-fingerprint. The fingerprint is the SHA-256 hash of the certificate in DER, as
// `sha256sum cert.der` prints it.
//
// License: GPL-3.0-only

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, OtherError, SignatureScheme};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

/// The hash function of fingerprints, as their text starts.
const PREFIX: &str = "sha256:";

/// The fingerprint of a certificate: the SHA-256 hash of its DER encoding. Its text is `sha256:`
/// and 64 hex digits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CertFingerprint([u8; 32]);

impl CertFingerprint {
    /// Returns the fingerprint of `certificate`, given in DER.
    pub fn of(certificate: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, certificate);
        let mut fingerprint = [0; 32];
        fingerprint.copy_from_slice(digest.as_ref());
        Self(fingerprint)
    }
}

impl fmt::Display for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PREFIX)?;
        self.0.iter().try_for_each(|byte| write!(f, "{:02x}", byte))
    }
}

impl fmt::Debug for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for CertFingerprint {
    type Err = String;

    /// Parses `sha256:` and 64 hex digits. The prefix is optional, as `sha256sum` doesn't print
    /// it, and colons may separate the digits, as `openssl x509 -fingerprint` prints them.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || {
            format!(
                "invalid certificate fingerprint {:?}: expected sha256: and 64 hex digits, as the server's --print-quic-cert-fingerprint prints",
                text
            )
        };
        let trimmed = text.trim();
        let hex = match trimmed.get(..PREFIX.len()) {
            Some(prefix) if prefix.eq_ignore_ascii_case(PREFIX) => &trimmed[PREFIX.len()..],
            _ => trimmed,
        };
        let digits: Vec<u8> = hex.bytes().filter(|&byte| byte != b':').collect();
        if digits.len() != 64 {
            return Err(invalid());
        }
        let mut fingerprint = [0; 32];
        for (byte, pair) in fingerprint.iter_mut().zip(digits.chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self(fingerprint))
    }
}

/// Verifies the server by the fingerprint of its certificate: trusts a certificate with one of
/// the given fingerprints, whatever name it is issued for and however long it is valid. As usual,
/// the server must prove in the TLS handshake that it has the certificate's private key.
#[derive(Debug)]
pub struct FingerprintVerifier {
    fingerprints: Vec<CertFingerprint>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl FingerprintVerifier {
    /// Returns a verifier that trusts certificates with the given `fingerprints`.
    pub fn new(fingerprints: Vec<CertFingerprint>) -> Self {
        Self {
            fingerprints,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = CertFingerprint::of(end_entity);
        if self.fingerprints.contains(&fingerprint) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(UnknownFingerprint(fingerprint))),
            )))
        }
    }

    // Not used: rustls is built without TLS 1.2, which QUIC doesn't allow anyway.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The server's certificate has none of the trusted fingerprints.
struct UnknownFingerprint(CertFingerprint);

impl fmt::Display for UnknownFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the server's certificate has the fingerprint {}, which isn't one of --quic-cert-fingerprint",
            self.0
        )
    }
}

// rustls shows this error with Debug, so that shows the message, too.
impl fmt::Debug for UnknownFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for UnknownFingerprint {}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::internal::msgs::codec::{Codec, Reader};

    /// SHA-256 of "abc", from FIPS 180-2.
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn fingerprint(text: &str) -> Result<CertFingerprint, String> {
        text.parse()
    }

    #[test]
    fn test_fingerprint_is_the_sha256_of_the_certificate() {
        let abc = CertFingerprint::of(b"abc");
        assert_eq!(abc.to_string(), format!("sha256:{}", ABC));
        assert_eq!(fingerprint(&abc.to_string()), Ok(abc));
        // Also in debug output, e.g. of a configuration.
        assert_eq!(format!("{:?}", abc), abc.to_string());
    }

    #[test]
    fn test_fingerprints_as_common_tools_print_them_are_accepted() {
        let abc = CertFingerprint::of(b"abc");
        let openssl = ABC
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap().to_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        for text in [
            format!("sha256:{}", ABC),
            // sha256sum
            ABC.to_string(),
            // openssl x509 -fingerprint -sha256
            openssl.clone(),
            format!("SHA256:{}", openssl),
            format!("  sha256:{}\n", ABC),
        ] {
            assert_eq!(fingerprint(&text), Ok(abc), "{:?}", text);
        }
    }

    #[test]
    fn test_invalid_fingerprints_are_rejected() {
        for text in [
            "".to_string(),
            "sha256:".to_string(),
            format!("sha256:{}", &ABC[..62]),
            format!("sha256:{}00", ABC),
            format!("sha256:{}g", &ABC[..63]),
            format!("sha256:{} ", &ABC[..63]),
            format!("sha1:{}", &ABC[..40]),
            format!("md5:{}", ABC),
            format!("sha256 Fingerprint={}", ABC),
            format!("sha256:{}ä", &ABC[..62]),
        ] {
            let err = fingerprint(&text).unwrap_err();
            assert!(
                err.contains("expected sha256: and 64 hex digits"),
                "{:?}: {}",
                text,
                err
            );
        }
    }

    #[test]
    fn test_verifier_trusts_only_certificates_with_its_fingerprints() {
        let trusted = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let verifier = FingerprintVerifier::new(vec![
            CertFingerprint::of(b"abc"),
            CertFingerprint::of(trusted.cert.der()),
        ]);
        let verify = |certificate: &CertificateDer<'_>| {
            verifier.verify_server_cert(
                certificate,
                &[],
                &ServerName::try_from("another-name").unwrap(),
                &[],
                UnixTime::now(),
            )
        };

        // The name doesn't matter, the fingerprint does.
        assert!(verify(trusted.cert.der()).is_ok());
        let err = verify(other.cert.der()).unwrap_err().to_string();
        let expected = CertFingerprint::of(other.cert.der()).to_string();
        assert!(err.contains(&expected), "{}", err);
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    /// Returns the TLS signature of `message` by `key`, an ECDSA P-256 key as rcgen generates.
    fn sign(key: &rcgen::KeyPair, message: &[u8]) -> DigitallySignedStruct {
        let rng = ring::rand::SystemRandom::new();
        let algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let key = ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, &key.serialize_der(), &rng);
        let signature = key.unwrap().sign(&rng, message).unwrap();
        let mut encoded = u16::from(SignatureScheme::ECDSA_NISTP256_SHA256)
            .to_be_bytes()
            .to_vec();
        encoded.extend(
            u16::try_from(signature.as_ref().len())
                .unwrap()
                .to_be_bytes(),
        );
        encoded.extend(signature.as_ref());
        DigitallySignedStruct::read(&mut Reader::init(&encoded)).unwrap()
    }

    #[test]
    fn test_verifier_needs_signatures_by_the_key_of_the_certificate() {
        let trusted = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let verifier = FingerprintVerifier::new(vec![CertFingerprint::of(trusted.cert.der())]);
        let message = b"handshake";
        let valid = sign(&trusted.signing_key, message);
        // E.g. by someone who has a copy of the certificate, but not its key.
        let forged = sign(&other.signing_key, message);
        let certificate = trusted.cert.der();

        assert!(verifier
            .verify_tls13_signature(message, certificate, &valid)
            .is_ok());
        assert!(verifier
            .verify_tls13_signature(message, certificate, &forged)
            .is_err());
        assert!(verifier
            .verify_tls13_signature(b"other", certificate, &valid)
            .is_err());
        assert!(verifier
            .verify_tls12_signature(message, certificate, &valid)
            .is_ok());
        assert!(verifier
            .verify_tls12_signature(message, certificate, &forged)
            .is_err());
    }
}
