// PortRedirect Protocol Module - Authentication
//
// Both sides prove that they know the pre-shared key (PSK), bound to the TLS session:
// - The client trusts the server because the server has the certificate the client pins.
//   Additionally, the server proves that it knows the PSK, so a leaked certificate key alone
//   doesn't let anyone impersonate the server.
// - Anyone can connect to the server, so the client proves its knowledge first. Otherwise, any
//   client could collect proofs from the server and try to guess the PSK offline.
// - A proof is an HMAC-SHA256 tag, keyed with the PSK, over a label, keying material exported
//   from the TLS session and a random nonce chosen by the server. The keying material is unique
//   to the TLS session, so a proof is worthless in any other session, e.g. when relayed or
//   replayed. The labels differ, so a client proof can't serve as server proof or vice versa.
// - Proofs are verified in constant time.
//
// The message formats are described in docs/PROTOCOL.md.
//
// License: GPL-3.0-only

use anyhow::{anyhow, Context, Result};
use ring::hmac;
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Label for exporting the keying material that binds the authentication to the TLS session.
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-portredirect-v3-authentication";

/// Length of the keying material exported from the TLS session.
pub const SESSION_BINDING_LENGTH: usize = 32;

/// Keying material exported from the TLS session.
pub type SessionBinding = [u8; SESSION_BINDING_LENGTH];

const CHALLENGE_HEADER: &[u8; 9] = b"CHALLENGE";
const RESPONSE_HEADER: &[u8; 8] = b"RESPONSE";
const ACCEPTED_HEADER: &[u8; 8] = b"ACCEPTED";
const NONCE_LENGTH: usize = 32;
const PROOF_LENGTH: usize = 32;
const CLIENT_PROOF_LABEL: &[u8] = b"portredirect v3 client proof";
const SERVER_PROOF_LABEL: &[u8] = b"portredirect v3 server proof";

type Nonce = [u8; NONCE_LENGTH];

/// The peer failed to prove that it knows the PSK: the PSKs of client and server differ.
#[derive(Debug)]
pub struct AuthenticationRejected(pub String);

impl std::fmt::Display for AuthenticationRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "authentication rejected: {}", self.0)
    }
}

impl std::error::Error for AuthenticationRejected {}

/// Returns keying material unique to the TLS session of `connection`, see [`TLS_EXPORTER_LABEL`].
pub fn session_binding(connection: &quinn::Connection) -> Result<SessionBinding> {
    let mut binding = [0u8; SESSION_BINDING_LENGTH];
    connection
        .export_keying_material(&mut binding, TLS_EXPORTER_LABEL, b"")
        .map_err(|e| {
            anyhow!(
                "failed to export keying material from the TLS session: {:?}",
                e
            )
        })?;
    Ok(binding)
}

/// Server-side authentication: sends a challenge, verifies the client's proof and proves its own
/// knowledge of the PSK.
///
/// Fails with [`AuthenticationRejected`] if the client's proof is wrong. The caller should then
/// close the connection.
pub async fn server_authenticate<S>(
    stream: &mut S,
    psk: &SecretString,
    session_binding: &SessionBinding,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Send the challenge.
    let mut nonce: Nonce = [0u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("failed to get random bytes: {}", e))?;
    send(stream, CHALLENGE_HEADER, &nonce)
        .await
        .context("failed to send challenge")?;

    // 2. Verify the client's proof.
    let client_proof: [u8; PROOF_LENGTH] = receive(stream, RESPONSE_HEADER)
        .await
        .context("failed to receive response")?;
    if !verify(
        psk,
        CLIENT_PROOF_LABEL,
        session_binding,
        &nonce,
        &client_proof,
    ) {
        return Err(AuthenticationRejected("the client's proof is wrong".into()).into());
    }

    // 3. Prove our knowledge of the PSK.
    let server_proof = sign(psk, SERVER_PROOF_LABEL, session_binding, &nonce);
    send(stream, ACCEPTED_HEADER, server_proof.as_ref())
        .await
        .context("failed to send acceptance")?;
    Ok(())
}

/// Client-side authentication: answers the server's challenge with a proof of knowledge of the
/// PSK and verifies the server's proof.
///
/// Fails with [`AuthenticationRejected`] if the server's proof is wrong. If the server rejects
/// the client's proof, it closes the connection, so reading its answer fails.
pub async fn client_authenticate<S>(
    stream: &mut S,
    psk: &SecretString,
    session_binding: &SessionBinding,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Receive the challenge and prove our knowledge of the PSK.
    let nonce: Nonce = receive(stream, CHALLENGE_HEADER)
        .await
        .context("failed to receive challenge")?;
    let client_proof = sign(psk, CLIENT_PROOF_LABEL, session_binding, &nonce);
    send(stream, RESPONSE_HEADER, client_proof.as_ref())
        .await
        .context("failed to send response")?;

    // 2. Verify the server's proof.
    let server_proof: [u8; PROOF_LENGTH] = receive(stream, ACCEPTED_HEADER)
        .await
        .context("failed to receive acceptance")?;
    if !verify(
        psk,
        SERVER_PROOF_LABEL,
        session_binding,
        &nonce,
        &server_proof,
    ) {
        return Err(AuthenticationRejected(
            "the server could not prove that it knows the PSK".into(),
        )
        .into());
    }
    Ok(())
}

/// Returns the proof for `label`, i.e. HMAC-SHA256 with the PSK as key over
/// `label || session_binding || nonce`.
fn sign(
    psk: &SecretString,
    label: &[u8],
    session_binding: &SessionBinding,
    nonce: &Nonce,
) -> hmac::Tag {
    hmac::sign(&proof_key(psk), &proof_input(label, session_binding, nonce))
}

/// Verifies a proof in constant time.
fn verify(
    psk: &SecretString,
    label: &[u8],
    session_binding: &SessionBinding,
    nonce: &Nonce,
    proof: &[u8],
) -> bool {
    hmac::verify(
        &proof_key(psk),
        &proof_input(label, session_binding, nonce),
        proof,
    )
    .is_ok()
}

fn proof_key(psk: &SecretString) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, psk.expose_secret().as_bytes())
}

fn proof_input(label: &[u8], session_binding: &SessionBinding, nonce: &Nonce) -> Vec<u8> {
    [label, session_binding, nonce].concat()
}

/// Sends a message consisting of a fixed header and a fixed-size payload.
async fn send<S: AsyncWrite + Unpin>(stream: &mut S, header: &[u8], payload: &[u8]) -> Result<()> {
    stream.write_all(&[header, payload].concat()).await?;
    stream.flush().await?;
    Ok(())
}

/// Receives a message consisting of the expected `header` and an `N` bytes payload.
async fn receive<S: AsyncRead + Unpin, const N: usize>(
    stream: &mut S,
    header: &[u8],
) -> Result<[u8; N]> {
    let mut received_header = vec![0u8; header.len()];
    stream.read_exact(&mut received_header).await?;
    if received_header != header {
        return Err(anyhow!(
            "expected {:?}, got {:?}",
            String::from_utf8_lossy(header),
            String::from_utf8_lossy(&received_header)
        ));
    }
    let mut payload = [0u8; N];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, DuplexStream};

    const BINDING: SessionBinding = [7u8; SESSION_BINDING_LENGTH];

    /// Runs server and client authentication against each other.
    async fn authenticate(
        server_psk: &str,
        server_binding: SessionBinding,
        client_psk: &str,
        client_binding: SessionBinding,
    ) -> (Result<()>, Result<()>) {
        let (mut client_side, mut server_side) = duplex(1024);
        let server_psk = SecretString::from(server_psk);
        let client_psk = SecretString::from(client_psk);

        let server = tokio::spawn(async move {
            let result = server_authenticate(&mut server_side, &server_psk, &server_binding).await;
            // Like the real server, close the connection after a failure.
            drop(server_side);
            result
        });
        let client = tokio::spawn(async move {
            client_authenticate(&mut client_side, &client_psk, &client_binding).await
        });

        (
            server.await.expect("server task panicked"),
            client.await.expect("client task panicked"),
        )
    }

    #[tokio::test]
    async fn test_authentication_succeeds_with_same_psk() {
        let (server, client) = authenticate("test-secret", BINDING, "test-secret", BINDING).await;
        server.unwrap();
        client.unwrap();
    }

    #[tokio::test]
    async fn test_server_rejects_wrong_psk() {
        let (server, client) =
            authenticate("test-secret", BINDING, "another-secret", BINDING).await;

        let server_err = server.unwrap_err();
        assert!(
            server_err.is::<AuthenticationRejected>(),
            "{:#}",
            server_err
        );
        // The server sends nothing more, so the client can't read the acceptance.
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn test_proofs_are_bound_to_the_tls_session() {
        // E.g. a client proof relayed into another TLS session.
        let (server, client) = authenticate("test-secret", BINDING, "test-secret", [8u8; 32]).await;

        assert!(server.unwrap_err().is::<AuthenticationRejected>());
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn test_client_rejects_server_without_psk() {
        // A server that has the certificate key but not the PSK can't send a valid proof.
        let (mut client_side, mut fake_server) = duplex(1024);
        let fake = tokio::spawn(async move {
            send(&mut fake_server, CHALLENGE_HEADER, &[1u8; NONCE_LENGTH]).await?;
            let _client_proof: [u8; PROOF_LENGTH] =
                receive(&mut fake_server, RESPONSE_HEADER).await?;
            send(&mut fake_server, ACCEPTED_HEADER, &[0u8; PROOF_LENGTH]).await?;
            Ok::<_, anyhow::Error>(fake_server)
        });

        let psk = SecretString::from("test-secret");
        let result = client_authenticate(&mut client_side, &psk, &BINDING).await;

        let err = result.unwrap_err();
        assert!(err.is::<AuthenticationRejected>(), "{:#}", err);
        fake.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_unexpected_messages_are_rejected() {
        let psk = SecretString::from("test-secret");

        // The client expects a challenge.
        let (mut client_side, mut server_side) = duplex(1024);
        server_side
            .write_all(b"HELLO WORLD, LET ME IN")
            .await
            .unwrap();
        let err = client_authenticate(&mut client_side, &psk, &BINDING)
            .await
            .unwrap_err();
        assert!(format!("{:#}", err).contains("expected \"CHALLENGE\""));

        // The server expects a response.
        let (mut client_side, mut server_side): (DuplexStream, DuplexStream) = duplex(1024);
        let server =
            tokio::spawn(
                async move { server_authenticate(&mut server_side, &psk, &BINDING).await },
            );
        let mut challenge = [0u8; CHALLENGE_HEADER.len() + NONCE_LENGTH];
        client_side.read_exact(&mut challenge).await.unwrap();
        client_side.write_all(&[b'X'; 40]).await.unwrap();
        let err = server.await.unwrap().unwrap_err();
        assert!(format!("{:#}", err).contains("expected \"RESPONSE\""));
    }

    #[test]
    fn test_proofs_match_reference_values() {
        // Computed independently with Python's hmac module, see docs/PROTOCOL.md for the format.
        let psk = SecretString::from("test-psk");
        let binding: SessionBinding = std::array::from_fn(|i| i as u8);
        let nonce: Nonce = std::array::from_fn(|i| 32 + i as u8);

        let client_proof = sign(&psk, CLIENT_PROOF_LABEL, &binding, &nonce);
        let server_proof = sign(&psk, SERVER_PROOF_LABEL, &binding, &nonce);

        assert_eq!(
            hex(client_proof.as_ref()),
            "d9183d723457d964b08ee797ee6f8e8d9555c3bcb88cf4aed96c597ac50dbfe1"
        );
        assert_eq!(
            hex(server_proof.as_ref()),
            "3e3e8adcd46b77001d02198f2981a38f0b57ada39b2e42588844a42b82b24139"
        );
    }

    #[test]
    fn test_client_proof_is_no_server_proof() {
        let psk = SecretString::from("test-secret");
        let nonce = [3u8; NONCE_LENGTH];
        let client_proof = sign(&psk, CLIENT_PROOF_LABEL, &BINDING, &nonce);
        assert!(!verify(
            &psk,
            SERVER_PROOF_LABEL,
            &BINDING,
            &nonce,
            client_proof.as_ref()
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
