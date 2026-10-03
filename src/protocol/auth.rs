// PortRedirect Protocol Module - Authentication
//
// Both sides prove that they know the client's pre-shared key (PSK), bound to the TLS session:
// - The client names itself, so the server knows which PSK to check and which ports the client
//   may use. The name travels inside TLS, so only the server sees it.
// - The client trusts the server because the server has the certificate the client pins.
//   Additionally, the server proves that it knows the PSK, so a leaked certificate key alone
//   doesn't let anyone impersonate the server.
// - Anyone can connect to the server, so the client proves its knowledge first. Otherwise, any
//   client could collect proofs from the server and try to guess the PSK offline.
// - A proof is an HMAC-SHA256 tag, keyed with the PSK, over a label, keying material exported
//   from the TLS session, a random nonce chosen by the server and the client's name. The keying
//   material is unique to the TLS session, so a proof is worthless in any other session, e.g.
//   when relayed or replayed. The labels differ, so a client proof can't serve as server proof
//   or vice versa.
// - Proofs are verified in constant time. An unknown name fails like a wrong PSK, in the same
//   time, so the server's answers don't reveal which names exist.
//
// The message formats are described in docs/PROTOCOL.md.
//
// License: GPL-3.0-only

use anyhow::{anyhow, bail, Context, Result};
use ring::hmac;
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Label for exporting the keying material that binds the authentication to the TLS session.
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-portredirect-v5-authentication";

/// Length of the keying material exported from the TLS session.
pub const SESSION_BINDING_LENGTH: usize = 32;

/// Keying material exported from the TLS session.
pub type SessionBinding = [u8; SESSION_BINDING_LENGTH];

/// Maximum number of PSKs of a client: e.g. the current one and the next one while changing it.
pub const MAX_PSKS_PER_CLIENT: usize = 2;

const CHALLENGE_HEADER: &[u8; 9] = b"CHALLENGE";
const RESPONSE_HEADER: &[u8; 8] = b"RESPONSE";
const ACCEPTED_HEADER: &[u8; 8] = b"ACCEPTED";
const NONCE_LENGTH: usize = 32;
const PROOF_LENGTH: usize = 32;
const CLIENT_PROOF_LABEL: &[u8] = b"portredirect v5 client proof";
const SERVER_PROOF_LABEL: &[u8] = b"portredirect v5 server proof";

type Nonce = [u8; NONCE_LENGTH];

/// The name a client authenticates with: 1 to 64 letters, digits, dots, underscores or hyphens,
/// so it can safely appear in logs and metric labels.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientName(String);

impl ClientName {
    pub const MAX_LENGTH: usize = 64;

    /// The name of the only client of a server configured on the command line, and the client's
    /// default name.
    pub const DEFAULT: &'static str = "default";

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ClientName {
    fn default() -> Self {
        Self(Self::DEFAULT.into())
    }
}

impl FromStr for ClientName {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let valid = (1..=Self::MAX_LENGTH).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if valid {
            Ok(Self(name.into()))
        } else {
            Err(format!(
                "invalid client name {:?}: use 1 to {} letters, digits, dots, underscores or hyphens",
                name,
                Self::MAX_LENGTH
            ))
        }
    }
}

impl fmt::Display for ClientName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The clients a server accepts, with their PSKs (server side).
pub trait PskLookup {
    /// Returns the PSKs of the client named `name`, at most [`MAX_PSKS_PER_CLIENT`] are used, or
    /// `None` if there is no such client.
    fn psks(&self, name: &ClientName) -> Option<&[SecretString]>;
}

/// The peer failed to prove that it knows the PSK: the PSKs of client and server differ, or the
/// server has no client with that name.
#[derive(Debug)]
pub struct AuthenticationRejected(pub String);

impl std::fmt::Display for AuthenticationRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "authentication rejected: {}", self.0)
    }
}

impl std::error::Error for AuthenticationRejected {}

/// An authenticated client (server side).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedClient {
    pub name: ClientName,
    /// Which of the client's PSKs it proved its knowledge of, starting at 0.
    pub psk_index: usize,
}

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

/// Server-side authentication: sends a challenge, verifies the client's proof with the PSKs of
/// the client it names and proves its own knowledge of the PSK.
///
/// Fails with [`AuthenticationRejected`] if the server has no client with that name or the proof
/// is wrong. The caller should then close the connection.
pub async fn server_authenticate<S, L>(
    stream: &mut S,
    clients: &L,
    session_binding: &SessionBinding,
) -> Result<AuthenticatedClient>
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: PskLookup + ?Sized,
{
    // 1. Send the challenge.
    let nonce = random_nonce()?;
    send(stream, CHALLENGE_HEADER, &nonce)
        .await
        .context("failed to send challenge")?;

    // 2. Verify the client's proof.
    let (name, client_proof) = receive_response(stream)
        .await
        .context("failed to receive response")?;
    let psks = clients.psks(&name);
    let psk_index = find_psk(
        psks.unwrap_or_default(),
        session_binding,
        &nonce,
        &name,
        &client_proof,
    )?;
    let (Some(psks), Some(psk_index)) = (psks, psk_index) else {
        return Err(AuthenticationRejected(match psks {
            None => format!("unknown client name {:?}", name.as_str()),
            Some(_) => format!("the proof of client {:?} is wrong", name.as_str()),
        })
        .into());
    };

    // 3. Prove our knowledge of the PSK.
    let server_proof = sign(
        &psks[psk_index],
        SERVER_PROOF_LABEL,
        session_binding,
        &nonce,
        &name,
    );
    send(stream, ACCEPTED_HEADER, server_proof.as_ref())
        .await
        .context("failed to send acceptance")?;

    Ok(AuthenticatedClient { name, psk_index })
}

/// Client-side authentication: answers the server's challenge with the client's name and a proof
/// of knowledge of the PSK, and verifies the server's proof.
///
/// Fails with [`AuthenticationRejected`] if the server's proof is wrong. If the server rejects
/// the client's proof, it closes the connection, so reading its answer fails.
pub async fn client_authenticate<S>(
    stream: &mut S,
    name: &ClientName,
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
    let client_proof = sign(psk, CLIENT_PROOF_LABEL, session_binding, &nonce, name);
    send(
        stream,
        RESPONSE_HEADER,
        &[name_field(name).as_slice(), client_proof.as_ref()].concat(),
    )
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
        name,
        &server_proof,
    ) {
        return Err(AuthenticationRejected(
            "the server could not prove that it knows the PSK".into(),
        )
        .into());
    }

    Ok(())
}

/// Returns the index of the PSK in `psks` the client's `proof` was made with, if any.
///
/// Always checks [`MAX_PSKS_PER_CLIENT`] PSKs, with random ones in place of missing ones, so the
/// time it takes doesn't tell whether the client exists or how many PSKs it has.
fn find_psk(
    psks: &[SecretString],
    session_binding: &SessionBinding,
    nonce: &Nonce,
    name: &ClientName,
    proof: &[u8],
) -> Result<Option<usize>> {
    let random_psk = random_psk()?;
    let mut found = None;
    for index in 0..MAX_PSKS_PER_CLIENT {
        let psk = psks.get(index).unwrap_or(&random_psk);
        let valid = verify(psk, CLIENT_PROOF_LABEL, session_binding, nonce, name, proof);
        if valid && index < psks.len() && found.is_none() {
            found = Some(index);
        }
    }
    Ok(found)
}

/// Returns a nonce from the operating system's secure random number generator.
fn random_nonce() -> Result<Nonce> {
    let mut nonce: Nonce = [0u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("failed to get random bytes: {}", e))?;
    Ok(nonce)
}

/// Returns a random PSK that nobody knows, as long as PSKs are usually.
fn random_psk() -> Result<SecretString> {
    let bytes = random_nonce()?;
    Ok(bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
        .into())
}

/// Returns the proof for `label`, i.e. HMAC-SHA256 with the PSK as key over
/// `label || session_binding || nonce || name length || name`.
fn sign(
    psk: &SecretString,
    label: &[u8],
    session_binding: &SessionBinding,
    nonce: &Nonce,
    name: &ClientName,
) -> hmac::Tag {
    hmac::sign(
        &proof_key(psk),
        &proof_input(label, session_binding, nonce, name),
    )
}

/// Verifies a proof in constant time.
fn verify(
    psk: &SecretString,
    label: &[u8],
    session_binding: &SessionBinding,
    nonce: &Nonce,
    name: &ClientName,
    proof: &[u8],
) -> bool {
    hmac::verify(
        &proof_key(psk),
        &proof_input(label, session_binding, nonce, name),
        proof,
    )
    .is_ok()
}

fn proof_key(psk: &SecretString) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, psk.expose_secret().as_bytes())
}

fn proof_input(
    label: &[u8],
    session_binding: &SessionBinding,
    nonce: &Nonce,
    name: &ClientName,
) -> Vec<u8> {
    [label, session_binding, nonce, &name_field(name)].concat()
}

/// Returns the client's name as it is sent: its length (u8) and the name.
fn name_field(name: &ClientName) -> Vec<u8> {
    // Client names have at most 64 bytes.
    let mut field = vec![name.as_str().len() as u8];
    field.extend_from_slice(name.as_str().as_bytes());
    field
}

/// Sends a message consisting of a fixed header and a payload.
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
    receive_header(stream, header).await?;
    let mut payload = [0u8; N];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Receives the client's response: its name and its proof.
async fn receive_response<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(ClientName, [u8; PROOF_LENGTH])> {
    receive_header(stream, RESPONSE_HEADER).await?;
    let name_length = usize::from(stream.read_u8().await?);
    if !(1..=ClientName::MAX_LENGTH).contains(&name_length) {
        bail!("invalid client name length {}", name_length);
    }
    let mut name = vec![0u8; name_length];
    stream.read_exact(&mut name).await?;
    let name = std::str::from_utf8(&name)
        .map_err(|_| anyhow!("invalid client name {:?}", String::from_utf8_lossy(&name)))?
        .parse::<ClientName>()
        .map_err(|e| anyhow!(e))?;
    let mut proof = [0u8; PROOF_LENGTH];
    stream.read_exact(&mut proof).await?;
    Ok((name, proof))
}

async fn receive_header<S: AsyncRead + Unpin>(stream: &mut S, header: &[u8]) -> Result<()> {
    let mut received_header = vec![0u8; header.len()];
    stream.read_exact(&mut received_header).await?;
    if received_header != header {
        bail!(
            "expected {:?}, got {:?}",
            String::from_utf8_lossy(header),
            String::from_utf8_lossy(&received_header)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::{duplex, DuplexStream};

    const BINDING: SessionBinding = [7u8; SESSION_BINDING_LENGTH];

    /// Clients of a test server, by name.
    struct TestClients(HashMap<ClientName, Vec<SecretString>>);

    impl TestClients {
        fn new(clients: &[(&str, &[&str])]) -> Self {
            Self(
                clients
                    .iter()
                    .map(|(name, psks)| {
                        let psks = psks.iter().map(|&psk| SecretString::from(psk)).collect();
                        (name.parse().unwrap(), psks)
                    })
                    .collect(),
            )
        }
    }

    impl PskLookup for TestClients {
        fn psks(&self, name: &ClientName) -> Option<&[SecretString]> {
            self.0.get(name).map(Vec::as_slice)
        }
    }

    fn name(name: &str) -> ClientName {
        name.parse().unwrap()
    }

    /// Runs server and client authentication against each other.
    async fn authenticate(
        server_clients: TestClients,
        server_binding: SessionBinding,
        client_name: &str,
        client_psk: &str,
        client_binding: SessionBinding,
    ) -> (Result<AuthenticatedClient>, Result<()>) {
        let (mut client_side, mut server_side) = duplex(1024);
        let client_name = name(client_name);
        let client_psk = SecretString::from(client_psk);

        let server = tokio::spawn(async move {
            let result =
                server_authenticate(&mut server_side, &server_clients, &server_binding).await;
            // Like the real server, close the connection after a failure.
            drop(server_side);
            result
        });
        let client = tokio::spawn(async move {
            client_authenticate(&mut client_side, &client_name, &client_psk, &client_binding).await
        });

        (
            server.await.expect("server task panicked"),
            client.await.expect("client task panicked"),
        )
    }

    fn one_client() -> TestClients {
        TestClients::new(&[("default", &["test-secret"])])
    }

    #[tokio::test]
    async fn test_authentication_succeeds_with_same_psk() {
        let (server, client) =
            authenticate(one_client(), BINDING, "default", "test-secret", BINDING).await;
        assert_eq!(
            server.unwrap(),
            AuthenticatedClient {
                name: name("default"),
                psk_index: 0
            }
        );
        client.unwrap();
    }

    #[tokio::test]
    async fn test_server_checks_the_psk_of_the_named_client() {
        let clients =
            || TestClients::new(&[("home", &["home-secret"]), ("office", &["office-secret"])]);

        let (server, client) =
            authenticate(clients(), BINDING, "office", "office-secret", BINDING).await;
        assert_eq!(server.unwrap().name, name("office"));
        client.unwrap();

        // The PSK of another client doesn't help.
        let (server, client) =
            authenticate(clients(), BINDING, "office", "home-secret", BINDING).await;
        let server_err = server.unwrap_err();
        assert!(
            server_err.is::<AuthenticationRejected>(),
            "{:#}",
            server_err
        );
        assert!(
            server_err
                .to_string()
                .contains("proof of client \"office\" is wrong"),
            "{:#}",
            server_err
        );
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn test_server_rejects_unknown_names_like_wrong_psks() {
        let (server, client) =
            authenticate(one_client(), BINDING, "intruder", "test-secret", BINDING).await;

        let server_err = server.unwrap_err();
        assert!(
            server_err.is::<AuthenticationRejected>(),
            "{:#}",
            server_err
        );
        assert!(
            server_err
                .to_string()
                .contains("unknown client name \"intruder\""),
            "{:#}",
            server_err
        );
        // As with a wrong PSK, the server sends nothing more.
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn test_server_accepts_both_psks_of_a_client() {
        let clients = || TestClients::new(&[("office", &["old-secret", "new-secret"])]);
        for (psk, index) in [("old-secret", 0), ("new-secret", 1)] {
            let (server, client) = authenticate(clients(), BINDING, "office", psk, BINDING).await;
            assert_eq!(server.unwrap().psk_index, index);
            client.unwrap();
        }
    }

    #[tokio::test]
    async fn test_server_uses_at_most_two_psks() {
        let clients = TestClients::new(&[("office", &["first", "second", "third"])]);
        let (server, client) = authenticate(clients, BINDING, "office", "third", BINDING).await;
        assert!(server.unwrap_err().is::<AuthenticationRejected>());
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn test_server_rejects_wrong_psk() {
        let (server, client) =
            authenticate(one_client(), BINDING, "default", "another-secret", BINDING).await;

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
        let (server, client) =
            authenticate(one_client(), BINDING, "default", "test-secret", [8u8; 32]).await;

        assert!(server.unwrap_err().is::<AuthenticationRejected>());
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn test_client_rejects_server_without_psk() {
        // A server that has the certificate key but not the PSK can't send a valid proof.
        let (mut client_side, mut fake_server) = duplex(1024);
        let fake = tokio::spawn(async move {
            send(&mut fake_server, CHALLENGE_HEADER, &[1u8; NONCE_LENGTH]).await?;
            let _response = receive_response(&mut fake_server).await?;
            send(&mut fake_server, ACCEPTED_HEADER, &[0u8; PROOF_LENGTH]).await?;
            Ok::<_, anyhow::Error>(fake_server)
        });

        let psk = SecretString::from("test-secret");
        let result = client_authenticate(&mut client_side, &name("default"), &psk, &BINDING).await;

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
        let err = client_authenticate(&mut client_side, &name("default"), &psk, &BINDING)
            .await
            .unwrap_err();
        assert!(format!("{:#}", err).contains("expected \"CHALLENGE\""));

        // The server expects a response.
        let err = response_error(&[b'X'; 48]).await;
        assert!(
            format!("{:#}", err).contains("expected \"RESPONSE\""),
            "{:#}",
            err
        );
    }

    /// Returns the server's error for a client that answers the challenge with `response`.
    async fn response_error(response: &[u8]) -> anyhow::Error {
        let (mut client_side, mut server_side): (DuplexStream, DuplexStream) = duplex(1024);
        let server = tokio::spawn(async move {
            server_authenticate(&mut server_side, &one_client(), &BINDING).await
        });
        let mut challenge = [0u8; CHALLENGE_HEADER.len() + NONCE_LENGTH];
        client_side.read_exact(&mut challenge).await.unwrap();
        client_side.write_all(response).await.unwrap();
        drop(client_side);
        server.await.unwrap().unwrap_err()
    }

    #[tokio::test]
    async fn test_invalid_names_are_rejected() {
        for (field, expected) in [
            (&[0u8][..], "invalid client name length 0"),
            (&[65], "invalid client name length 65"),
            (&[3, b'a', b' ', b'b'], "invalid client name \"a b\""),
            (&[2, 0xc3, 0x28], "invalid client name"),
        ] {
            let mut response = RESPONSE_HEADER.to_vec();
            response.extend_from_slice(field);
            response.extend_from_slice(&[0u8; PROOF_LENGTH]);
            let err = response_error(&response).await;
            assert!(
                format!("{:#}", err).contains(expected),
                "{:?}: {:#}",
                field,
                err
            );
            assert!(!err.is::<AuthenticationRejected>(), "{:#}", err);
        }
    }

    #[test]
    fn test_client_names() {
        for valid in ["default", "home", "a", "Office-2.backup_1", &"x".repeat(64)] {
            assert_eq!(valid.parse::<ClientName>().unwrap().as_str(), valid);
        }
        for invalid in ["", "a b", "über", "a/b", "a\n", &"x".repeat(65)] {
            let err = invalid.parse::<ClientName>().unwrap_err();
            assert!(
                err.contains("invalid client name"),
                "{:?}: {}",
                invalid,
                err
            );
        }
        assert_eq!(ClientName::default().to_string(), "default");
    }

    #[test]
    fn test_proofs_match_reference_values() {
        // Computed independently with Python's hmac module, see docs/PROTOCOL.md for the format.
        let psk = SecretString::from("test-psk");
        let binding: SessionBinding = std::array::from_fn(|i| i as u8);
        let nonce: Nonce = std::array::from_fn(|i| 32 + i as u8);

        let client_proof = sign(&psk, CLIENT_PROOF_LABEL, &binding, &nonce, &name("home"));
        let server_proof = sign(&psk, SERVER_PROOF_LABEL, &binding, &nonce, &name("home"));

        assert_eq!(
            hex(client_proof.as_ref()),
            "0a777ecbe15f463d8b64ee83b80f3b7dadd0dc762903faec5a1c7614293ac91b"
        );
        assert_eq!(
            hex(server_proof.as_ref()),
            "d82322ef17b0e7218b0213953921bac78fd87347ddab8a36806c3bc786450008"
        );
    }

    #[test]
    fn test_client_proof_is_no_server_proof() {
        let psk = SecretString::from("test-secret");
        let nonce = random_nonce().unwrap();
        let client_proof = sign(&psk, CLIENT_PROOF_LABEL, &BINDING, &nonce, &name("a"));
        assert!(!verify(
            &psk,
            SERVER_PROOF_LABEL,
            &BINDING,
            &nonce,
            &name("a"),
            client_proof.as_ref()
        ));
    }

    #[test]
    fn test_proofs_are_bound_to_the_name() {
        // A proof for one name doesn't work for another one with the same PSK.
        let psk = SecretString::from("shared-secret");
        let nonce = random_nonce().unwrap();
        let proof = sign(&psk, CLIENT_PROOF_LABEL, &BINDING, &nonce, &name("home"));
        assert!(!verify(
            &psk,
            CLIENT_PROOF_LABEL,
            &BINDING,
            &nonce,
            &name("office"),
            proof.as_ref()
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
