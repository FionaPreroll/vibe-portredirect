// PortRedirect Protocol Module
//
// The idea behind PRRS authentication is:
// - The server is trusted by the client because it has the right public certificate matching our configuration file.
// - The client is not trusted by the server because anyone can connect to the server and say that it speaks our protocol.
// - The client proves its trustworthiness by sending a response to a challenge that only the client can answer using the PSK.
// - Add a time component to the challenge to prevent replay attacks, by making the challenge expire after a certain time.
// - Add a safe big random component to make the challenge not brute-forceable.
// - Use a safe hash function. Note this may require that we need rate-limiting for clients that fail
//   authentication to avoid getting DoS'ed by people trying to get us to compute a lot of big hashes.
//
// Implementation details:
// - Make it kinda readable for debugging.
//
// License: GPL-3.0-only

use crate::PortRedirectProtocol;

use super::utils::ElapsedMinutes;
use super::utils::TimeProvider;

use anyhow::{anyhow, Result};
use secrecy::ExposeSecret;
use secrecy::SecretString;
use sha2::{Digest, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Server-side authentication: send challenge, receive and verify the client’s response.
pub async fn server_authenticate<S>(
    stream: &mut S,
    psk: SecretString,
    time_provider: &impl TimeProvider,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Generate a challenge.
    let coarse_unix_time = time_provider.now().elapsed_minutes();
    let random_bytes = crate::protocol::utils::generate_random_bytes(32)?;
    let random_bytes_hex = hex::encode(random_bytes);

    let challenge = format!(
        "this-is-the-challenge-{}-at-{}-pr-v1",
        random_bytes_hex, coarse_unix_time
    );
    let request = format!("WHO THE HECK ARE YOU?\n{}\n", challenge);

    if request.len() > PortRedirectProtocol::CHALLENGE_REQUEST_BUFFER_LENGTH {
        return Err(anyhow!("Challenge string exceeds maximum length"));
    }

    // 2. Send the challenge.
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // 3. Read client response.
    let mut buf = vec![0u8; 129]; // 128 hex bytes + newline
    stream.read_exact(&mut buf).await?;
    let client_response = std::str::from_utf8(&buf)?.trim_end();

    // 4. Compute expected response.
    let mut hasher = Sha512::new();
    hasher.update(challenge.as_bytes());
    hasher.update(psk.expose_secret());
    let expected_response = hex::encode(hasher.finalize());

    // 5. Verify.
    if client_response == expected_response {
        stream.write_all(b"HAPPY\n").await?;
        stream.flush().await?;
        Ok(())
    } else {
        stream.write_all(b"BAD\n").await?;
        stream.flush().await?;
        Err(anyhow!("Authentication failed: response mismatch"))
    }
}

/// Client-side authentication: receive the challenge, compute the response, send it.
pub async fn client_authenticate<S>(stream: &mut S, psk: SecretString) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Read the challenge message.
    let mut buf = vec![0u8; PortRedirectProtocol::CHALLENGE_REQUEST_BUFFER_LENGTH];
    let n = stream.read(&mut buf).await?;
    let message = std::str::from_utf8(&buf[..n])?;
    let mut lines = message.lines();

    match lines.next() {
        Some("WHO THE HECK ARE YOU?") => {}
        _ => return Err(anyhow!("Unexpected authentication prompt")),
    }
    let challenge = lines
        .next()
        .ok_or_else(|| anyhow!("Missing challenge in authentication message"))?;

    // 2. Compute response.
    let mut hasher = Sha512::new();
    hasher.update(challenge.as_bytes());
    hasher.update(psk.expose_secret());
    let response = hex::encode(hasher.finalize()) + "\n";

    // 3. Send response.
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    // 4. Read final server reply.
    let mut reply = vec![0u8; 16];
    let n = stream.read(&mut reply).await?;
    let reply = std::str::from_utf8(&reply[..n])?;
    if reply.starts_with("HAPPY") {
        Ok(())
    } else {
        Err(anyhow!("Server rejected authentication: {}", reply.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::utils::SystemTimeProvider;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_authentication_protocol_good() -> Result<()> {
        let test_psk = "test-secret";

        // Create an in‑memory duplex stream.
        let (mut client_side, mut server_side) = duplex(1024);

        // Run server and client auth concurrently.
        let server = tokio::spawn(async move {
            server_authenticate(&mut server_side, test_psk.into(), &SystemTimeProvider).await
        });

        let client =
            tokio::spawn(
                async move { client_authenticate(&mut client_side, test_psk.into()).await },
            );

        server.await??;
        client.await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_authentication_protocol_bad_psk() -> Result<()> {
        let test_psk1 = "test-secret";
        let test_psk2 = "another-test-secret";

        // Create an in‑memory duplex stream.
        let (mut client_side, mut server_side) = duplex(1024);

        // Run server and client auth concurrently.
        let server = tokio::spawn(async move {
            server_authenticate(&mut server_side, test_psk1.into(), &SystemTimeProvider).await
        });

        let client =
            tokio::spawn(
                async move { client_authenticate(&mut client_side, test_psk2.into()).await },
            );

        // Await both tasks. Use `expect` to panic if the task itself panics.
        let server_res = server.await.expect("server task panicked");
        let client_res = client.await.expect("client task panicked");

        // In a bad authentication, we expect at least one of the two sides to error.
        // Here, we check that if the server returned Ok, then the client must have failed;
        // otherwise, if the server failed, we check its error.
        if server_res.is_ok() {
            let client_err = client_res.expect_err("client_authenticate should have failed");
            assert!(
                client_err
                    .to_string()
                    .contains("Authentication failed: response mismatch"),
                "Unexpected client error message: {}",
                client_err
            );
        } else {
            let server_err = server_res.expect_err("server_authenticate should have failed");
            assert!(
                server_err
                    .to_string()
                    .contains("Authentication failed: response mismatch"),
                "Unexpected server error message: {}",
                server_err
            );
        }
        Ok(())
    }
}
