// PortRedirect Protocol Module - Setting up the tunnel on the control stream
//
// After the authentication, the client sends HELLO with the port the server should listen on,
// and the server answers with WELCOME once it listens. Both messages consist of parameters, see
// protocol::message and docs/PROTOCOL.md.
//
// License: GPL-3.0-only

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::protocol::message::{
    param, read_message, write_message, Message, MessageType, Parameters, ProtocolViolation,
};

/// Software parameter of the client's HELLO.
pub const CLIENT_SOFTWARE: &str = concat!("portredirect_client ", env!("CARGO_PKG_VERSION"));
/// Software parameter of the server's WELCOME.
pub const SERVER_SOFTWARE: &str = concat!("portredirect_server ", env!("CARGO_PKG_VERSION"));

/// Content of HELLO (client to server) and WELCOME (server to client).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Greeting {
    /// The sender's software and version, only for logs.
    pub software: Option<String>,
    /// HELLO: the port the server should listen on. WELCOME: the port it listens on.
    pub listen_port: u16,
}

impl Greeting {
    pub fn new(software: &str, listen_port: u16) -> Self {
        Self {
            software: Some(software.into()),
            listen_port,
        }
    }

    /// Returns the software for logs, or a placeholder if the peer didn't send it.
    pub fn software(&self) -> &str {
        self.software.as_deref().unwrap_or("unknown software")
    }

    fn to_message(&self, kind: MessageType) -> Message {
        let mut parameters = Parameters::new();
        if let Some(software) = &self.software {
            parameters.insert_text(param::SOFTWARE, software);
        }
        parameters.insert_u16(param::LISTEN_PORT, self.listen_port);
        Message::new(kind, parameters.encode())
    }

    fn from_message(message: &Message, kind: MessageType) -> Result<Self, ProtocolViolation> {
        if message.kind != kind {
            return Err(ProtocolViolation(format!(
                "expected {:?}, got {:?}",
                kind, message.kind
            )));
        }
        let parameters = Parameters::decode(&message.payload)?;
        Ok(Self {
            software: parameters.get_text(param::SOFTWARE)?.map(String::from),
            listen_port: Parameters::require(
                parameters.get_u16(param::LISTEN_PORT),
                param::LISTEN_PORT,
                &format!("{:?}", kind),
            )?,
        })
    }
}

/// Receives the client's HELLO (server side).
///
/// The caller checks whether the client may use the requested port, and confirms it with
/// [`send_welcome`] once it listens. Fails with [`ProtocolViolation`] if the client sends
/// anything else.
pub async fn receive_hello<S>(control_stream: &mut S) -> Result<Greeting>
where
    S: AsyncRead + Unpin,
{
    receive_greeting(control_stream, MessageType::Hello).await
}

/// Tells the client which port the server listens on (server side).
pub async fn send_welcome<S>(control_stream: &mut S, welcome: &Greeting) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_message(control_stream, &welcome.to_message(MessageType::Welcome))
        .await
        .context("failed to send WELCOME")
}

/// Sends HELLO and returns the server's WELCOME (client side).
///
/// If the server refuses, it closes the connection instead of answering.
pub async fn request_listen_port<S>(control_stream: &mut S, hello: &Greeting) -> Result<Greeting>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_message(control_stream, &hello.to_message(MessageType::Hello))
        .await
        .context("failed to send HELLO")?;
    receive_greeting(control_stream, MessageType::Welcome).await
}

async fn receive_greeting<S>(control_stream: &mut S, kind: MessageType) -> Result<Greeting>
where
    S: AsyncRead + Unpin,
{
    let message = read_message(control_stream)
        .await
        .with_context(|| format!("failed to receive {:?}", kind))?;
    let Some(message) = message else {
        bail!("the control stream ended before {:?}", kind);
    };
    Ok(Greeting::from_message(&message, kind)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    #[tokio::test]
    async fn test_hello_and_welcome() -> Result<()> {
        let (mut client_side, mut server_side) = duplex(1024);

        let server = tokio::spawn(async move {
            let hello = receive_hello(&mut server_side).await?;
            send_welcome(&mut server_side, &Greeting::new(SERVER_SOFTWARE, 4243)).await?;
            Ok::<Greeting, anyhow::Error>(hello)
        });

        let welcome =
            request_listen_port(&mut client_side, &Greeting::new(CLIENT_SOFTWARE, 4242)).await?;

        let hello = server.await??;
        assert_eq!(hello, Greeting::new(CLIENT_SOFTWARE, 4242));
        assert_eq!(welcome, Greeting::new(SERVER_SOFTWARE, 4243));
        assert_eq!(
            CLIENT_SOFTWARE,
            format!("portredirect_client {}", env!("CARGO_PKG_VERSION"))
        );
        Ok(())
    }

    #[test]
    fn test_hello_format() {
        // As described in docs/PROTOCOL.md.
        let hello = Greeting::new("portredirect_client 1.0.0", 443).to_message(MessageType::Hello);
        let mut expected = vec![0, 1, 0, 25];
        expected.extend_from_slice(b"portredirect_client 1.0.0");
        expected.extend_from_slice(&[0, 2, 0, 2, 0x01, 0xbb]);
        assert_eq!(hello, Message::new(MessageType::Hello, expected));
    }

    #[tokio::test]
    async fn test_software_is_optional_and_unknown_parameters_are_ignored() -> Result<()> {
        let (mut client_side, mut server_side) = duplex(1024);
        let mut parameters = Parameters::new();
        parameters
            .insert_u16(param::LISTEN_PORT, 80)
            .insert(0x0100, b"an extension".as_slice());
        write_message(
            &mut client_side,
            &Message::new(MessageType::Hello, parameters.encode()),
        )
        .await?;

        let hello = receive_hello(&mut server_side).await?;
        assert_eq!(
            hello,
            Greeting {
                software: None,
                listen_port: 80
            }
        );
        assert_eq!(hello.software(), "unknown software");
        Ok(())
    }

    /// Returns the server's error for a client that sends `message` instead of a valid HELLO.
    async fn hello_error(message: Message) -> anyhow::Error {
        let (mut client_side, mut server_side) = duplex(1024);
        write_message(&mut client_side, &message).await.unwrap();
        receive_hello(&mut server_side).await.unwrap_err()
    }

    #[tokio::test]
    async fn test_invalid_hellos_are_protocol_violations() {
        let mut software_only = Parameters::new();
        software_only.insert_text(param::SOFTWARE, "x");
        let mut long_port = Parameters::new();
        long_port.insert(param::LISTEN_PORT, [0u8, 0, 80]);

        for (message, expected) in [
            (
                Message::empty(MessageType::Ping),
                "expected Hello, got Ping",
            ),
            (
                Message::new(MessageType::Hello, software_only.encode()),
                "Hello without parameter 2",
            ),
            (
                Message::new(MessageType::Hello, long_port.encode()),
                "parameter 2 is not a 16-bit number",
            ),
            (
                Message::new(MessageType::Hello, vec![0, 2, 0]),
                "truncated parameter",
            ),
        ] {
            let err = hello_error(message).await;
            assert!(err.is::<ProtocolViolation>(), "{:#}", err);
            assert!(err.to_string().contains(expected), "{:#}", err);
        }
    }

    #[tokio::test]
    async fn test_missing_hello() {
        let (client_side, mut server_side) = duplex(64);
        drop(client_side);
        let err = receive_hello(&mut server_side).await.unwrap_err();
        assert!(err.to_string().contains("ended before Hello"), "{:#}", err);

        // A stream that breaks off in the middle of a message.
        let (mut client_side, mut server_side) = duplex(64);
        client_side.write_all(&[1, 0, 8, 0]).await.unwrap();
        drop(client_side);
        let err = receive_hello(&mut server_side).await.unwrap_err();
        assert!(!err.is::<ProtocolViolation>(), "{:#}", err);
    }

    #[tokio::test]
    async fn test_request_fails_when_server_closes() {
        let (mut client_side, server_side) = duplex(1024);
        let server = tokio::spawn(async move {
            let mut server_side = server_side;
            let _ = read_message(&mut server_side).await;
            // Closes without answering, like a server that refuses the port.
        });
        let result =
            request_listen_port(&mut client_side, &Greeting::new(CLIENT_SOFTWARE, 80)).await;
        server.await.unwrap();
        assert!(result.is_err(), "missing WELCOME must be an error");
    }

    #[tokio::test]
    async fn test_request_rejects_other_answers() {
        let (mut client_side, mut server_side) = duplex(1024);
        write_message(&mut server_side, &Message::empty(MessageType::Pong))
            .await
            .unwrap();
        let err = request_listen_port(&mut client_side, &Greeting::new(CLIENT_SOFTWARE, 80))
            .await
            .unwrap_err();
        assert!(err.is::<ProtocolViolation>(), "{:#}", err);
    }
}
