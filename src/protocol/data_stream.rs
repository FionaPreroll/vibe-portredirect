// PortRedirect Protocol Module - Data streams
//
// The server starts each data stream with a header naming the external client's address. Besides
// passing on that address, the header makes the stream known to the client right away: QUIC
// announces a new stream to the peer only with its first data. Without the header, the client
// would learn about a forwarded connection only when the external client sends something, so
// protocols in which the server speaks first (e.g. SMTP) would hang.
//
// A side that aborts a data stream resets it with an error code, so the other side can reset its
// TCP connection instead of ending it normally.
//
// The formats and codes are described in docs/PROTOCOL.md.
//
// License: GPL-3.0-only

use anyhow::{bail, Context, Result};
use quinn::VarInt;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::message::{param, Parameters, ProtocolViolation, MAX_PAYLOAD_LENGTH};

/// Error codes for resetting (`RESET_STREAM`) or stopping (`STOP_SENDING`) a data stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamErrorCode {
    /// Normal end. quinn stops a stream with this code when it is dropped before its end.
    Ok = 0,
    /// The sender's TCP connection was reset or failed.
    Aborted = 1,
    /// The client could not connect to the destination.
    ConnectFailed = 2,
}

impl StreamErrorCode {
    /// Returns the numeric value sent over the wire.
    pub fn code(self) -> VarInt {
        VarInt::from(self as u32)
    }

    /// Returns the error code with the numeric value `code`. Unknown codes other than 0 count as
    /// [`StreamErrorCode::Aborted`].
    pub fn from_code(code: VarInt) -> Self {
        match code.into_inner() {
            0 => StreamErrorCode::Ok,
            2 => StreamErrorCode::ConnectFailed,
            _ => StreamErrorCode::Aborted,
        }
    }
}

/// Sends the header of a data stream, naming `peer`, the external client.
pub async fn send_connection_header<W>(stream: &mut W, peer: SocketAddr) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    stream
        .write_all(&encode_connection_header(peer))
        .await
        .context("failed to send the connection header")?;
    stream
        .flush()
        .await
        .context("failed to send the connection header")?;
    Ok(())
}

/// Receives the header of a data stream and returns the external client's address.
///
/// Fails with [`ProtocolViolation`] if the header is malformed.
pub async fn receive_connection_header<R>(stream: &mut R) -> Result<SocketAddr>
where
    R: AsyncRead + Unpin,
{
    let length = usize::from(
        stream
            .read_u16()
            .await
            .context("failed to receive the connection header")?,
    );
    if length > MAX_PAYLOAD_LENGTH {
        bail!(ProtocolViolation(format!(
            "connection header of {} bytes, at most {} are allowed",
            length, MAX_PAYLOAD_LENGTH
        )));
    }
    let mut header = vec![0u8; length];
    stream
        .read_exact(&mut header)
        .await
        .context("failed to receive the connection header")?;
    let parameters = Parameters::decode(&header)?;
    Ok(Parameters::require(
        parameters.get_address(param::PEER),
        param::PEER,
        "connection header",
    )?)
}

fn encode_connection_header(peer: SocketAddr) -> Vec<u8> {
    let mut parameters = Parameters::new();
    parameters.insert_address(param::PEER, peer);
    let parameters = parameters.encode();
    // A single address is far below the maximum length.
    let mut header = (parameters.len() as u16).to_be_bytes().to_vec();
    header.extend_from_slice(&parameters);
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn roundtrip(peer: SocketAddr) -> SocketAddr {
        let (mut client_side, mut server_side) = duplex(64);
        send_connection_header(&mut server_side, peer)
            .await
            .unwrap();
        receive_connection_header(&mut client_side).await.unwrap()
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn test_header_roundtrip() {
        for peer in ["192.0.2.1:50000", "[2001:db8::1]:443", "[::1]:1"] {
            assert_eq!(roundtrip(addr(peer)).await, addr(peer));
        }
    }

    #[tokio::test]
    async fn test_ipv4_mapped_addresses_are_sent_as_ipv4() {
        assert_eq!(
            roundtrip(addr("[::ffff:192.0.2.1]:50000")).await,
            addr("192.0.2.1:50000")
        );
    }

    #[test]
    fn test_header_format() {
        // As described in docs/PROTOCOL.md.
        assert_eq!(
            encode_connection_header(addr("192.0.2.1:50000")),
            [0x00, 0x0b, 0x00, 0x03, 0x00, 0x07, 0x04, 0xc0, 0x00, 0x02, 0x01, 0xc3, 0x50]
        );
        let ipv6 = encode_connection_header(addr("[2001:db8::1]:443"));
        assert_eq!(ipv6.len(), 2 + 4 + 1 + 16 + 2);
        assert_eq!(ipv6[6], 6);
        assert_eq!(&ipv6[23..], &443u16.to_be_bytes());
    }

    #[tokio::test]
    async fn test_unknown_parameters_are_ignored() {
        let mut parameters = Parameters::new();
        parameters
            .insert(0x0100, b"an extension".as_slice())
            .insert_address(param::PEER, addr("192.0.2.1:50000"));
        let parameters = parameters.encode();
        let mut header = (parameters.len() as u16).to_be_bytes().to_vec();
        header.extend_from_slice(&parameters);

        let (mut client_side, mut server_side) = duplex(256);
        server_side.write_all(&header).await.unwrap();
        assert_eq!(
            receive_connection_header(&mut client_side).await.unwrap(),
            addr("192.0.2.1:50000")
        );
    }

    #[tokio::test]
    async fn test_invalid_headers_are_rejected() {
        for (header, expected_error, violation) in [
            (
                &[0x00, 0x00][..],
                "connection header without parameter 3",
                true,
            ),
            (
                &[
                    0x00, 0x0b, 0x00, 0x03, 0x00, 0x07, 0x05, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50,
                ],
                "parameter 3 is not an address",
                true,
            ),
            (&[0x04, 0x01], "connection header of 1025 bytes", true),
            (
                &[0x00, 0x0b, 0x00, 0x03],
                "failed to receive the connection header",
                false,
            ),
            (&[0x00], "failed to receive the connection header", false),
        ] {
            let (mut client_side, mut server_side) = duplex(64);
            server_side.write_all(header).await.unwrap();
            drop(server_side);
            let err = receive_connection_header(&mut client_side)
                .await
                .unwrap_err();
            assert!(
                format!("{:#}", err).contains(expected_error),
                "{:?}: {:#}",
                header,
                err
            );
            assert_eq!(err.is::<ProtocolViolation>(), violation, "{:?}", header);
        }
    }

    #[tokio::test]
    async fn test_payload_follows_the_header() {
        let (mut client_side, mut server_side) = duplex(64);
        send_connection_header(&mut server_side, addr("192.0.2.1:50000"))
            .await
            .unwrap();
        server_side.write_all(b"payload").await.unwrap();
        drop(server_side);

        receive_connection_header(&mut client_side).await.unwrap();
        let mut payload = Vec::new();
        client_side.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn test_stream_error_codes() {
        // The values are part of the protocol, see docs/PROTOCOL.md.
        for (code, value) in [
            (StreamErrorCode::Ok, 0u32),
            (StreamErrorCode::Aborted, 1),
            (StreamErrorCode::ConnectFailed, 2),
        ] {
            assert_eq!(code.code(), VarInt::from_u32(value));
            assert_eq!(StreamErrorCode::from_code(code.code()), code);
        }
        // E.g. a code of a newer version.
        assert_eq!(
            StreamErrorCode::from_code(VarInt::from_u32(1000)),
            StreamErrorCode::Aborted
        );
    }
}
