// PortRedirect Protocol Module - Header of data streams
//
// The server starts each data stream with a header naming the external client's address. Besides
// passing on that address, the header makes the stream known to the client right away: QUIC
// announces a new stream to the peer only with its first data. Without the header, the client
// would learn about a forwarded connection only when the external client sends something, so
// protocols in which the server speaks first (e.g. SMTP) would hang.
//
// The message format is described in docs/PROTOCOL.md.
//
// License: GPL-3.0-only

use anyhow::{bail, Context, Result};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CONNECTION_HEADER: &[u8; 10] = b"CONNECTION";
const IPV4: u8 = 4;
const IPV6: u8 = 6;

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
pub async fn receive_connection_header<R>(stream: &mut R) -> Result<SocketAddr>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; CONNECTION_HEADER.len()];
    stream
        .read_exact(&mut header)
        .await
        .context("failed to receive the connection header")?;
    if &header != CONNECTION_HEADER {
        bail!(
            "invalid connection header: expected 'CONNECTION', got {:?}",
            String::from_utf8_lossy(&header)
        );
    }

    let ip = match stream.read_u8().await? {
        IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            IpAddr::from(octets)
        }
        IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            IpAddr::from(octets)
        }
        family => bail!("invalid address family {} in the connection header", family),
    };
    let port = stream.read_u16().await?;
    Ok(SocketAddr::new(ip, port))
}

fn encode_connection_header(peer: SocketAddr) -> Vec<u8> {
    let mut header = CONNECTION_HEADER.to_vec();
    // An IPv4 client of a dual-stack listener has an IPv4-mapped IPv6 address.
    match peer.ip().to_canonical() {
        IpAddr::V4(ip) => {
            header.push(IPV4);
            header.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            header.push(IPV6);
            header.extend_from_slice(&ip.octets());
        }
    }
    header.extend_from_slice(&peer.port().to_be_bytes());
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
            b"CONNECTION\x04\xc0\x00\x02\x01\xc3\x50"
        );
        let ipv6 = encode_connection_header(addr("[2001:db8::1]:443"));
        assert_eq!(ipv6.len(), 10 + 1 + 16 + 2);
        assert_eq!(ipv6[10], 6);
        assert_eq!(&ipv6[27..], &443u16.to_be_bytes());
    }

    #[tokio::test]
    async fn test_invalid_headers_are_rejected() {
        for (header, expected_error) in [
            (
                b"CONNECTED\x04\x7f\x00\x00\x01\x00\x50".as_slice(),
                "invalid connection header",
            ),
            (
                b"CONNECTION\x05\x7f\x00\x00\x01\x00\x50",
                "invalid address family 5",
            ),
            (b"CONNECTION\x04\x7f\x00", "early eof"),
            (b"CONN", "failed to receive the connection header"),
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
                String::from_utf8_lossy(header),
                err
            );
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
}
