// PortRedirect Protocol Module - Messages and parameters
//
// After the authentication, client and server exchange framed messages on the control stream:
// a type, a length and a payload. Messages that describe a tunnel, and the header of each data
// stream, consist of parameters, each with an ID, a length and a value. Receivers skip
// parameters they don't know, so later 1.x versions can add parameters, e.g. to negotiate
// optional features, without breaking older peers.
//
// The formats are described in docs/PROTOCOL.md.
//
// License: GPL-3.0-only

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum length of a message's payload, and of the parameters of a data stream header.
pub const MAX_PAYLOAD_LENGTH: usize = 1024;

/// The peer sent something the protocol doesn't allow, e.g. a malformed or unexpected message.
#[derive(Debug)]
pub struct ProtocolViolation(pub String);

impl fmt::Display for ProtocolViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol violation: {}", self.0)
    }
}

impl std::error::Error for ProtocolViolation {}

/// Types of the messages on the control stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    /// Client to server, right after the authentication: the port the server should listen on.
    Hello = 1,
    /// Server to client: answer to `Hello` once the port is bound.
    Welcome = 2,
    /// Client to server: keepalive.
    Ping = 3,
    /// Server to client: answer to `Ping`.
    Pong = 4,
    /// Either side: the sender starts no new forwarded connections, running ones may finish.
    Drain = 5,
}

impl MessageType {
    const ALL: [MessageType; 5] = [
        MessageType::Hello,
        MessageType::Welcome,
        MessageType::Ping,
        MessageType::Pong,
        MessageType::Drain,
    ];

    fn from_byte(byte: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| *kind as u8 == byte)
    }
}

/// A message on the control stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: MessageType,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(kind: MessageType, payload: Vec<u8>) -> Self {
        Self { kind, payload }
    }

    /// Returns a message without payload, e.g. `Ping`.
    pub fn empty(kind: MessageType) -> Self {
        Self::new(kind, Vec::new())
    }

    /// Returns the message as it is sent: type, length and payload.
    fn encode(&self) -> Result<Vec<u8>> {
        let length = u16::try_from(self.payload.len())
            .ok()
            .filter(|&length| usize::from(length) <= MAX_PAYLOAD_LENGTH)
            .with_context(|| format!("{:?} message too long", self.kind))?;
        let mut encoded = Vec::with_capacity(3 + self.payload.len());
        encoded.push(self.kind as u8);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }
}

/// Sends `message` and flushes the stream.
pub async fn write_message<W>(stream: &mut W, message: &Message) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    stream.write_all(&message.encode()?).await?;
    stream.flush().await?;
    Ok(())
}

/// Reads the next message, or returns `None` if the stream ended before it.
///
/// Fails with [`ProtocolViolation`] on an unknown type or a too long payload, without reading
/// the payload.
pub async fn read_message<R>(stream: &mut R) -> Result<Option<Message>>
where
    R: AsyncRead + Unpin,
{
    let mut kind = [0u8; 1];
    if stream.read(&mut kind).await? == 0 {
        return Ok(None);
    }
    let Some(kind) = MessageType::from_byte(kind[0]) else {
        bail!(ProtocolViolation(format!(
            "unknown message type {}",
            kind[0]
        )));
    };
    let length = usize::from(stream.read_u16().await?);
    if length > MAX_PAYLOAD_LENGTH {
        bail!(ProtocolViolation(format!(
            "{:?} message of {} bytes, at most {} are allowed",
            kind, length, MAX_PAYLOAD_LENGTH
        )));
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).await?;
    Ok(Some(Message::new(kind, payload)))
}

/// A stream of messages, e.g. the control stream once the tunnel is set up.
///
/// Reading is cancel safe: if a read is cancelled, e.g. in `tokio::select!` because a message
/// has to be sent first, the bytes read so far are kept for the next read.
pub struct MessageStream<S> {
    stream: S,
    /// Bytes of incomplete messages.
    buffer: Vec<u8>,
}

impl<S> MessageStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    /// Reads the next message, or returns `None` if the stream ended before it, see
    /// [`read_message`]. Cancel safe.
    pub async fn read(&mut self) -> Result<Option<Message>> {
        loop {
            if let Some(message) = self.take_message()? {
                return Ok(Some(message));
            }
            let mut chunk = [0u8; 256];
            // Cancel safe: if cancelled, nothing was read.
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the stream ended within a message",
                )
                .into());
            }
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }

    /// Sends `message`, see [`write_message`].
    pub async fn write(&mut self, message: &Message) -> Result<()> {
        write_message(&mut self.stream, message).await
    }

    /// Removes the first message from the buffer and returns it, if it is complete.
    fn take_message(&mut self) -> Result<Option<Message>> {
        let Some(&kind) = self.buffer.first() else {
            return Ok(None);
        };
        let Some(kind) = MessageType::from_byte(kind) else {
            bail!(ProtocolViolation(format!("unknown message type {}", kind)));
        };
        let Some(&[high, low]) = self.buffer.get(1..3) else {
            return Ok(None);
        };
        let length = usize::from(u16::from_be_bytes([high, low]));
        if length > MAX_PAYLOAD_LENGTH {
            bail!(ProtocolViolation(format!(
                "{:?} message of {} bytes, at most {} are allowed",
                kind, length, MAX_PAYLOAD_LENGTH
            )));
        }
        let Some(payload) = self.buffer.get(3..3 + length) else {
            return Ok(None);
        };
        let message = Message::new(kind, payload.to_vec());
        self.buffer.drain(..3 + length);
        Ok(Some(message))
    }
}

/// IDs of the parameters, see docs/PROTOCOL.md.
pub(crate) mod param {
    /// The sender's software and version, e.g. `portredirect_client 1.0.0`. Only for logs.
    pub const SOFTWARE: u16 = 1;
    /// The port the server should listen on, or listens on.
    pub const LISTEN_PORT: u16 = 2;
    /// The address of the external client of a forwarded connection.
    pub const PEER: u16 = 3;
}

/// Maximum length of a text parameter, e.g. [`param::SOFTWARE`].
pub const MAX_TEXT_LENGTH: usize = 64;

const IPV4: u8 = 4;
const IPV6: u8 = 6;

/// The parameters of a message or of a data stream header, by ID.
///
/// Parameters are encoded in ascending order of their IDs, each as ID (u16), length (u16) and
/// value. Decoding keeps unknown parameters, the typed getters only look at known ones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parameters(BTreeMap<u16, Vec<u8>>);

impl Parameters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets parameter `id` to `value`, replacing a previous value.
    pub fn insert(&mut self, id: u16, value: impl Into<Vec<u8>>) -> &mut Self {
        self.0.insert(id, value.into());
        self
    }

    /// Sets parameter `id` to a 16-bit number.
    pub fn insert_u16(&mut self, id: u16, value: u16) -> &mut Self {
        self.insert(id, value.to_be_bytes())
    }

    /// Sets parameter `id` to `text`, shortened to [`MAX_TEXT_LENGTH`] bytes if necessary.
    pub fn insert_text(&mut self, id: u16, text: &str) -> &mut Self {
        let mut end = text.len().min(MAX_TEXT_LENGTH);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.insert(id, &text.as_bytes()[..end])
    }

    /// Sets parameter `id` to a socket address. IPv4-mapped IPv6 addresses are sent as IPv4.
    pub fn insert_address(&mut self, id: u16, address: SocketAddr) -> &mut Self {
        let mut value = Vec::with_capacity(19);
        match address.ip().to_canonical() {
            IpAddr::V4(ip) => {
                value.push(IPV4);
                value.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                value.push(IPV6);
                value.extend_from_slice(&ip.octets());
            }
        }
        value.extend_from_slice(&address.port().to_be_bytes());
        self.insert(id, value)
    }

    /// Returns the raw value of parameter `id`.
    pub fn get(&self, id: u16) -> Option<&[u8]> {
        self.0.get(&id).map(Vec::as_slice)
    }

    /// Returns parameter `id` as a 16-bit number.
    pub fn get_u16(&self, id: u16) -> Result<Option<u16>, ProtocolViolation> {
        self.get(id)
            .map(|value| {
                <[u8; 2]>::try_from(value)
                    .map(u16::from_be_bytes)
                    .map_err(|_| invalid(id, "a 16-bit number"))
            })
            .transpose()
    }

    /// Returns parameter `id` as text of at most [`MAX_TEXT_LENGTH`] bytes.
    pub fn get_text(&self, id: u16) -> Result<Option<&str>, ProtocolViolation> {
        self.get(id)
            .map(|value| {
                std::str::from_utf8(value)
                    .ok()
                    .filter(|text| text.len() <= MAX_TEXT_LENGTH)
                    .ok_or_else(|| invalid(id, "text"))
            })
            .transpose()
    }

    /// Returns parameter `id` as a socket address.
    pub fn get_address(&self, id: u16) -> Result<Option<SocketAddr>, ProtocolViolation> {
        self.get(id)
            .map(|value| {
                let ip = match value {
                    [IPV4, octets @ .., _, _] if octets.len() == 4 => {
                        IpAddr::from(<[u8; 4]>::try_from(octets).expect("checked length"))
                    }
                    [IPV6, octets @ .., _, _] if octets.len() == 16 => {
                        IpAddr::from(<[u8; 16]>::try_from(octets).expect("checked length"))
                    }
                    _ => return Err(invalid(id, "an address")),
                };
                let port = u16::from_be_bytes([value[value.len() - 2], value[value.len() - 1]]);
                Ok(SocketAddr::new(ip, port))
            })
            .transpose()
    }

    /// Returns parameter `id`, which the message `what` must contain.
    pub fn require<T>(
        value: Result<Option<T>, ProtocolViolation>,
        id: u16,
        what: &str,
    ) -> Result<T, ProtocolViolation> {
        value?.ok_or_else(|| ProtocolViolation(format!("{} without parameter {}", what, id)))
    }

    /// Returns the parameters as they are sent.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        for (id, value) in &self.0 {
            encoded.extend_from_slice(&id.to_be_bytes());
            // Values are short, and senders check the length of the whole encoding.
            encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
            encoded.extend_from_slice(value);
        }
        encoded
    }

    /// Decodes parameters. A truncated parameter or an ID that occurs twice is a protocol
    /// violation.
    pub fn decode(mut bytes: &[u8]) -> Result<Self, ProtocolViolation> {
        let mut parameters = Self::new();
        while !bytes.is_empty() {
            let [id_high, id_low, length_high, length_low, rest @ ..] = bytes else {
                return Err(ProtocolViolation("truncated parameter".into()));
            };
            let id = u16::from_be_bytes([*id_high, *id_low]);
            let length = usize::from(u16::from_be_bytes([*length_high, *length_low]));
            if rest.len() < length {
                return Err(ProtocolViolation(format!("truncated parameter {}", id)));
            }
            let (value, rest) = rest.split_at(length);
            if parameters.0.insert(id, value.to_vec()).is_some() {
                return Err(ProtocolViolation(format!("parameter {} occurs twice", id)));
            }
            bytes = rest;
        }
        Ok(parameters)
    }
}

fn invalid(id: u16, expected: &str) -> ProtocolViolation {
    ProtocolViolation(format!("parameter {} is not {}", id, expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::duplex;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    async fn roundtrip(message: &Message) -> Message {
        let (mut sender, mut receiver) = duplex(4096);
        write_message(&mut sender, message).await.unwrap();
        read_message(&mut receiver).await.unwrap().unwrap()
    }

    /// Returns the errors of reading `bytes` as a message, with [`read_message`] and with a
    /// [`MessageStream`].
    async fn read_errors(bytes: &[u8]) -> [anyhow::Error; 2] {
        let (mut sender, mut receiver) = duplex(4096);
        sender.write_all(bytes).await.unwrap();
        drop(sender);
        let read_message_error = read_message(&mut receiver).await.unwrap_err();

        let (mut sender, receiver) = duplex(4096);
        sender.write_all(bytes).await.unwrap();
        drop(sender);
        let stream_error = MessageStream::new(receiver).read().await.unwrap_err();
        [read_message_error, stream_error]
    }

    #[tokio::test]
    async fn test_messages_roundtrip() {
        for message in [
            Message::empty(MessageType::Ping),
            Message::new(MessageType::Hello, vec![1, 2, 3]),
            Message::new(MessageType::Drain, vec![0; MAX_PAYLOAD_LENGTH]),
        ] {
            assert_eq!(roundtrip(&message).await, message);
        }
    }

    #[test]
    fn test_message_format() {
        // As described in docs/PROTOCOL.md: type, length, payload.
        assert_eq!(
            Message::new(MessageType::Welcome, vec![0xaa, 0xbb])
                .encode()
                .unwrap(),
            [2, 0, 2, 0xaa, 0xbb]
        );
        let types: Vec<u8> = MessageType::ALL.iter().map(|&kind| kind as u8).collect();
        assert_eq!(types, [1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn test_too_long_messages_are_not_sent() {
        let (mut sender, _receiver) = duplex(4096);
        let message = Message::new(MessageType::Hello, vec![0; MAX_PAYLOAD_LENGTH + 1]);
        let err = write_message(&mut sender, &message).await.unwrap_err();
        assert!(err.to_string().contains("too long"), "{:#}", err);
    }

    #[tokio::test]
    async fn test_end_of_stream_before_a_message() {
        let (sender, mut receiver) = duplex(64);
        drop(sender);
        assert_eq!(read_message(&mut receiver).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_invalid_messages_are_protocol_violations() {
        for (bytes, expected) in [
            (&[0u8, 0, 0][..], "unknown message type 0"),
            (&[6, 0, 0], "unknown message type 6"),
            (&[1, 0x04, 0x01], "Hello message of 1025 bytes"),
        ] {
            for err in read_errors(bytes).await {
                assert!(err.is::<ProtocolViolation>(), "{:?}: {:#}", bytes, err);
                assert!(err.to_string().contains(expected), "{:?}: {:#}", bytes, err);
            }
        }
    }

    #[tokio::test]
    async fn test_truncated_messages_are_stream_errors() {
        // The stream ended in the middle of a message, e.g. because the connection was lost.
        for bytes in [&[3u8][..], &[3, 0], &[1, 0, 2, 0xaa]] {
            for err in read_errors(bytes).await {
                assert!(!err.is::<ProtocolViolation>(), "{:?}: {:#}", bytes, err);
                let io_error = err.downcast_ref::<std::io::Error>();
                assert_eq!(
                    io_error.map(std::io::Error::kind),
                    Some(std::io::ErrorKind::UnexpectedEof),
                    "{:?}: {:#}",
                    bytes,
                    err
                );
            }
        }
    }

    #[tokio::test]
    async fn test_message_stream_reads_messages_split_and_joined() {
        let messages = [
            Message::empty(MessageType::Ping),
            Message::new(MessageType::Hello, vec![1, 2, 3]),
            Message::new(MessageType::Drain, vec![0; MAX_PAYLOAD_LENGTH]),
            Message::empty(MessageType::Pong),
        ];
        let bytes: Vec<u8> = messages
            .iter()
            .flat_map(|message| message.encode().unwrap())
            .collect();
        // Byte by byte, and all at once.
        for chunk_size in [1, bytes.len()] {
            let (mut sender, receiver) = duplex(4096);
            let mut stream = MessageStream::new(receiver);
            let writer = tokio::spawn({
                let bytes = bytes.clone();
                async move {
                    for chunk in bytes.chunks(chunk_size) {
                        sender.write_all(chunk).await.unwrap();
                        tokio::task::yield_now().await;
                    }
                }
            });
            for message in &messages {
                assert_eq!(stream.read().await.unwrap().as_ref(), Some(message));
            }
            writer.await.unwrap();
            assert_eq!(stream.read().await.unwrap(), None);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_message_stream_reads_are_cancel_safe() {
        let (mut sender, receiver) = duplex(64);
        let mut stream = MessageStream::new(receiver);
        let hello = Message::new(MessageType::Hello, vec![0xaa, 0xbb])
            .encode()
            .unwrap();

        // A read gets part of the message, and is cancelled while waiting for the rest.
        sender.write_all(&hello[..4]).await.unwrap();
        let cancelled = tokio::time::timeout(Duration::from_secs(1), stream.read()).await;
        assert!(cancelled.is_err(), "{:?}", cancelled);

        sender.write_all(&hello[4..]).await.unwrap();
        let message = stream.read().await.unwrap().unwrap();
        assert_eq!(message, Message::new(MessageType::Hello, vec![0xaa, 0xbb]));
    }

    #[tokio::test]
    async fn test_message_stream_writes_messages() {
        let (sender, mut receiver) = duplex(64);
        let mut stream = MessageStream::new(sender);
        stream
            .write(&Message::empty(MessageType::Drain))
            .await
            .unwrap();
        let message = read_message(&mut receiver).await.unwrap();
        assert_eq!(message, Some(Message::empty(MessageType::Drain)));
    }

    #[test]
    fn test_parameters_roundtrip() {
        let mut parameters = Parameters::new();
        parameters
            .insert_text(param::SOFTWARE, "portredirect_client 1.0.0")
            .insert_u16(param::LISTEN_PORT, 443)
            .insert_address(param::PEER, addr("[2001:db8::1]:50000"));
        let decoded = Parameters::decode(&parameters.encode()).unwrap();

        assert_eq!(decoded, parameters);
        assert_eq!(
            decoded.get_text(param::SOFTWARE).unwrap(),
            Some("portredirect_client 1.0.0")
        );
        assert_eq!(decoded.get_u16(param::LISTEN_PORT).unwrap(), Some(443));
        assert_eq!(
            decoded.get_address(param::PEER).unwrap(),
            Some(addr("[2001:db8::1]:50000"))
        );
        assert_eq!(decoded.get_u16(99).unwrap(), None);
    }

    #[test]
    fn test_parameter_format() {
        // As described in docs/PROTOCOL.md: ID, length and value, in ascending order of the IDs.
        let mut parameters = Parameters::new();
        parameters
            .insert_u16(param::LISTEN_PORT, 443)
            .insert_text(param::SOFTWARE, "x");
        assert_eq!(
            parameters.encode(),
            [0, 1, 0, 1, b'x', 0, 2, 0, 2, 0x01, 0xbb]
        );

        let mut peer = Parameters::new();
        peer.insert_address(param::PEER, addr("192.0.2.1:50000"));
        assert_eq!(
            peer.encode(),
            [0, 3, 0, 7, 4, 0xc0, 0x00, 0x02, 0x01, 0xc3, 0x50]
        );
    }

    #[test]
    fn test_unknown_parameters_are_kept_and_skipped() {
        let mut parameters = Parameters::new();
        parameters
            .insert(0x1234, b"from a newer version".as_slice())
            .insert_u16(param::LISTEN_PORT, 80);
        let decoded = Parameters::decode(&parameters.encode()).unwrap();
        assert_eq!(decoded.get_u16(param::LISTEN_PORT).unwrap(), Some(80));
        assert_eq!(
            decoded.get(0x1234),
            Some(b"from a newer version".as_slice())
        );
    }

    #[test]
    fn test_ipv4_mapped_addresses_are_sent_as_ipv4() {
        let mut parameters = Parameters::new();
        parameters.insert_address(param::PEER, addr("[::ffff:192.0.2.1]:50000"));
        assert_eq!(
            parameters.get_address(param::PEER).unwrap(),
            Some(addr("192.0.2.1:50000"))
        );
    }

    #[test]
    fn test_long_text_is_shortened_at_a_character_boundary() {
        let mut parameters = Parameters::new();
        // 63 ASCII characters and a 2-byte character that doesn't fit completely.
        let text = format!("{}é", "a".repeat(MAX_TEXT_LENGTH - 1));
        parameters.insert_text(param::SOFTWARE, &text);
        assert_eq!(
            parameters.get_text(param::SOFTWARE).unwrap(),
            Some("a".repeat(MAX_TEXT_LENGTH - 1).as_str())
        );
    }

    #[test]
    fn test_invalid_parameters_are_protocol_violations() {
        let invalid_encodings: [&[u8]; 4] = [
            &[0, 1, 0],
            &[0, 1, 0, 5, b'a'],
            &[0, 2, 0, 2, 0, 80, 0, 2, 0, 2, 0, 81],
            &[0],
        ];
        for bytes in invalid_encodings {
            assert!(Parameters::decode(bytes).is_err(), "{:?}", bytes);
        }

        let mut parameters = Parameters::new();
        parameters
            .insert(param::LISTEN_PORT, [1u8, 2, 3])
            .insert(param::SOFTWARE, [0xffu8, 0xfe])
            .insert(param::PEER, [4u8, 127, 0, 0, 1, 0]);
        assert!(parameters.get_u16(param::LISTEN_PORT).is_err());
        assert!(parameters.get_text(param::SOFTWARE).is_err());
        assert!(parameters.get_address(param::PEER).is_err());
        for value in [&[5u8, 127, 0, 0, 1, 0, 80][..], &[6, 0, 0], &[]] {
            parameters.insert(param::PEER, value);
            assert!(parameters.get_address(param::PEER).is_err(), "{:?}", value);
        }
        parameters.insert(param::SOFTWARE, vec![b'a'; MAX_TEXT_LENGTH + 1]);
        assert!(parameters.get_text(param::SOFTWARE).is_err());
    }

    #[test]
    fn test_required_parameters() {
        let parameters = Parameters::new();
        let err =
            Parameters::require(parameters.get_u16(param::LISTEN_PORT), 2, "HELLO").unwrap_err();
        assert_eq!(
            err.to_string(),
            "protocol violation: HELLO without parameter 2"
        );
    }
}
