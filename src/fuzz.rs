// PortRedirect - Entry points for fuzzing
//
// The parsers of the protocol are private, so the fuzz targets in fuzz/ reach them through these
// functions. They are compiled with --cfg fuzzing, which cargo fuzz sets, and for the tests,
// which run them on changed copies of valid input as a smoke test on stable Rust. See
// fuzz/README.md.
//
// Each function feeds its input to one parser, as a peer would send it, and checks properties
// beyond not panicking, e.g. that what one side decodes, the other side encodes the same way.
// Each returns whether the input was well-formed, for the tests.
//
// License: GPL-3.0-only

use secrecy::SecretString;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use crate::protocol::auth::{
    client_authenticate, server_authenticate, AuthenticationRejected, ClientName, PskLookup,
    SessionBinding, SESSION_BINDING_LENGTH,
};
use crate::protocol::control::{
    receive_hello, request_listen_port, send_welcome, Greeting, CLIENT_SOFTWARE,
};
use crate::protocol::data_stream::{receive_connection_header, send_connection_header};
use crate::protocol::keepalive::{run_control_channel_loop, ControlChannelEnd};
use crate::protocol::message::{
    param, read_message, write_message, Message, MessageStream, MessageType, Parameters,
    ProtocolViolation,
};
use crate::shutdown::Shutdown;

const BINDING: SessionBinding = [7; SESSION_BINDING_LENGTH];
const PSK: &str = "fuzzing-psk";

/// Authentication as the server sees it, with the client's messages from `data`.
///
/// Returns whether the client's response was well-formed, i.e. whether the server got to check
/// its proof. The server's challenge is random, so the input can't hold a valid proof: the
/// server must never accept it.
pub fn server_authentication(data: &[u8]) -> bool {
    struct Clients(Vec<SecretString>);

    impl PskLookup for Clients {
        fn psks(&self, name: &ClientName) -> Option<&[SecretString]> {
            (name == &ClientName::default()).then_some(self.0.as_slice())
        }
    }

    let clients = Clients(vec![PSK.into()]);
    let result = run(server_authenticate(
        &mut FuzzStream::new(data),
        &clients,
        &BINDING,
    ));
    let error = result.expect_err("authenticated a client without a valid proof");
    error.is::<AuthenticationRejected>()
}

/// Authentication as the client sees it, with the server's messages from `data`.
///
/// Returns whether the server's messages were well-formed, i.e. whether the client got to check
/// the server's proof. The input can't hold a valid proof without the PSK, so the client must
/// never accept it.
pub fn client_authentication(data: &[u8]) -> bool {
    let psk = SecretString::from(PSK);
    let result = run(client_authenticate(
        &mut FuzzStream::new(data),
        &ClientName::default(),
        &psk,
        &BINDING,
    ));
    let error = result.expect_err("accepted a server without a valid proof");
    error.is::<AuthenticationRejected>()
}

/// HELLO as the server receives it, from `data`.
///
/// Returns whether the server accepted it. A client that sends what the server understood
/// sends the same, apart from unknown parameters.
pub fn hello(data: &[u8]) -> bool {
    let Ok(hello) = run(receive_hello(&mut FuzzStream::new(data))) else {
        return false;
    };
    // The client sends HELLO, then waits for WELCOME, which doesn't come.
    let mut client = FuzzStream::new(&[]);
    assert!(run(request_listen_port(&mut client, &hello)).is_err());
    let sent = run(receive_hello(&mut FuzzStream::of_output(client)));
    assert_eq!(sent.expect("failed to receive a valid HELLO"), hello);
    true
}

/// WELCOME as the client receives it after sending HELLO, from `data`.
///
/// Returns whether the client accepted it. A server that sends what the client understood
/// sends the same, apart from unknown parameters.
pub fn welcome(data: &[u8]) -> bool {
    let hello = Greeting::new(CLIENT_SOFTWARE, 8080);
    let Ok(welcome) = run(request_listen_port(&mut FuzzStream::new(data), &hello)) else {
        return false;
    };
    let mut server = FuzzStream::new(&[]);
    run(send_welcome(&mut server, &welcome)).expect("failed to send WELCOME");
    let sent = run(request_listen_port(
        &mut FuzzStream::of_output(server),
        &hello,
    ));
    assert_eq!(sent.expect("failed to receive a valid WELCOME"), welcome);
    true
}

/// Messages on the control stream once the tunnel is set up, from `data`.
///
/// Reads them with [`read_message`] and with [`MessageStream`], which must agree, and runs the
/// server's control loop on them. Returns whether the server accepted all of them.
pub fn control_messages(data: &[u8]) -> bool {
    let (messages, end) = run(read_messages(FuzzStream::new(data)));
    let (buffered, buffered_end) = run(read_buffered_messages(FuzzStream::new(data)));
    assert_eq!((&buffered, buffered_end), (&messages, end));

    // The messages are what the input holds, unchanged.
    let mut encoded = FuzzStream::new(&[]);
    for message in &messages {
        run(write_message(&mut encoded, message)).expect("failed to encode a message");
    }
    let input = data.get(1..).unwrap_or_default();
    assert!(input.starts_with(&encoded.output));

    // The server answers each PING with PONG, up to the first message it doesn't expect.
    let accepted = messages
        .iter()
        .take_while(|message| matches!(message.kind, MessageType::Ping | MessageType::Drain))
        .count();
    let pings = messages[..accepted]
        .iter()
        .filter(|message| message.kind == MessageType::Ping)
        .count();
    let listener = CancellationToken::new();
    let mut stream = FuzzStream::new(data);
    let loop_end = run(run_control_channel_loop(
        &mut stream,
        listener.clone(),
        Shutdown::default(),
    ));
    assert_eq!(stream.output, [MessageType::Pong as u8, 0, 0].repeat(pings));
    assert!(listener.is_cancelled());
    let expected = if accepted < messages.len() {
        End::Invalid
    } else {
        end
    };
    let ended_as_expected = match expected {
        End::Clean => matches!(loop_end, ControlChannelEnd::StreamClosed(None)),
        End::Truncated => matches!(loop_end, ControlChannelEnd::StreamClosed(Some(_))),
        End::Invalid => matches!(loop_end, ControlChannelEnd::ProtocolViolation(_)),
    };
    assert!(
        ended_as_expected,
        "control loop ended with {:?}, not {:?}",
        loop_end, expected
    );
    expected == End::Clean
}

/// The header of a data stream as the client receives it, from `data`.
///
/// Returns whether the client accepted it. A server that sends the address the client
/// understood sends the same address, IPv4-mapped IPv6 addresses as IPv4.
pub fn connection_header(data: &[u8]) -> bool {
    let Ok(peer) = run(receive_connection_header(&mut FuzzStream::new(data))) else {
        return false;
    };
    let mut server = FuzzStream::new(&[]);
    run(send_connection_header(&mut server, peer)).expect("failed to send the header");
    let sent = run(receive_connection_header(&mut FuzzStream::of_output(
        server,
    )));
    let canonical = SocketAddr::new(peer.ip().to_canonical(), peer.port());
    assert_eq!(sent.expect("failed to receive a valid header"), canonical);
    true
}

/// Parameters of a message or of a data stream header, from `data`.
///
/// Returns whether they were well-formed. Decoding their encoding gives the same parameters.
pub fn parameters(data: &[u8]) -> bool {
    let Ok(parameters) = Parameters::decode(data) else {
        return false;
    };
    for id in [param::SOFTWARE, param::LISTEN_PORT, param::PEER] {
        let _ = parameters.get_u16(id);
        let _ = parameters.get_text(id);
        let _ = parameters.get_address(id);
    }
    let decoded = Parameters::decode(&parameters.encode()).expect("failed to decode the encoding");
    assert_eq!(decoded, parameters);
    true
}

/// How a sequence of messages ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// After a message.
    Clean,
    /// Within a message.
    Truncated,
    /// At an invalid message.
    Invalid,
}

impl End {
    fn of(error: &anyhow::Error) -> Self {
        if error.is::<ProtocolViolation>() {
            End::Invalid
        } else {
            End::Truncated
        }
    }
}

/// Reads all messages with [`read_message`].
async fn read_messages(mut stream: FuzzStream) -> (Vec<Message>, End) {
    let mut messages = Vec::new();
    loop {
        match read_message(&mut stream).await {
            Ok(Some(message)) => messages.push(message),
            Ok(None) => return (messages, End::Clean),
            Err(e) => return (messages, End::of(&e)),
        }
    }
}

/// Reads all messages with [`MessageStream`].
async fn read_buffered_messages(stream: FuzzStream) -> (Vec<Message>, End) {
    let mut stream = MessageStream::new(stream);
    let mut messages = Vec::new();
    loop {
        match stream.read().await {
            Ok(Some(message)) => messages.push(message),
            Ok(None) => return (messages, End::Clean),
            Err(e) => return (messages, End::of(&e)),
        }
    }
}

/// Runs `future` to its end on this thread's runtime.
fn run<F: Future>(future: F) -> F::Output {
    thread_local! {
        static RUNTIME: Runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("failed to build a runtime");
    }
    RUNTIME.with(|runtime| runtime.block_on(future))
}

/// A stream that returns its input in chunks, never waits, and keeps what is written to it.
struct FuzzStream {
    input: Vec<u8>,
    /// Number of input bytes read so far.
    read: usize,
    /// Maximum number of bytes a read returns, so parsers get messages in parts.
    chunk: usize,
    output: Vec<u8>,
}

impl FuzzStream {
    /// Returns a stream whose input is `data` without its first byte, which sets the chunk size.
    fn new(data: &[u8]) -> Self {
        let (chunk, input) = match data.split_first() {
            Some((&chunk, input)) => (usize::from(chunk) + 1, input),
            None => (1, data),
        };
        Self {
            input: input.to_vec(),
            read: 0,
            chunk,
            output: Vec::new(),
        }
    }

    /// Returns a stream whose input is what was written to `stream`.
    fn of_output(stream: FuzzStream) -> Self {
        Self {
            input: stream.output,
            read: 0,
            chunk: usize::MAX,
            output: Vec::new(),
        }
    }
}

impl AsyncRead for FuzzStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream = self.get_mut();
        let rest = &stream.input[stream.read..];
        let length = rest.len().min(stream.chunk).min(buf.remaining());
        buf.put_slice(&rest[..length]);
        stream.read += length;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FuzzStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A small random number generator (xorshift64*), the same in every run.
    struct Random(u64);

    impl Random {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn byte(&mut self) -> u8 {
            self.next() as u8
        }
    }

    /// Returns `seed` with a few random changes, like a fuzzer makes them.
    fn mutate(seed: &[u8], random: &mut Random) -> Vec<u8> {
        let mut input = seed.to_vec();
        for _ in 0..=random.below(3) {
            let position = random.below(input.len() + 1);
            match (random.below(5), position < input.len()) {
                (0, true) => input[position] ^= 1 << random.below(8),
                (1, true) => input[position] = random.byte(),
                (2, true) => {
                    input.remove(position);
                }
                (3, _) => input.insert(position, random.byte()),
                _ => input.truncate(position),
            }
        }
        input
    }

    /// Runs `target` on `seeds`, which must be well-formed, on changed copies of them and on
    /// random bytes.
    fn smoke_test(target: fn(&[u8]) -> bool, seeds: &[Vec<u8>]) {
        for seed in seeds {
            assert!(target(seed), "{:?} isn't well-formed", seed);
        }
        let mut random = Random(0x9e37_79b9_7f4a_7c15);
        for _ in 0..2000 {
            let seed = &seeds[random.below(seeds.len())];
            target(&mutate(seed, &mut random));
        }
        for _ in 0..200 {
            let length = random.below(80);
            let input: Vec<u8> = (0..length).map(|_| random.byte()).collect();
            target(&input);
        }
    }

    /// Prepends the byte that sets the chunk size of [`FuzzStream`].
    fn chunked(chunk: u8, input: &[u8]) -> Vec<u8> {
        [&[chunk], input].concat()
    }

    fn message(kind: MessageType, payload: &[u8]) -> Vec<u8> {
        let length = payload.len() as u16;
        [&[kind as u8], &length.to_be_bytes()[..], payload].concat()
    }

    fn greeting(kind: MessageType, software: Option<&str>, port: u16) -> Vec<u8> {
        let mut parameters = Parameters::new();
        if let Some(software) = software {
            parameters.insert_text(param::SOFTWARE, software);
        }
        parameters.insert_u16(param::LISTEN_PORT, port);
        message(kind, &parameters.encode())
    }

    fn header(peer: &str) -> Vec<u8> {
        let mut parameters = Parameters::new();
        parameters.insert_address(param::PEER, peer.parse().unwrap());
        let parameters = parameters.encode();
        [&(parameters.len() as u16).to_be_bytes()[..], &parameters].concat()
    }

    #[test]
    fn test_fuzz_stream_returns_its_input_in_chunks_and_keeps_writes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // The first byte sets chunks of 2 bytes.
        let mut stream = FuzzStream::new(&[1, 10, 11, 12, 13, 14]);
        let mut buffer = [0; 8];
        assert_eq!(run(stream.read(&mut buffer)).unwrap(), 2);
        assert_eq!(buffer[..2], [10, 11]);
        let mut rest = Vec::new();
        run(stream.read_to_end(&mut rest)).unwrap();
        assert_eq!(rest, [12, 13, 14]);

        run(async {
            stream.write_all(b"written").await?;
            stream.shutdown().await
        })
        .unwrap();
        assert_eq!(FuzzStream::of_output(stream).input, b"written");
    }

    #[test]
    fn test_server_authentication_survives_invalid_input() {
        let response = |name: &str| {
            let name = [&[name.len() as u8], name.as_bytes()].concat();
            [&b"RESPONSE"[..], &name, &[0x5a; 32]].concat()
        };
        smoke_test(
            server_authentication,
            &[
                chunked(0, &response("default")),
                chunked(255, &response("unknown-client")),
            ],
        );
    }

    #[test]
    fn test_client_authentication_survives_invalid_input() {
        let messages = [&b"CHALLENGE"[..], &[1; 32], b"ACCEPTED", &[2; 32]].concat();
        smoke_test(
            client_authentication,
            &[chunked(0, &messages), chunked(16, &messages)],
        );
    }

    #[test]
    fn test_hello_survives_invalid_input() {
        let mut unknown_parameter = Parameters::new();
        unknown_parameter
            .insert_u16(param::LISTEN_PORT, 443)
            .insert(99, vec![0]);
        smoke_test(
            hello,
            &[
                chunked(
                    0,
                    &greeting(MessageType::Hello, Some(CLIENT_SOFTWARE), 8080),
                ),
                chunked(7, &greeting(MessageType::Hello, None, 443)),
                chunked(
                    255,
                    &message(MessageType::Hello, &unknown_parameter.encode()),
                ),
            ],
        );
    }

    #[test]
    fn test_welcome_survives_invalid_input() {
        smoke_test(
            welcome,
            &[
                chunked(0, &greeting(MessageType::Welcome, Some("server"), 8080)),
                chunked(9, &greeting(MessageType::Welcome, None, 1)),
            ],
        );
    }

    #[test]
    fn test_control_messages_survive_invalid_input() {
        let ping = message(MessageType::Ping, &[]);
        let drain = message(MessageType::Drain, &[]);
        smoke_test(
            control_messages,
            &[
                chunked(0, &[ping.clone(), drain, ping.clone()].concat()),
                chunked(2, &[ping, message(MessageType::Ping, b"data")].concat()),
                chunked(255, &[]),
            ],
        );
    }

    #[test]
    fn test_control_loop_stops_at_unexpected_messages() {
        let ping = message(MessageType::Ping, &[]);
        let pong = message(MessageType::Pong, &[]);
        // Answers the PING, not the one after the PONG.
        assert!(!control_messages(&chunked(
            0,
            &[ping.clone(), pong, ping].concat()
        )));
    }

    #[test]
    fn test_connection_header_survives_invalid_input() {
        smoke_test(
            connection_header,
            &[
                chunked(0, &header("192.0.2.1:443")),
                chunked(5, &header("[2001:db8::1]:8443")),
                chunked(255, &header("[::ffff:192.0.2.1]:80")),
            ],
        );
    }

    #[test]
    fn test_parameters_survive_invalid_input() {
        let mut all = Parameters::new();
        all.insert_text(param::SOFTWARE, "software")
            .insert_u16(param::LISTEN_PORT, 8080)
            .insert_address(param::PEER, SocketAddr::from((Ipv4Addr::LOCALHOST, 80)))
            .insert(1000, b"unknown".to_vec());
        smoke_test(parameters, &[Vec::new(), all.encode()]);
    }
}
