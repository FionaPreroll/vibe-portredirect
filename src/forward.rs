// PortRedirect
//
// License: GPL-3.0-only

use anyhow::{Context, Result};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite};
use tracing::info;

use crate::metrics_helper::MetricsCounter;

/// Forwards data bidirectionally between two asynchronous streams.
///
/// This function copies data between two streams concurrently using a fixed buffer size defined by
/// `PortRedirectProtocol::QUIC_STREAM_READ_BUFFER_SIZE`. As data is transferred, the provided counters
/// are incremented by the number of bytes forwarded in each direction. If the copy completes without
/// errors, the function returns `Ok(())`. If an error occurs, it is wrapped with additional context.
/// However, if the error message contains `"error 0"`, this is interpreted as a graceful shutdown,
/// and the function returns success.
///
/// # Parameters
///
/// - `a`: A mutable reference to the first stream implementing both `AsyncRead` and `AsyncWrite`.
/// - `b`: A mutable reference to the second stream implementing both `AsyncRead` and `AsyncWrite`.
/// - `id`: A stream identifier (displayable) used for logging purposes.
/// - `stream_a_counter`: A counter that is incremented by the number of bytes read from stream A.
/// - `stream_b_counter`: A counter that is incremented by the number of bytes read from stream B.
///
/// # Returns
///
/// Returns `Ok(())` if the bidirectional copy completes (or a graceful shutdown is detected),
/// or an error wrapped with context if a non-graceful error occurs.
///
/// # Errors
///
/// If the underlying I/O operations fail with an error that does **not** contain `"error 0"` in its
/// description, an error with additional context `"Bidirectional copy failed"` is returned.
///
/// # Examples
///
/// ```no_run
/// # use portredirect::forward::forward_bidirectional;
/// # use portredirect::metrics_helper::DummyCounter;
/// # use tokio::io::{duplex, AsyncRead, AsyncWrite};
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// let (mut a, mut b) = duplex(64);
/// let counter_a = DummyCounter::new();
/// let counter_b = DummyCounter::new();
/// forward_bidirectional(&mut a, &mut b, "stream1", &counter_a, &counter_b).await?;
/// # Ok(())
/// # }
/// ```
pub async fn forward_bidirectional<StreamA, StreamB, StreamName, CounterA, CounterB>(
    a: &mut StreamA,
    b: &mut StreamB,
    id: StreamName,
    stream_a_counter: CounterA,
    stream_b_counter: CounterB,
) -> Result<()>
where
    StreamA: AsyncRead + AsyncWrite + Unpin,
    StreamB: AsyncRead + AsyncWrite + Unpin,
    StreamName: std::fmt::Display,
    CounterA: MetricsCounter,
    CounterB: MetricsCounter,
{
    let buf_size = crate::PortRedirectProtocol::QUIC_STREAM_READ_BUFFER_SIZE;
    let result = copy_bidirectional_with_sizes(a, b, buf_size, buf_size).await;

    match result {
        Ok((bytes_a, bytes_b)) => {
            stream_a_counter.inc_by(bytes_a);
            stream_b_counter.inc_by(bytes_b);
            info!(
                "Stream (id={}): forwarded (A:B) ({}:{}) bytes",
                id, bytes_a, bytes_b
            );
            Ok(())
        }
        Err(err) => {
            // If the error indicates a graceful shutdown, log it and return success.
            if err.to_string().contains("error 0") {
                info!("Stream (id={}): graceful shutdown detected: {}", id, err);
                Ok(())
            } else {
                Err(err).context("Bidirectional copy failed")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics_helper::DummyCounter;
    use anyhow::Result;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// A simple in-memory test stream that has a read buffer and collects written data.
    #[derive(Debug)]
    struct TestStream {
        /// Data that will be "read" from this stream.
        read_data: Vec<u8>,
        /// Data that has been "written" to this stream.
        write_data: Vec<u8>,
        /// Current read position.
        pos: usize,
    }

    impl TestStream {
        fn new(initial_data: &[u8]) -> Self {
            Self {
                read_data: initial_data.to_vec(),
                write_data: Vec::new(),
                pos: 0,
            }
        }
    }

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            let remaining = &self.read_data[self.pos..];
            if remaining.is_empty() {
                // Signal EOF by not filling any new data.
                return Poll::Ready(Ok(()));
            }
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            self.write_data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A stream that fails immediately when read or written.
    struct FailingStream;

    impl AsyncRead for FailingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "read failure",
            )))
        }
    }

    impl AsyncWrite for FailingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "write failure",
            )))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_forward_bidirectional_success() -> Result<()> {
        // Stream A will "send" the bytes in "hello" and expect to receive data from B.
        let mut stream_a = TestStream::new(b"hello");
        // Stream B will "send" the bytes in "world" and expect to receive data from A.
        let mut stream_b = TestStream::new(b"world");

        // Create dummy counters for both directions.
        let dummy_counter_a = DummyCounter::new();
        let dummy_counter_b = DummyCounter::new();

        // Run the forwarding function.
        forward_bidirectional(
            &mut stream_a,
            &mut stream_b,
            "A",
            &dummy_counter_a,
            &dummy_counter_b,
        )
        .await?;

        // After bidirectional copy, stream_a should have received stream_b's data, and vice versa.
        assert_eq!(stream_a.write_data, b"world");
        assert_eq!(stream_b.write_data, b"hello");

        Ok(())
    }

    #[tokio::test]
    async fn test_forward_bidirectional_failure() {
        let mut normal_stream = TestStream::new(b"data");
        let mut failing_stream = FailingStream;

        // Create dummy counters for both directions.
        let dummy_counter_a = DummyCounter::new();
        let dummy_counter_b = DummyCounter::new();

        // One of the streams will immediately fail; our function should return an error with the proper context.
        let result = forward_bidirectional(
            &mut failing_stream,
            &mut normal_stream,
            "fail",
            &dummy_counter_a,
            &dummy_counter_b,
        )
        .await;
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.err().unwrap());
        assert!(
            err_msg.contains("Bidirectional copy failed"),
            "Error message did not contain expected context, got: {}",
            err_msg
        );
    }

    /// A stream that simulates a graceful shutdown error by returning errors containing "error 0".
    struct GracefulStream;

    impl AsyncRead for GracefulStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "sending stopped by peer: error 0",
            )))
        }
    }

    impl AsyncWrite for GracefulStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "sending stopped by peer: error 0",
            )))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_forward_bidirectional_graceful_shutdown() -> Result<()> {
        // Use a normal TestStream for one side.
        let mut normal_stream = TestStream::new(b"normal");
        // Use the graceful stream for the other side.
        let mut graceful_stream = GracefulStream;

        // Create dummy counters for both directions.
        let dummy_counter_a = DummyCounter::new();
        let dummy_counter_b = DummyCounter::new();

        // When one side produces an error containing "error 0", our forward_bidirectional
        // function should treat it as a graceful shutdown and return Ok(()).
        forward_bidirectional(
            &mut normal_stream,
            &mut graceful_stream,
            "normal",
            &dummy_counter_a,
            &dummy_counter_b,
        )
        .await?;

        Ok(())
    }
}
