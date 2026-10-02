use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A bidirectional stream that encapsulates a separate asynchronous reader and writer,
/// along with an identifying name.
///
/// This struct provides a unified interface to both read from and write to a stream while
/// preserving separate components. It implements both [`AsyncRead`] and [`AsyncWrite`]
/// from the Tokio library.
///
/// # Examples
///
/// ```rust
/// # use tokio::io::{AsyncReadExt, AsyncWriteExt};
/// # use tokio::net::TcpStream;
/// # use portredirect::bi_stream::BiStream;
/// # async fn run() -> std::io::Result<()> {
/// // For example, split a TCP stream:
/// let tcp_stream = TcpStream::connect("127.0.0.1:8080").await?;
/// let (read_half, write_half) = tcp_stream.into_split();
///
/// let mut stream = BiStream::new(read_half, write_half, "MyTcpStream".to_string());
///
/// // Use the stream as an AsyncRead
/// let mut buf = [0; 1024];
/// let _ = stream.read.read(&mut buf).await?;
///
/// // And as an AsyncWrite
/// let _ = stream.write.write(b"hello").await?;
/// # Ok(())
/// # }
/// ```
pub struct BiStream<R, W> {
    /// The asynchronous reader component.
    pub read: R,
    /// The asynchronous writer component.
    pub write: W,
    /// A name used to identify the stream.
    pub name: String,
}

impl<R, W> BiStream<R, W> {
    /// Creates a new `BiStream` from the provided reader, writer, and name.
    ///
    /// # Parameters
    ///
    /// - `read`: The asynchronous reader.
    /// - `write`: The asynchronous writer.
    /// - `name`: A string identifier for the stream.
    ///
    /// # Returns
    ///
    /// A new instance of `BiStream`.
    pub fn new(read: R, write: W, name: String) -> Self {
        Self { read, write, name }
    }
}

// Implement AsyncRead when the reader supports AsyncRead and both components are Unpin.
impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for BiStream<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Delegate to the inner reader.
        let this = self.get_mut();
        Pin::new(&mut this.read).poll_read(cx, buf)
    }
}

// Implement AsyncWrite when the writer supports AsyncWrite and both components are Unpin.
impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for BiStream<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.write).poll_shutdown(cx)
    }
}

impl<R, W> fmt::Display for BiStream<R, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BiStream{{{}}}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A simple in-memory stream for testing purposes.
    struct MemoryStream {
        inner: Cursor<Vec<u8>>,
    }

    impl MemoryStream {
        fn new(data: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(data),
            }
        }
    }

    // MemoryStream contains no self-referential data, so it's safe to mark it as Unpin.
    impl Unpin for MemoryStream {}

    impl AsyncRead for MemoryStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let pos = self.inner.position() as usize;
            let data = self.inner.get_ref();
            let available = &data[pos..];

            // If no data is available, return immediately.
            if available.is_empty() {
                return Poll::Ready(Ok(()));
            }

            // Read as much data as fits into the provided buffer.
            let to_read = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_read]);
            self.inner.set_position((pos + to_read) as u64);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MemoryStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            // Append the data to the internal buffer.
            self.inner.get_mut().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_bistream_read() {
        // Prepare the in-memory reader with some data.
        let data = b"hello world".to_vec();
        let reader = MemoryStream::new(data.clone());
        // Use a dummy writer for this test.
        let writer = MemoryStream::new(Vec::new());
        let mut bistream = BiStream::new(reader, writer, "test_read".to_string());

        let mut buffer = vec![0u8; data.len()];
        bistream.read.read_exact(&mut buffer).await.unwrap();

        assert_eq!(buffer, data);
    }

    #[tokio::test]
    async fn test_bistream_write() {
        // Use a dummy reader for this test.
        let reader = MemoryStream::new(Vec::new());
        let writer = MemoryStream::new(Vec::new());
        let mut bistream = BiStream::new(reader, writer, "test_write".to_string());

        let data = b"test data";
        let bytes_written = bistream.write.write(data).await.unwrap();

        assert_eq!(bytes_written, data.len());
    }

    #[test]
    fn test_display() {
        let reader = MemoryStream::new(Vec::new());
        let writer = MemoryStream::new(Vec::new());
        let bistream = BiStream::new(reader, writer, "DisplayTest".to_string());

        assert_eq!(format!("{}", bistream), "BiStream{DisplayTest}");
    }
}
