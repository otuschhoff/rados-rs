use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::frame::{CrcCodec, Frame, Limits};
use super::secure::{SecureCodec, SecureDecoder, SecureEncoder};
use super::session::SessionError;

pub(crate) trait IoStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

pub(crate) enum Codec {
    Crc(CrcCodec),
    Secure(Box<SecureCodec>),
}

enum Encoder {
    Crc(CrcCodec),
    Secure(Box<SecureEncoder>),
}

enum Decoder {
    Crc(CrcCodec),
    Secure(Box<SecureDecoder>),
}

impl Codec {
    fn split(self) -> (Encoder, Decoder) {
        match self {
            Self::Crc(codec) => (Encoder::Crc(codec), Decoder::Crc(codec)),
            Self::Secure(codec) => {
                let (encoder, decoder) = (*codec).split();
                (
                    Encoder::Secure(Box::new(encoder)),
                    Decoder::Secure(Box::new(decoder)),
                )
            }
        }
    }
}

impl Encoder {
    fn encode(&mut self, frame: &Frame, limits: Limits) -> Result<Vec<u8>, SessionError> {
        match self {
            Self::Crc(codec) => codec.encode(frame, limits),
            Self::Secure(codec) => codec.encode(frame, limits),
        }
        .map_err(SessionError::Frame)
    }
}

impl Decoder {
    async fn read(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin),
        limits: Limits,
    ) -> Result<Frame, SessionError> {
        match self {
            Self::Crc(codec) => codec.read_async(reader, limits).await,
            Self::Secure(codec) => codec.read(reader, limits).await,
        }
        .map_err(SessionError::Frame)
    }
}

#[derive(Debug)]
pub(crate) enum Event {
    Frame {
        generation: u64,
        frame: Frame,
    },
    WriteComplete {
        generation: u64,
        request_id: Option<u64>,
        result: Result<(), SessionError>,
    },
    Fault {
        generation: u64,
        error: SessionError,
    },
    RenewalDue {
        generation: u64,
    },
}

#[derive(Debug)]
struct Write {
    request_id: Option<u64>,
    frame: Frame,
}

pub(crate) struct Connection {
    writes: mpsc::Sender<Write>,
    close: watch::Sender<bool>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl Connection {
    pub(crate) fn spawn(
        generation: u64,
        stream: Box<dyn IoStream>,
        codec: Codec,
        renewal_after: Option<Duration>,
        limits: Limits,
        events: mpsc::Sender<Event>,
    ) -> Self {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (mut encoder, mut decoder) = codec.split();
        let (write_tx, mut write_rx) = mpsc::channel::<Write>(1);
        let (close, mut reader_close) = watch::channel(false);
        let mut writer_close = close.subscribe();
        let reader_events = events.clone();

        spawn_renewal(generation, renewal_after, &events, &close);

        let reader = tokio::spawn(async move {
            loop {
                let result = tokio::select! {
                    biased;
                    changed = reader_close.changed() => {
                        if changed.is_ok() || *reader_close.borrow() {
                            return;
                        }
                        return;
                    }
                    result = decoder.read(&mut reader, limits) => result,
                };
                match result {
                    Ok(frame) => {
                        tokio::select! {
                            biased;
                            changed = reader_close.changed() => {
                                let _ = changed;
                                return;
                            }
                            result = reader_events.send(Event::Frame { generation, frame }) => {
                                if result.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        tokio::select! {
                            biased;
                            changed = reader_close.changed() => {
                                let _ = changed;
                            }
                            result = reader_events.send(Event::Fault { generation, error }) => {
                                let _ = result;
                            }
                        }
                        return;
                    }
                }
            }
        });

        let writer = tokio::spawn(async move {
            loop {
                let task = tokio::select! {
                    biased;
                    changed = writer_close.changed() => {
                        if changed.is_ok() || *writer_close.borrow() {
                            return;
                        }
                        return;
                    }
                    task = write_rx.recv() => task,
                };
                let Some(task) = task else {
                    return;
                };
                let result = match encoder.encode(&task.frame, limits) {
                    Ok(wire) => tokio::select! {
                        biased;
                        changed = writer_close.changed() => {
                            let _ = changed;
                            return;
                        }
                        result = writer.write_all(&wire) => result.map_err(|error| map_io_error(&error)),
                    },
                    Err(error) => Err(error),
                };
                let failed = result.is_err();
                let published = tokio::select! {
                    biased;
                    changed = writer_close.changed() => {
                        let _ = changed;
                        return;
                    }
                    result = events.send(Event::WriteComplete {
                        generation,
                        request_id: task.request_id,
                        result,
                    }) => result,
                };
                if published.is_err() || failed {
                    return;
                }
            }
        });

        Self {
            writes: write_tx,
            close,
            reader,
            writer,
        }
    }

    pub(crate) async fn write(
        &self,
        request_id: Option<u64>,
        frame: Frame,
    ) -> Result<(), SessionError> {
        self.writes
            .send(Write { request_id, frame })
            .await
            .map_err(|_| SessionError::Disconnected)
    }

    pub(crate) async fn close(self) {
        let _ = self.close.send(true);
        drop(self.writes);
        let _ = self.reader.await;
        let _ = self.writer.await;
    }
}

fn spawn_renewal(
    generation: u64,
    renewal_after: Option<Duration>,
    events: &mpsc::Sender<Event>,
    close: &watch::Sender<bool>,
) {
    let Some(delay) = renewal_after else {
        return;
    };
    let renewal_events = events.clone();
    let mut renewal_close = close.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            biased;
            changed = renewal_close.changed() => {
                let _ = changed;
            }
            () = tokio::time::sleep(delay) => {
                let _ = renewal_events.send(Event::RenewalDue { generation }).await;
            }
        }
    });
}

fn map_io_error(error: &io::Error) -> SessionError {
    match error.kind() {
        io::ErrorKind::OutOfMemory => SessionError::Frame(super::frame::FrameError::LimitExceeded),
        _ => SessionError::Disconnected,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;
    use crate::msgr::frame::{DEFAULT_ALIGNMENT, FrameError, Segment, Tag};

    const LIMITS: Limits = Limits {
        max_segment_bytes: 4096,
        max_frame_bytes: 8192,
        max_addresses: 4,
        max_auth_bytes: 4096,
    };

    #[derive(Default)]
    struct Script {
        reads: VecDeque<Vec<u8>>,
        written: Vec<u8>,
        write_limit: usize,
        fail_after: Option<usize>,
        block_read: bool,
        block_write: bool,
        read_waker: Option<Waker>,
        write_waker: Option<Waker>,
    }

    #[derive(Clone, Default)]
    struct FaultStream(Arc<Mutex<Script>>);

    impl FaultStream {
        fn with_read(data: Vec<u8>) -> Self {
            let reads = data.into_iter().map(|byte| vec![byte]).collect();
            Self(Arc::new(Mutex::new(Script {
                reads,
                write_limit: 1,
                block_read: true,
                ..Script::default()
            })))
        }

        fn written(&self) -> Vec<u8> {
            self.0.lock().expect("script mutex").written.clone()
        }
    }

    impl AsyncRead for FaultStream {
        fn poll_read(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut script = self.0.lock().expect("script mutex");
            if let Some(mut chunk) = script.reads.pop_front() {
                let count = chunk.len().min(output.remaining());
                output.put_slice(&chunk[..count]);
                if count < chunk.len() {
                    chunk.drain(..count);
                    script.reads.push_front(chunk);
                }
                return Poll::Ready(Ok(()));
            }
            if script.block_read {
                script.read_waker = Some(context.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for FaultStream {
        fn poll_write(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut script = self.0.lock().expect("script mutex");
            if script.block_write {
                script.write_waker = Some(context.waker().clone());
                return Poll::Pending;
            }
            if script
                .fail_after
                .is_some_and(|limit| script.written.len() >= limit)
            {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "scripted")));
            }
            let remaining = script.fail_after.map_or(input.len(), |limit| {
                limit.saturating_sub(script.written.len())
            });
            let count = input.len().min(script.write_limit.max(1)).min(remaining);
            script.written.extend_from_slice(&input[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn frame(data: &[u8]) -> Frame {
        Frame {
            tag: Tag::Hello,
            segments: vec![Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: data.to_vec(),
            }],
        }
    }

    #[tokio::test]
    async fn one_byte_reads_and_short_writes_complete_frames() {
        let codec = CrcCodec {
            with_data_crc: true,
        };
        let expected = frame(b"fragmented");
        let wire = codec.encode(&expected, LIMITS).expect("encode");
        let stream = FaultStream::with_read(wire);
        let observer = stream.clone();
        let (events, mut event_rx) = mpsc::channel(4);
        let connection =
            Connection::spawn(7, Box::new(stream), Codec::Crc(codec), None, LIMITS, events);

        let Event::Frame {
            generation,
            frame: decoded,
        } = event_rx.recv().await.expect("frame event")
        else {
            panic!("expected frame");
        };
        assert_eq!(generation, 7);
        assert_eq!(decoded, expected);

        let outgoing = frame(b"short writes");
        let expected_wire = codec.encode(&outgoing, LIMITS).expect("encode");
        connection
            .write(Some(3), outgoing)
            .await
            .expect("queue write");
        let Event::WriteComplete { result, .. } = event_rx.recv().await.expect("write event")
        else {
            panic!("expected write completion");
        };
        assert_eq!(result, Ok(()));
        assert_eq!(observer.written(), expected_wire);
        connection.close().await;
    }

    #[tokio::test]
    async fn invalid_crc_never_dispatches_a_frame() {
        let codec = CrcCodec {
            with_data_crc: true,
        };
        let mut wire = codec.encode(&frame(b"bad"), LIMITS).expect("encode");
        wire[28] ^= 1;
        let (events, mut event_rx) = mpsc::channel(2);
        let connection = Connection::spawn(
            2,
            Box::new(FaultStream::with_read(wire)),
            Codec::Crc(codec),
            None,
            LIMITS,
            events,
        );
        assert!(matches!(
            event_rx.recv().await,
            Some(Event::Fault {
                generation: 2,
                error: SessionError::Frame(FrameError::Integrity)
            })
        ));
        assert!(event_rx.try_recv().is_err());
        connection.close().await;
    }

    #[tokio::test]
    async fn invalid_gcm_never_dispatches_a_frame() {
        let secret =
            std::array::from_fn::<_, 64, _>(|index| u8::try_from(index).expect("secret index"));
        let mut server = SecureCodec::new(&secret, true).expect("server codec");
        let client = SecureCodec::new(&secret, false).expect("client codec");
        let mut wire = server
            .encode(&frame(b"authenticated"), LIMITS)
            .expect("encode");
        let last = wire.last_mut().expect("authentication tag");
        *last ^= 1;
        let (events, mut event_rx) = mpsc::channel(2);
        let connection = Connection::spawn(
            3,
            Box::new(FaultStream::with_read(wire)),
            Codec::Secure(Box::new(client)),
            None,
            LIMITS,
            events,
        );
        assert!(matches!(
            event_rx.recv().await,
            Some(Event::Fault {
                generation: 3,
                error: SessionError::Frame(FrameError::Integrity)
            })
        ));
        assert!(event_rx.try_recv().is_err());
        connection.close().await;
    }

    #[tokio::test]
    async fn partial_write_fault_and_blocked_io_are_closed_and_joined() {
        let stream = FaultStream::default();
        {
            let mut script = stream.0.lock().expect("script mutex");
            script.block_read = true;
            script.write_limit = 2;
            script.fail_after = Some(5);
        }
        let observer = stream.clone();
        let codec = CrcCodec {
            with_data_crc: true,
        };
        let (events, mut event_rx) = mpsc::channel(2);
        let connection =
            Connection::spawn(4, Box::new(stream), Codec::Crc(codec), None, LIMITS, events);
        connection
            .write(Some(9), frame(b"partial"))
            .await
            .expect("queue write");
        assert!(matches!(
            event_rx.recv().await,
            Some(Event::WriteComplete {
                generation: 4,
                request_id: Some(9),
                result: Err(SessionError::Disconnected)
            })
        ));
        assert_eq!(observer.written().len(), 5);
        connection.close().await;

        let blocked = FaultStream::default();
        {
            let mut script = blocked.0.lock().expect("script mutex");
            script.block_read = true;
            script.block_write = true;
        }
        let (events, _event_rx) = mpsc::channel(1);
        let connection = Connection::spawn(
            5,
            Box::new(blocked),
            Codec::Crc(codec),
            None,
            LIMITS,
            events,
        );
        connection
            .write(None, frame(b"blocked"))
            .await
            .expect("queue write");
        connection.close().await;
    }
}
