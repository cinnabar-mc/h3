use std::{collections::VecDeque, future::Future};

use bytes::BytesMut;
use futures_util::task::noop_waker_ref;

use super::*;

/// Supplies finite transport results; no queued result means an open, pending stream.
#[derive(Default)]
struct FakeRecv {
    chunks: VecDeque<Result<Option<Bytes>, StreamErrorIncoming>>,
}

impl FakeRecv {
    /// Makes the next actual receive poll yield these bytes without ending the stream.
    fn chunk(&mut self, bytes: Bytes) {
        self.chunks.push_back(Ok(Some(bytes)));
    }
}

impl RecvStream for FakeRecv {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.chunks.pop_front().map_or(Poll::Pending, Poll::Ready)
    }

    fn stop_sending(&mut self, _: u64) {
        unreachable!("preface parsing does not stop the stream")
    }

    fn recv_id(&self) -> quic::StreamId {
        quic::StreamId::try_from(2).unwrap()
    }
}

/// Encodes both preface fields through their original wire owners.
fn preface(ty: &StreamType, id: VarInt) -> Bytes {
    let mut bytes = BytesMut::new();
    if *ty == StreamType::WEBTRANSPORT_UNI {
        UniStreamHeader::WebTransportUni(SessionId::from_varint(id)).encode(&mut bytes);
    } else {
        ty.encode(&mut bytes);
        id.encode(&mut bytes);
    }
    bytes.freeze()
}

#[test]
fn uni_preface_coalesced_webtransport_completes_without_fin_and_keeps_body() {
    let id = SessionId::from_varint(VarInt(0));
    let mut bytes = BytesMut::from(preface(&StreamType::WEBTRANSPORT_UNI, VarInt(0)).as_ref());
    bytes.extend_from_slice(b"retained-body");
    let mut recv = FakeRecv::default();
    recv.chunk(bytes.freeze());
    let mut accept = AcceptRecvStream::<_, Bytes>::new(recv);
    let mut cx = Context::from_waker(noop_waker_ref());

    assert!(
        matches!(accept.poll_type(&mut cx), Poll::Ready(Ok(()))),
        "complete buffered uni prefix waited for more transport input"
    );
    let AcceptedRecvStream::WebTransportUni(actual, mut stream) = accept.into_stream() else {
        panic!("original preface did not produce a WebTransport uni stream");
    };
    assert_eq!(actual, id);
    assert_eq!(
        stream.take_chunk(usize::MAX).unwrap().as_ref(),
        b"retained-body"
    );
    assert!(!stream.has_remaining());
    assert!(stream.poll_data(&mut cx).is_pending());
}

#[test]
fn uni_preface_push_and_webtransport_ids_have_independent_encoded_widths() {
    for ty in [StreamType::PUSH, StreamType::WEBTRANSPORT_UNI] {
        for id in [VarInt(0), VarInt(64), VarInt(1 << 14), VarInt(1 << 30)] {
            let mut recv = FakeRecv::default();
            recv.chunk(preface(&ty, id));
            let mut accept = AcceptRecvStream::<_, Bytes>::new(recv);
            let mut cx = Context::from_waker(noop_waker_ref());
            assert!(
                matches!(accept.poll_type(&mut cx), Poll::Ready(Ok(()))),
                "complete {ty} prefix with {}-byte ID did not resolve",
                id.size()
            );
            assert_eq!(accept.ty.as_ref(), Some(&ty));
            assert_eq!(accept.id, Some(id));
            assert!(!accept.stream.has_remaining());
        }
    }
}

#[test]
fn uni_preface_fragmented_borrowed_polls_resume_without_consuming_body() {
    for ty in [StreamType::PUSH, StreamType::WEBTRANSPORT_UNI] {
        let id = VarInt(1 << 30);
        let bytes = preface(&ty, id);
        let mut accept = AcceptRecvStream::<FakeRecv, Bytes>::new(FakeRecv::default());
        let mut cx = Context::from_waker(noop_waker_ref());
        for offset in 0..bytes.len() - 1 {
            accept.stream.stream.chunk(bytes.slice(offset..offset + 1));
            let mut attempt = Box::pin(future::poll_fn(|cx| accept.poll_type(cx)));
            assert!(attempt.as_mut().poll(&mut cx).is_pending());
            drop(attempt);
            assert!(accept.poll_type(&mut cx).is_pending());
            assert_eq!(accept.id, None);
        }
        let mut last = BytesMut::from(&bytes[bytes.len() - 1..]);
        last.extend_from_slice(b"body");
        accept.stream.stream.chunk(last.freeze());
        assert!(matches!(accept.poll_type(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(accept.ty.as_ref(), Some(&ty));
        assert_eq!(accept.id, Some(id));
        assert_eq!(accept.stream.buf_mut().copy_to_bytes(4).as_ref(), b"body");
        assert!(!accept.stream.has_remaining());
    }
}

#[test]
fn uni_preface_truncated_fin_reset_and_unknown_error_leave_partial_bytes() {
    let bytes = preface(&StreamType::WEBTRANSPORT_UNI, VarInt(1 << 30));
    for offset in 0..bytes.len() {
        for end in [
            Ok(None),
            Err(StreamErrorIncoming::StreamTerminated {
                error_code: Code::H3_REQUEST_CANCELLED.value(),
            }),
            Err(StreamErrorIncoming::Unknown(Box::new(std::fmt::Error))),
        ] {
            let mut recv = FakeRecv::default();
            if offset != 0 {
                recv.chunk(bytes.slice(..offset));
            }
            let mut accept = AcceptRecvStream::<_, Bytes>::new(recv);
            let mut cx = Context::from_waker(noop_waker_ref());
            assert!(accept.poll_type(&mut cx).is_pending());
            let buffered = accept.stream.buf_mut().remaining();
            let before = accept.stream.buf_mut().cursor().copy_to_bytes(buffered);
            accept.stream.stream.chunks.push_back(end);
            assert!(matches!(
                accept.poll_type(&mut cx),
                Poll::Ready(Err(PollTypeError::EndOfStream))
            ));
            assert_eq!(accept.id, None);
            assert_eq!(accept.stream.buf_mut().copy_to_bytes(buffered), before);
        }
    }
}

#[test]
fn uni_preface_partial_header_preserves_original_connection_error() {
    let bytes = preface(&StreamType::WEBTRANSPORT_UNI, VarInt(0));
    for offset in [0, 1, 2] {
        let mut recv = FakeRecv::default();
        if offset != 0 {
            recv.chunk(bytes.slice(..offset));
        }
        recv.chunks
            .push_back(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::ApplicationClose {
                    error_code: Code::H3_NO_ERROR.value(),
                },
            }));
        let mut accept = AcceptRecvStream::<_, Bytes>::new(recv);
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(matches!(
            accept.poll_type(&mut cx),
            Poll::Ready(Err(PollTypeError::IncomingError(
                ConnectionErrorIncoming::ApplicationClose { error_code }
            ))) if error_code == Code::H3_NO_ERROR.value()
        ));
        assert_eq!(accept.id, None);
    }
}
