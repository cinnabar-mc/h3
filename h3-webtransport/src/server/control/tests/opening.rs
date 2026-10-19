use bytes::Buf;
use futures_util::{future::poll_fn, Future};
use h3::{
    error::Code,
    quic::{SendStream, WriteBuf},
    stream::{BidiStreamHeader, UniStreamHeader},
};
use std::{task::Poll, time::Duration};

use super::fixture::Fixture;

#[tokio::test]
async fn opening_cancellation_resets_actual_partial_unidirectional_prefix() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = Fixture::with_receive_window(1).await;
        let (observed, original_bytes, remaining) = {
            let session = fixture.session.as_ref().unwrap();
            let original_bytes = WriteBuf::<&'static [u8]>::from(UniStreamHeader::WebTransportUni(
                session.session_id(),
            ))
            .remaining();
            let mut opening = Box::pin(session.open_uni(session.session_id()));
            let (id, remaining) = poll_fn(|cx| {
                assert!(opening.as_mut().poll(cx).is_pending());
                if let Some((stream, prefix)) = &opening.as_ref().get_ref().stream {
                    if prefix.has_remaining() && prefix.remaining() < original_bytes {
                        return Poll::Ready((stream.send_id(), prefix.remaining()));
                    }
                }
                Poll::Pending
            })
            .await;
            // Keep any earlier original h3 critical streams alive; never read the target prefix.
            let mut earlier = Vec::new();
            let mut target = loop {
                let stream = fixture.peer.accept_uni().await.unwrap();
                if u64::from(stream.id()) == id.into_inner() {
                    break stream;
                }
                assert!(stream.id().index() < id.index());
                earlier.push(stream);
            };
            drop(opening);
            let observed = target.read_to_end(original_bytes).await;
            drop((target, earlier));
            (observed, original_bytes, remaining)
        };
        fixture.retire().await;
        assert!(remaining > 0 && remaining < original_bytes);
        assert!(
            matches!(observed, Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)))
                if code.into_inner() == Code::H3_REQUEST_CANCELLED.value()),
            "canceling a real partial WT uni prefix produced FIN instead of RESET: {observed:?}"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn opening_cancellation_resets_actual_partial_bidirectional_prefix() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = Fixture::with_receive_window(1).await;
        let (observed, stopped, original_bytes, remaining) = {
            let session = fixture.session.as_ref().unwrap();
            let original_bytes =
                WriteBuf::<&'static [u8]>::from(BidiStreamHeader::WebTransportBidi(session.session_id()))
                    .remaining();
            let mut opening = Box::pin(session.open_bi(session.session_id()));
            let (id, remaining) = poll_fn(|cx| {
                assert!(opening.as_mut().poll(cx).is_pending());
                if let Some((stream, prefix)) = &opening.as_ref().get_ref().stream {
                    if prefix.has_remaining() && prefix.remaining() < original_bytes {
                        return Poll::Ready((stream.send_id(), prefix.remaining()));
                    }
                }
                Poll::Pending
            })
            .await;
            let (send, mut receive) = fixture.peer.accept_bi().await.unwrap();
            assert_eq!(u64::from(receive.id()), id.into_inner());
            drop(opening);
            let (observed, stopped) = tokio::join!(receive.read_to_end(original_bytes), send.stopped());
            drop((send, receive));
            (observed, stopped, original_bytes, remaining)
        };
        fixture.retire().await;
        assert!(remaining > 0 && remaining < original_bytes);
        assert!(
            matches!(observed, Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)))
                if code.into_inner() == Code::H3_REQUEST_CANCELLED.value()),
            "canceling a real partial WT bidi prefix produced FIN instead of RESET: {observed:?}"
        );
        assert!(
            matches!(stopped, Ok(Some(code)) if code.into_inner() == Code::H3_REQUEST_CANCELLED.value()),
            "canceling a real partial WT bidi prefix failed to stop its original receive direction: {stopped:?}"
        );
    })
    .await
    .unwrap();
}
