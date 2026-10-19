use bytes::Bytes;
use futures_util::{future::poll_fn, Future, FutureExt};
use h3::{error::Code, quic::RecvStream};
use std::{panic::AssertUnwindSafe, task::Poll, time::Duration};

use super::fixture::{support::Pair, Fixture};

#[tokio::test]
async fn pending_receive_can_be_canceled_before_local_session_close() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::new().await;
        let session = fixture.session.take().unwrap();
        {
            let mut waiting = Box::pin(session.recv_session_close());
            poll_fn(|cx| {
                assert!(waiting.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            // Local retirement wins while the original CONNECT receive is still pending.
        }
        let outcome = AssertUnwindSafe(session.close(42, "x"))
            .catch_unwind()
            .await;
        let completed = matches!(&outcome, Ok(Ok(_)));
        // Keep any returned closed guard alive through the original physical cleanup.
        fixture.host.close(0u32.into(), b"");
        fixture.peer.closed().await;
        drop(outcome);
        fixture.retire().await;
        assert!(
            completed,
            "canceling a pending CONNECT receive prevented local close"
        );
    })
    .await
    .unwrap();
}

/// Owns one real Quinn stream accepted by the public h3 adapter, with its sender unfinished.
struct ReceiveFixture {
    endpoint: quinn::Endpoint,
    host: quinn::Connection,
    peer: quinn::Connection,
    send: quinn::SendStream,
    receive: h3_quinn::RecvStream,
}

impl ReceiveFixture {
    /// Consumes original bytes, then observes a real pending read without sending FIN.
    async fn pending() -> Self {
        let mut pair = Pair::default();
        pair.with_timeout(Duration::from_secs(10));
        let endpoint = pair.server_inner();
        let (peer, host) = tokio::join!(pair.client_inner(), async {
            endpoint.accept().await.unwrap().await.unwrap()
        });
        let mut send = peer.open_uni().await.unwrap();
        send.write_all(b"x").await.unwrap();
        let mut backend = h3_quinn::Connection::new(host.clone());
        let mut receive = poll_fn(|cx| {
            <h3_quinn::Connection as h3::quic::Connection<Bytes>>::poll_accept_recv(
                &mut backend,
                cx,
            )
        })
        .await
        .unwrap();
        let bytes = poll_fn(|cx| receive.poll_data(cx)).await.unwrap().unwrap();
        assert_eq!(bytes, Bytes::from_static(b"x"));
        poll_fn(|cx| {
            assert!(receive.poll_data(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        Self {
            endpoint,
            host,
            peer,
            send,
            receive,
        }
    }

    /// Releases the same socket/stream owners and joins the original endpoint before assertions.
    async fn retire(self) {
        self.host.close(0u32.into(), b"");
        self.peer.closed().await;
        let Self {
            endpoint,
            host,
            peer,
            send,
            receive,
        } = self;
        drop((receive, send, peer, host));
        endpoint.wait_idle().await;
    }
}

#[tokio::test]
async fn pending_receive_keeps_its_original_stream_id_available() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = ReceiveFixture::pending().await;
        let expected = u64::from(fixture.send.id());
        let observed = std::panic::catch_unwind(AssertUnwindSafe(|| fixture.receive.recv_id()));
        fixture.retire().await;
        assert!(
            observed.is_ok(),
            "pending receive lost its original stream ID"
        );
        assert_eq!(observed.unwrap().into_inner(), expected);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pending_receive_stops_its_original_stream_with_the_requested_code() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = ReceiveFixture::pending().await;
        let code = Code::H3_REQUEST_CANCELLED.value();
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            fixture.receive.stop_sending(code);
        }));
        let stopped = if outcome.is_ok() {
            fixture.send.stopped().await.unwrap()
        } else {
            None
        };
        fixture.retire().await;
        assert!(
            outcome.is_ok(),
            "pending receive lost its original stop owner"
        );
        assert_eq!(stopped.map(|value| value.into_inner()), Some(code));
    })
    .await
    .unwrap();
}
