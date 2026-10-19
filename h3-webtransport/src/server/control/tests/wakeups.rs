use bytes::{BufMut, BytesMut};
use futures_util::{future::poll_fn, task::AtomicWaker, Future};
use h3::{quic::WriteBuf, stream::UniStreamHeader};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};
use tokio::io::AsyncReadExt;

use super::fixture::Fixture;

/// Counts one actual waiter's wakes and schedules only the enclosing finite test driver.
#[derive(Default)]
pub(super) struct CountWake {
    count: AtomicUsize,
    pub(super) driver: AtomicWaker,
}

impl CountWake {
    /// Reads the wake sequence without polling the waiter or its shared connection.
    pub(super) fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.driver.wake();
    }
}

#[tokio::test]
async fn maintenance_wakes_the_original_uni_acceptor_after_queueing_its_stream() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::new().await;
        let (acceptor_woke, id, received) = {
            let session = fixture.session.as_ref().unwrap();
            let accepting_wake = Arc::new(CountWake::default());
            let maintenance_wake = Arc::new(CountWake::default());
            let accepting_waker = Waker::from(Arc::clone(&accepting_wake));
            let maintenance_waker = Waker::from(Arc::clone(&maintenance_wake));
            let mut accepting = Box::pin(session.accept_uni());
            let mut maintenance = Box::pin(session.maintain());
            assert!(accepting
                .as_mut()
                .poll(&mut Context::from_waker(&accepting_waker))
                .is_pending());
            assert!(maintenance
                .as_mut()
                .poll(&mut Context::from_waker(&maintenance_waker))
                .is_pending());
            let accepting_before = accepting_wake.count();
            let mut maintenance_seen = maintenance_wake.count();

            let peer = async {
                let mut wire = BytesMut::new();
                wire.put(WriteBuf::<&'static [u8]>::from(
                    UniStreamHeader::WebTransportUni(session.session_id()),
                ));
                wire.extend_from_slice(b"original stream");
                let mut sending = fixture.peer.open_uni().await.unwrap();
                sending.write_all(&wire).await.unwrap();
                sending.finish().unwrap();
            };
            let host = async {
                let acceptor_woke = poll_fn(|cx| {
                    maintenance_wake.driver.register(cx.waker());
                    let count = maintenance_wake.count();
                    if count == maintenance_seen {
                        return Poll::Pending;
                    }
                    maintenance_seen = count;
                    assert!(maintenance
                        .as_mut()
                        .poll(&mut Context::from_waker(&maintenance_waker))
                        .is_pending());
                    let queued = !session
                        .server_conn
                        .lock()
                        .unwrap()
                        .inner
                        .accepted_streams_mut()
                        .wt_uni_streams
                        .is_empty();
                    if queued {
                        Poll::Ready(accepting_wake.count() != accepting_before)
                    } else {
                        Poll::Pending
                    }
                })
                .await;

                // Resume the same original accept solely after recording the causal wake result.
                let (id, receiving) = accepting.await.unwrap().unwrap();
                let mut received = Vec::new();
                receiving
                    .take(32)
                    .read_to_end(&mut received)
                    .await
                    .unwrap();
                (acceptor_woke, id, received)
            };
            tokio::select! {
                (_, observed) = async { tokio::join!(peer, host) } => observed,
                error = poll_fn(|cx| fixture.driver.poll_close(cx)) => panic!("peer control failed: {error:?}"),
            }
        };
        let expected_id = fixture.session.as_ref().unwrap().session_id();
        fixture.retire().await;
        assert_eq!(id, expected_id);
        assert_eq!(received.as_slice(), b"original stream");
        assert!(
            acceptor_woke,
            "maintenance queued the original WT uni stream without waking its acceptor"
        );
    })
    .await
    .unwrap();
}
