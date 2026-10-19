use futures_util::{future::poll_fn, Future};
use std::{
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use super::{fixture::Fixture, wakeups::CountWake};
use crate::{capsule::encode_close, SessionClose};

#[tokio::test]
async fn session_close_wakes_every_original_pending_observer() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::new().await;
        let (first_woke, first_result, second_result) = {
            let session = fixture.session.as_ref().unwrap();
            let first_wake = Arc::new(CountWake::default());
            let second_wake = Arc::new(CountWake::default());
            let first_waker = Waker::from(Arc::clone(&first_wake));
            let second_waker = Waker::from(Arc::clone(&second_wake));
            let mut first = Box::pin(session.recv_session_close());
            let mut second = Box::pin(session.recv_session_close());
            assert!(first
                .as_mut()
                .poll(&mut Context::from_waker(&first_waker))
                .is_pending());
            assert!(second
                .as_mut()
                .poll(&mut Context::from_waker(&second_waker))
                .is_pending());
            let first_before = first_wake.count();
            let mut second_seen = second_wake.count();
            let peer = async {
                fixture.request.send_data(encode_close(42, "observers")).await.unwrap();
            };
            let host = async {
                let second_result = poll_fn(|cx| {
                    second_wake.driver.register(cx.waker());
                    let count = second_wake.count();
                    if count == second_seen {
                        return Poll::Pending;
                    }
                    second_seen = count;
                    second.as_mut().poll(&mut Context::from_waker(&second_waker))
                })
                .await;
                // Capture wake delivery only after the other actual observer reached its terminal.
                let first_woke = first_wake.count() != first_before;
                let first_result = first.await;
                (first_woke, first_result, second_result)
            };
            tokio::select! {
                (_, observed) = async { tokio::join!(peer, host) } => observed,
                error = poll_fn(|cx| fixture.driver.poll_close(cx)) => panic!("peer control failed: {error:?}"),
                error = session.maintain() => panic!("host control failed: {error:?}"),
            }
        };
        fixture.retire().await;
        let expected = Some(SessionClose {
            code: 42,
            reason: bytes::Bytes::from_static(b"observers"),
        });
        assert_eq!(second_result.unwrap(), expected);
        assert_eq!(first_result.unwrap(), expected);
        assert!(
            first_woke,
            "the completed CONNECT terminal did not wake the original pending observer"
        );
    })
    .await
    .unwrap();
}
