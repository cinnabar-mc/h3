use bytes::{Buf, Bytes, BytesMut};
use futures_util::{future::poll_fn, Future};
use std::{sync::Arc, task::Poll, time::Duration};

use crate::SessionClose;

mod fixture;
mod observers;
mod opening;
mod pending_receive;
mod trailers;
mod wakeups;
use fixture::Fixture;

#[tokio::test]
async fn session_close_retains_partial_capsule_across_canceled_borrowed_wait() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::new().await;
        let observed = {
            let session = fixture.session.as_ref().unwrap();
            let (partial, continue_body) = tokio::sync::oneshot::channel();
            let peer = async {
                fixture
                    .request
                    .send_data(Bytes::from_static(&[0x68, 0x43, 0x05]))
                    .await
                    .unwrap();
                continue_body.await.unwrap();
                fixture
                    .request
                    .send_data(Bytes::from_static(&[0, 0, 0, 42, b'x']))
                    .await
                    .unwrap();
            };
            let host = async {
                let mut original = Box::pin(session.recv_session_close());
                poll_fn(|cx| {
                    assert!(original.as_mut().poll(cx).is_pending());
                    if session
                        .connect_control
                        .lock()
                        .unwrap()
                        .decoder
                        .finish()
                        .is_err()
                    {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                drop(original);
                partial.send(()).unwrap();
                let first = session.recv_session_close().await.unwrap();
                let repeated = session.recv_session_close().await.unwrap();
                (first, repeated)
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
            reason: Bytes::from_static(b"x"),
        });
        assert_eq!(observed.0, expected);
        assert_eq!(observed.1, expected);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn session_close_distinguishes_clean_eof_and_retains_original_truncation_error() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for truncated in [false, true] {
            let mut fixture = Fixture::new().await;
            let observed = {
                let session = fixture.session.as_ref().unwrap();
                let peer = async {
                    if truncated {
                        fixture
                            .request
                            .send_data(Bytes::from_static(&[0x68, 0x43, 0x05]))
                            .await
                            .unwrap();
                    }
                    fixture.request.finish().await.unwrap();
                };
                let host = async {
                    let first = session.recv_session_close().await;
                    let repeated = session.recv_session_close().await;
                    (first, repeated)
                };
                tokio::select! {
                    (_, observed) = async { tokio::join!(peer, host) } => observed,
                    error = poll_fn(|cx| fixture.driver.poll_close(cx)) => panic!("peer control failed: {error:?}"),
                    error = session.maintain() => panic!("host control failed: {error:?}"),
                }
            };
            fixture.retire().await;
            match observed {
                (Err(first), Err(repeated)) if truncated => {
                    assert!(Arc::ptr_eq(&first, &repeated));
                }
                (Ok(None), Ok(None)) if !truncated => {}
                result => panic!("unexpected CONNECT EOF result: {result:?}"),
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn session_close_guard_retains_h3_through_actual_peer_data_and_fin() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::new().await;
        let session = fixture.session.take().unwrap();
        let (received, visible) = tokio::sync::oneshot::channel();
        let host = async {
            let guard = session.close(42, "x").await.unwrap();
            let remained_open = tokio::select! {
                result = visible => { result.unwrap(); fixture.host.close_reason().is_none() },
                error = guard.maintain() => panic!("closed owner control failed: {error:?}"),
            };
            (guard, remained_open)
        };
        let peer = async {
            let mut wire = BytesMut::new();
            while let Some(mut data) = fixture.request.recv_data().await.unwrap() {
                assert!(wire.len() + data.remaining() <= 64);
                wire.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            received.send(()).unwrap();
            wire.freeze()
        };
        let ((guard, remained_open), wire) = tokio::select! {
            observed = async { tokio::join!(host, peer) } => observed,
            error = poll_fn(|cx| fixture.driver.poll_close(cx)) => panic!("peer control failed: {error:?}"),
        };
        // Close the real transport while the same h3 owner is still retained.
        fixture.host.close(0u32.into(), b"");
        fixture.peer.closed().await;
        drop(guard);
        fixture.retire().await;
        assert!(remained_open, "local close completion dropped the h3 owner");
        assert_eq!(wire, Bytes::from_static(&[0x68, 0x43, 0x05, 0, 0, 0, 42, b'x']));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn session_close_retains_validated_trailer_wait_across_canceled_borrow() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::new().await;
        let observed = {
            let session = fixture.session.as_ref().unwrap();
            let (continue_fin, finish) = tokio::sync::oneshot::channel();
            let peer = async {
                let mut fields = http::HeaderMap::new();
                fields.insert("x-proof", "yes".parse().unwrap());
                fixture.request.send_trailers(fields).await.unwrap();
                finish.await.unwrap();
                fixture.request.finish().await.unwrap();
            };
            let host = async {
                let mut original = Box::pin(session.recv_session_close());
                poll_fn(|cx| {
                    assert!(original.as_mut().poll(cx).is_pending());
                    // The original close owner consumed HEADERS and is waiting on the same FIN.
                    if session.connect_control.lock().unwrap().receiving_trailers {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                drop(original);
                continue_fin.send(()).unwrap();
                let first = session.recv_session_close().await.unwrap();
                let repeated = session.recv_session_close().await.unwrap();
                (first, repeated)
            };
            tokio::select! {
                (_, observed) = async { tokio::join!(peer, host) } => observed,
                error = poll_fn(|cx| fixture.driver.poll_close(cx)) => panic!("peer control failed: {error:?}"),
                error = session.maintain() => panic!("host control failed: {error:?}"),
            }
        };
        fixture.retire().await;
        assert_eq!(observed, (None, None));
    })
    .await
    .unwrap();
}
