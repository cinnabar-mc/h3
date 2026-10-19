use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, Request, StatusCode};
use std::{future::poll_fn, task::Context, task::Poll, time::Duration};
use tokio::sync::oneshot;

use crate::{
    client,
    error::{Code, ConnectionError, LocalError, StreamError},
    proto::{
        frame::{Frame, FrameType},
        headers::Header,
        varint::VarInt,
    },
    qpack, server,
};

use super::{get_stream_blocking, h3_quinn, Pair};

#[derive(Clone, Copy, Debug)]
enum Body {
    Clean,
    EmptyBetween,
    EmptyTrailers,
    EmptyFin,
    Truncated,
    PartialFin,
}

impl Body {
    fn truncated(self) -> bool {
        matches!(self, Self::Truncated | Self::PartialFin)
    }

    /// Uses the original frame encoder; only the intentionally truncated payload is incomplete.
    fn encode(self, wire: &mut BytesMut) {
        match self {
            Self::Clean => Frame::Data(&b"body"[..]).encode_with_payload(wire),
            Self::EmptyBetween => {
                Frame::Data(&b""[..]).encode_with_payload(wire);
                Frame::Data(&b"bo"[..]).encode_with_payload(wire);
                Frame::Data(&b""[..]).encode_with_payload(wire);
                Frame::Data(&b"dy"[..]).encode_with_payload(wire);
            }
            Self::EmptyTrailers => {
                Frame::Data(&b"body"[..]).encode_with_payload(wire);
                Frame::Data(&b""[..]).encode_with_payload(wire);
                let mut fields = HeaderMap::new();
                fields.insert("x-proof", "yes".parse().unwrap());
                let mut encoded = BytesMut::new();
                qpack::encode_stateless(&mut encoded, Header::trailer(fields)).unwrap();
                Frame::<Bytes>::Headers(encoded.freeze()).encode_with_payload(wire);
            }
            Self::EmptyFin => Frame::Data(&b""[..]).encode_with_payload(wire),
            Self::Truncated | Self::PartialFin => {
                FrameType::DATA.encode(wire);
                VarInt::from(4u32).encode(wire);
                if matches!(self, Self::PartialFin) {
                    wire.extend_from_slice(b"bo");
                }
            }
        }
    }
}

#[derive(Debug)]
struct Observed {
    body: Result<Bytes, StreamError>,
    trailers: Option<Result<Option<HeaderMap>, StreamError>>,
}

#[tokio::test]
async fn body_end_client_skips_empty_data_before_body_and_trailers() {
    actual_bodies(
        true,
        &[
            Body::Clean,
            Body::EmptyBetween,
            Body::EmptyTrailers,
            Body::EmptyFin,
        ],
    )
    .await;
}

#[tokio::test]
async fn body_end_server_skips_empty_data_before_body_and_trailers() {
    actual_bodies(
        false,
        &[
            Body::Clean,
            Body::EmptyBetween,
            Body::EmptyTrailers,
            Body::EmptyFin,
        ],
    )
    .await;
}

#[tokio::test]
async fn body_end_client_rejects_finite_data_fin_before_declared_payload() {
    actual_bodies(true, &[Body::Truncated, Body::PartialFin]).await;
}

#[tokio::test]
async fn body_end_server_rejects_finite_data_fin_before_declared_payload() {
    actual_bodies(false, &[Body::Truncated, Body::PartialFin]).await;
}

/// Retires every real pair before checking the shared public request/response body contract.
async fn actual_bodies(client_receives: bool, cases: &[Body]) {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut results = Vec::new();
        for &body in cases {
            results.push((body, actual_body(client_receives, body).await));
        }
        for (case, observed) in results {
            if case.truncated() {
                assert!(
                    matches!(
                        &observed.body,
                        Err(StreamError::ConnectionError(ConnectionError::Local {
                            error: LocalError::Application {
                                code: Code::H3_FRAME_ERROR,
                                ..
                            }
                        }))
                    ),
                    "finite DATA ended before its declared payload: {case:?}: {observed:?}"
                );
                continue;
            }
            let expected = if matches!(case, Body::EmptyFin) {
                &b""[..]
            } else {
                &b"body"[..]
            };
            assert!(
                matches!(&observed.body, Ok(bytes) if bytes.as_ref() == expected),
                "empty DATA became HTTP body end: {case:?}: {observed:?}"
            );
            match observed.trailers.unwrap().unwrap() {
                Some(fields) if matches!(case, Body::EmptyTrailers) => {
                    assert_eq!(fields.get("x-proof").unwrap(), "yes");
                }
                None if !matches!(case, Body::EmptyTrailers) => {}
                fields => panic!("unexpected actual trailers: {case:?}: {fields:?}"),
            }
        }
    })
    .await
    .expect("finite actual HTTP body exchange stalled");
}

/// A partial DATA prefix must be delivered before the peer releases the same stream's FIN.
async fn read_body<F, B>(mut receive: F, prefix: oneshot::Sender<()>) -> Result<Bytes, StreamError>
where
    F: FnMut(&mut Context<'_>) -> Poll<Result<Option<B>, StreamError>>,
    B: Buf,
{
    let mut body = BytesMut::new();
    let mut prefix = Some(prefix);
    while let Some(mut data) = poll_fn(&mut receive).await? {
        assert!(body.len() + data.remaining() <= 4);
        body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        if body.len() >= 2 {
            if let Some(prefix) = prefix.take() {
                let _ = prefix.send(());
            }
        }
    }
    Ok(body.freeze())
}

/// Keeps the original HTTP3 owners alive while only the selected body writer uses raw QUIC.
async fn actual_body(client_receives: bool, body: Body) -> Observed {
    let mut pair = Pair::default();
    pair.with_timeout(Duration::from_secs(10));
    let endpoint = pair.server_inner();
    let (done, observation) = oneshot::channel();
    let (prefix, prefix_read) = oneshot::channel();
    let (client_receive, server_receive) = if client_receives {
        (Some((done, prefix)), None)
    } else {
        (None, Some((done, prefix)))
    };
    let (client_write, server_write) = if client_receives {
        (None, Some((observation, prefix_read)))
    } else {
        (Some((observation, prefix_read)), None)
    };
    let client = async {
        let peer = pair.client_inner().await;
        let (driver, mut sender) = client::new(h3_quinn::Connection::new(peer.clone()))
            .await
            .unwrap();
        let request = Request::post("https://localhost/body").body(()).unwrap();
        let result = if client_receives {
            let (done, prefix) = client_receive.unwrap();
            let mut stream = sender.send_request(request).await.unwrap();
            stream.finish().await.unwrap();
            stream.recv_response().await.unwrap();
            let received = read_body(|cx| stream.poll_recv_data(cx), prefix).await;
            let trailers = if received.is_ok() && !body.truncated() {
                Some(stream.recv_trailers().await)
            } else {
                None
            };
            done.send(()).unwrap();
            drop(stream);
            Some(Observed {
                body: received,
                trailers,
            })
        } else {
            let (observation, prefix_read) = client_write.unwrap();
            let (mut send, recv) = peer.open_bi().await.unwrap();
            let (parts, ()) = request.into_parts();
            let headers =
                Header::request(parts.method, parts.uri, parts.headers, parts.extensions).unwrap();
            write_body(&mut send, headers, body, prefix_read).await;
            observation.await.unwrap();
            drop((send, recv));
            None
        };
        peer.close(0u32.into(), b"");
        drop((sender, driver, peer));
        result
    };
    let server = async {
        let host = endpoint.accept().await.unwrap().await.unwrap();
        let mut connection =
            server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(host.clone()))
                .await
                .unwrap();
        let result = if client_receives {
            let (observation, prefix_read) = server_write.unwrap();
            let (mut send, recv) = host.accept_bi().await.unwrap();
            write_body(
                &mut send,
                Header::response(StatusCode::OK, HeaderMap::new()),
                body,
                prefix_read,
            )
            .await;
            observation.await.unwrap();
            drop((send, recv));
            None
        } else {
            let (done, prefix) = server_receive.unwrap();
            let (_, mut stream) = get_stream_blocking(&mut connection).await.unwrap();
            let received = read_body(|cx| stream.poll_recv_data(cx), prefix).await;
            let trailers = if received.is_ok() && !body.truncated() {
                Some(stream.recv_trailers().await)
            } else {
                None
            };
            done.send(()).unwrap();
            drop(stream);
            Some(Observed {
                body: received,
                trailers,
            })
        };
        host.closed().await;
        drop((connection, host));
        result
    };
    let (client, server) = tokio::join!(client, server);
    endpoint.wait_idle().await;
    client.or(server).unwrap()
}

/// Encodes actual initial fields and body, withholding only an intentionally partial DATA FIN.
async fn write_body(
    send: &mut quinn::SendStream,
    headers: Header,
    body: Body,
    prefix: oneshot::Receiver<()>,
) {
    let mut encoded = BytesMut::new();
    qpack::encode_stateless(&mut encoded, headers).unwrap();
    let mut wire = BytesMut::new();
    Frame::<Bytes>::Headers(encoded.freeze()).encode_with_payload(&mut wire);
    body.encode(&mut wire);
    send.write_all(&wire).await.unwrap();
    if matches!(body, Body::PartialFin) {
        prefix
            .await
            .expect("actual partial body reached the receiver");
    }
    send.finish().unwrap();
}
