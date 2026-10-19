use bytes::BytesMut;
use http::{HeaderMap, Request};

use crate::{
    client,
    error::StreamError,
    proto::{frame::Frame, headers::Header},
    qpack::{self, HeaderField},
    server,
};

use super::{get_stream_blocking, h3_quinn, Pair};

#[tokio::test]
async fn trailer_context_rejects_pseudo_fields_and_preserves_ordinary_duplicates() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let ordinary = vec![
            HeaderField::from(("origin", "https://first.test")),
            HeaderField::from(("origin", "https://second.test")),
        ];
        let preserved = actual_trailers(ordinary.clone()).await.unwrap();
        assert_eq!(preserved.get("origin").unwrap(), "https://first.test");
        assert_eq!(preserved.get_all("origin").iter().count(), 2);

        let mut malformed = vec![HeaderField::from((":method", "GET"))];
        malformed.extend(ordinary);
        let rejected = actual_trailers(malformed).await;
        assert!(
            rejected.is_err(),
            "a request pseudo field was silently discarded from actual trailers"
        );
    })
    .await
    .expect("finite actual trailer exchange stalled");
}

/// Sends original QPACK/frame bytes through the existing real QUIC pair and joins both owners.
async fn actual_trailers(fields: Vec<HeaderField>) -> Result<HeaderMap, StreamError> {
    let mut pair = Pair::default();
    let mut listener = pair.server();
    let (observed, observation) = tokio::sync::oneshot::channel();
    let client = async {
        let connection = pair.client_inner().await;
        let (mut driver, sender) = client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        let (mut send, recv) = connection.open_bi().await.unwrap();
        let (parts, ()) = Request::post("https://localhost/trailers")
            .body(())
            .unwrap()
            .into_parts();
        let request =
            Header::request(parts.method, parts.uri, parts.headers, parts.extensions).unwrap();
        let mut wire = BytesMut::new();
        let mut encoded = BytesMut::new();
        qpack::encode_stateless(&mut encoded, request).unwrap();
        Frame::headers(encoded).encode_with_payload(&mut wire);
        let mut encoded = BytesMut::new();
        qpack::encode_stateless(&mut encoded, fields).unwrap();
        Frame::headers(encoded).encode_with_payload(&mut wire);
        send.write_all(&wire).await.unwrap();
        send.finish().unwrap();

        tokio::select! {
            result = observation => result.expect("actual server trailer observation"),
            error = std::future::poll_fn(|cx| driver.poll_close(cx)) => panic!("unexpected client retirement: {error:?}"),
        }
        connection.close(0u32.into(), b"");
        drop((send, recv, sender, driver, connection));
    };
    let server = async {
        let connection = listener.next().await;
        let mut incoming = server::Connection::new(connection).await.unwrap();
        let (_, mut stream) = get_stream_blocking(&mut incoming).await.unwrap();
        while stream.recv_data().await?.is_some() {}
        let result = stream.recv_trailers().await.map(|fields| fields.unwrap());
        drop(stream);
        observed.send(()).unwrap();
        let _closed = incoming.accept().await;
        result
    };
    let (result, ()) = tokio::join!(server, client);
    listener.endpoint.wait_idle().await;
    result
}
