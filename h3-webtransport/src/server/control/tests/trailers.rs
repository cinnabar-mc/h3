use bytes::{BufMut, Bytes, BytesMut};
use h3::{error::StreamError, proto::frame::Frame, stream::WriteBuf};
use std::{sync::Arc, time::Duration};

use crate::{server::WebTransportSession, SessionClose};

use super::fixture::support;

type Observed = Result<Option<SessionClose>, Arc<StreamError>>;

#[tokio::test]
async fn session_close_validates_actual_connect_trailers_before_caching_eof() {
    tokio::time::timeout(Duration::from_secs(20), async {
        // Empty dynamic table, literal x-proof: yes.
        let ordinary = Bytes::from_static(b"\x00\x00\x27\x00x-proof\x03yes");
        let mut observed = Vec::new();
        observed.push(actual_close(ordinary.clone(), false).await);
        // Empty dynamic table, static :method GET: prohibited in trailers.
        observed.push(actual_close(Bytes::from_static(b"\x00\x00\xd1"), false).await);
        // An incomplete QPACK field-section prefix cannot be a valid trailer block.
        observed.push(actual_close(Bytes::from_static(b"\x00"), false).await);
        observed.push(actual_close(ordinary, true).await);

        // All original physical transports and endpoints retire before behavioral verdicts.
        assert!(matches!(observed[0], (Ok(None), Ok(None))));
        for (name, (first, repeated)) in ["pseudo field", "QPACK", "DATA after trailers"]
            .into_iter()
            .zip(observed.into_iter().skip(1))
        {
            assert!(
                matches!((&first, &repeated), (Err(first), Err(repeated))
                    if Arc::ptr_eq(first, repeated)),
                "CONNECT close bypassed {name} validation or replaced its original error: {first:?}, {repeated:?}"
            );
        }
    })
    .await
    .expect("finite real CONNECT trailer control stalled");
}

/// Sends fixed original-format HEADERS through the shared real TLS/QUIC pair and public WT owner.
async fn actual_close(trailers: Bytes, data_after_trailers: bool) -> (Observed, Observed) {
    let mut pair = support::Pair::default();
    pair.with_timeout(Duration::from_secs(10));
    let endpoint = pair.server_inner();
    let (done, observation) = tokio::sync::oneshot::channel();
    let client = async {
        let peer = pair.client_inner().await;
        let (driver, sender) = h3::client::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .enable_webtransport(true)
            .max_webtransport_sessions(1)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(peer.clone()))
            .await
            .unwrap();
        let (mut send, recv) = peer.open_bi().await.unwrap();
        // Static references and a non-Huffman literal QPACK fixture: CONNECT https://localhost/relay, :protocol webtransport.
        let request = Bytes::from_static(
            b"\x00\x00\xcf\xd7\x50\x09localhost\x51\x06/relay\x27\x02:protocol\x0cwebtransport",
        );
        let mut wire = BytesMut::new();
        wire.put(WriteBuf::from(Frame::<Bytes>::Headers(request)));
        wire.put(WriteBuf::from(Frame::<Bytes>::Headers(trailers)));
        if data_after_trailers {
            wire.put(WriteBuf::from(Frame::Data(Bytes::from_static(b"x"))));
        }
        send.write_all(&wire).await.unwrap();
        send.finish().unwrap();
        observation.await.expect("original CONNECT owner completed");
        peer.close(0u32.into(), b"");
        drop((send, recv, sender, driver, peer));
    };
    let server = async {
        let host = endpoint.accept().await.unwrap().await.unwrap();
        let mut connection = h3::server::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .enable_webtransport(true)
            .max_webtransport_sessions(1)
            .send_grease(false)
            .build::<_, Bytes>(h3_quinn::Connection::new(host.clone()))
            .await
            .unwrap();
        let (request, stream) = connection
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        let session = WebTransportSession::accept(request, stream, connection)
            .await
            .unwrap();
        let first = session.recv_session_close().await;
        let repeated = session.recv_session_close().await;
        done.send(()).unwrap();
        host.closed().await;
        drop((session, host));
        (first, repeated)
    };
    let (observed, ()) = tokio::join!(server, client);
    endpoint.wait_idle().await;
    observed
}
