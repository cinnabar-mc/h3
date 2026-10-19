use bytes::Bytes;
use h3::ext::Protocol;
use h3_quinn as quic_backend;
use http::{Method, Request, StatusCode};
use std::{sync::Arc, time::Duration};

#[path = "../../../../../h3/src/tests/support.rs"]
mod support;

use crate::server::WebTransportSession;

pub(super) type Session = WebTransportSession<h3_quinn::Connection, Bytes>;

/// Original shared certificate/QUIC construction with real typed CONNECT and finite cleanup.
pub(super) struct Fixture {
    pub session: Option<Session>,
    pub host: quinn::Connection,
    pub peer: quinn::Connection,
    pub driver: h3::client::Connection<h3_quinn::Connection, Bytes>,
    pub request: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    endpoint: quinn::Endpoint,
}

impl Fixture {
    /// Establishes only through actual peer settings, TLS, HTTP3 and the public WT accept owner.
    pub async fn new() -> Self {
        Self::with_client_transport(None).await
    }

    /// Advertises actual QUIC stream credit so the original opener must retain a partial prefix.
    pub async fn with_receive_window(window: u32) -> Self {
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(window.into());
        Self::with_client_transport(Some(Arc::new(transport))).await
    }

    /// Builds the same real CONNECT session with only the selected peer transport configuration.
    async fn with_client_transport(transport: Option<Arc<quinn::TransportConfig>>) -> Self {
        let mut pair = support::Pair::default();
        pair.with_timeout(Duration::from_secs(10));
        let endpoint = pair.server_inner();
        let client = async {
            let peer = match transport {
                Some(transport) => pair.client_inner_with_transport(Some(transport)).await,
                None => pair.client_inner().await,
            };
            let (mut driver, mut sender) = h3::client::builder()
                .enable_datagram(true)
                .enable_extended_connect(true)
                .enable_webtransport(true)
                .max_webtransport_sessions(1)
                .build::<_, _, Bytes>(h3_quinn::Connection::new(peer.clone()))
                .await
                .unwrap();
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri("https://localhost/relay")
                .extension(Protocol::WEB_TRANSPORT)
                .body(())
                .unwrap();
            let mut request = sender.send_request(request).await.unwrap();
            let response = tokio::select! {
                result = request.recv_response() => result.unwrap(),
                error = std::future::poll_fn(|cx| driver.poll_close(cx)) => panic!("CONNECT peer failed: {error:?}"),
            };
            assert_eq!(response.status(), StatusCode::OK);
            (peer, driver, sender, request)
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
            (host, session)
        };
        let ((peer, driver, sender, request), (host, session)) = tokio::join!(client, server);
        Self {
            session: Some(session),
            host,
            peer,
            driver,
            request,
            _sender: sender,
            endpoint,
        }
    }

    /// Drops original application owners only after explicit physical close, then joins endpoint idle.
    pub async fn retire(mut self) {
        self.host.close(0u32.into(), b"");
        self.peer.closed().await;
        drop(self.session.take());
        drop((
            self.request,
            self.driver,
            self._sender,
            self.peer,
            self.host,
        ));
        self.endpoint.wait_idle().await;
    }
}
