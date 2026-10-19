// This is to avoid an import loop:
// h3 tests depend on having private access to the crate.
// They must be part of the crate so as not to break privacy.
// They also depend on h3_quinn which depends on the crate.
// Having a dev-dependency on h3_quinn would work as far as cargo is
// concerned, but quic traits wouldn't match between the "h3" crate that
// comes before h3_quinn and the one that comes after and runs the tests
#[path = "../../../h3-quinn/src/lib.rs"]
#[allow(unknown_lints, unexpected_cfgs)] // The included adapter owns its own feature set.
mod h3_quinn;

mod body_end;
mod connection;
mod encoded_headers;
mod header_validation;
mod request;
mod support;

use support::Pair;

use bytes::{Buf, Bytes};
use http::Request;

use self::h3_quinn as quic_backend;
use crate::quic;
use h3_quinn::Connection;

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_test_writer()
        .try_init();
}

/// This accepts an incoming request. After the bidirectional stream is started it will not poll the
/// connection or receive further requests until the first headers are received.
/// Only use this for testing purposes.
async fn get_stream_blocking<C: quic::Connection<B>, B: Buf>(
    incoming: &mut crate::server::Connection<C, B>,
) -> Option<(Request<()>, crate::server::RequestStream<C::BidiStream, B>)> {
    let request_resolver = incoming.accept().await.ok()??;
    let (request, stream) = request_resolver.resolve_request().await.ok()?;
    Some((request, stream))
}

impl Pair {
    pub fn server(&mut self) -> Server {
        let endpoint = self.server_inner();
        Server { endpoint }
    }

    pub async fn client(&self) -> h3_quinn::Connection {
        Connection::new(self.client_inner().await)
    }
}

pub struct Server {
    pub endpoint: h3_quinn::Endpoint,
}

impl Server {
    pub async fn next(&mut self) -> impl quic::Connection<Bytes> {
        Connection::new(self.endpoint.accept().await.unwrap().await.unwrap())
    }
}
