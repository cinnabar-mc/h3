use super::quic_backend as h3_quinn;
use h3_quinn::quinn::TransportConfig;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    convert::TryInto,
    net::{Ipv6Addr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

pub struct Pair {
    port: u16,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    config: Arc<TransportConfig>,
}

impl Default for Pair {
    fn default() -> Self {
        let (cert, key) = build_certs();
        Self {
            cert,
            key,
            port: 0,
            config: Arc::new(TransportConfig::default()),
        }
    }
}

impl Pair {
    pub fn with_timeout(&mut self, duration: Duration) {
        Arc::get_mut(&mut self.config)
            .unwrap()
            .max_idle_timeout(Some(
                duration.try_into().expect("idle timeout duration invalid"),
            ))
            .initial_rtt(Duration::from_millis(10));
    }

    pub fn server_inner(&mut self) -> h3_quinn::Endpoint {
        let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
        .unwrap();
        crypto.max_early_data_size = u32::MAX;
        crypto.alpn_protocols = vec![b"h3".to_vec()];

        let mut server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(crypto).unwrap(),
        ));
        server_config.transport = self.config.clone();
        let endpoint =
            h3_quinn::quinn::Endpoint::server(server_config, "[::]:0".parse().unwrap()).unwrap();

        self.port = endpoint.local_addr().unwrap().port();

        endpoint
    }

    pub async fn client_inner(&self) -> quinn::Connection {
        self.client_inner_with_transport(None).await
    }

    /// Applies an optional real peer transport limit without changing the original default pair.
    pub async fn client_inner_with_transport(
        &self,
        transport: Option<Arc<TransportConfig>>,
    ) -> quinn::Connection {
        let addr = (Ipv6Addr::LOCALHOST, self.port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.add(self.cert.clone()).unwrap();
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
        crypto.enable_early_data = true;
        crypto.alpn_protocols = vec![b"h3".to_vec()];

        let mut client_config = h3_quinn::quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).unwrap(),
        ));
        if let Some(transport) = transport {
            client_config.transport_config(transport);
        }

        let mut client_endpoint =
            h3_quinn::quinn::Endpoint::client("[::]:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        client_endpoint
            .connect(addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    }
}

pub fn build_certs() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (
        cert.cert.into(),
        PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
    )
}
