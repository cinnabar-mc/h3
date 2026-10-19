use bytes::BytesMut;
use http::StatusCode;

use crate::{
    client,
    error::StreamError,
    proto::{
        frame::{Frame, FrameType},
        headers::Header,
        varint::VarInt,
    },
    qpack, server,
};

use super::{h3_quinn, Pair};

#[tokio::test]
async fn encoded_headers_server_refuses_before_the_advertised_body_arrives() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let limit = 64;
        let mut pair = Pair::default();
        let mut listener = pair.server();
        let client = async {
            let connection = pair.client_inner().await;
            let (mut driver, sender) = client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            let mut prefix = BytesMut::new();
            FrameType::HEADERS.encode(&mut prefix);
            VarInt::from_u64(limit + 1).unwrap().encode(&mut prefix);
            send.write_all(&prefix).await.unwrap();
            // Keep the real send direction open without supplying the advertised body.
            let response = tokio::select! {
                response = recv.read_to_end(1024) => response.unwrap(),
                error = std::future::poll_fn(|cx| driver.poll_close(cx)) => panic!("request retired before its bounded response: {error:?}"),
            };
            connection.close(0u32.into(), b"");
            drop((send, recv, sender, driver, connection));
            response
        };
        let server = async {
            let connection = listener.next().await;
            let mut incoming = server::builder()
                .max_encoded_headers_size(limit)
                .build(connection)
                .await
                .unwrap();
            let result = incoming
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await;
            let result = result.map(|_| ());
            let _closed = incoming.accept().await;
            result
        };
        let (refused, response) = tokio::join!(server, client);
        listener.endpoint.wait_idle().await;
        assert!(matches!(refused, Err(StreamError::HeaderTooBig {actual_size, max_size})
            if actual_size == limit + 1 && max_size == limit));
        let mut wire = response.as_slice();
        let mut block = match Frame::decode(&mut wire).unwrap() {
            Frame::Headers(block) => block,
            _ => panic!("actual HEADERS error response"),
        };
        let fields = qpack::decode_stateless(&mut block, 1024).unwrap().fields;
        let (status, _) = Header::try_from(fields).unwrap().into_response_parts().unwrap();
        assert_eq!(status, StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    })
    .await
    .expect("finite encoded HEADERS exchange stalled");
}
